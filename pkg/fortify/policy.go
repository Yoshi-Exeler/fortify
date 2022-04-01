package fortify

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"syscall"
	"time"

	"github.com/elastic/go-seccomp-bpf"
	ps "github.com/mitchellh/go-ps"
)

type Policy struct {
	kernel                       *Kernel
	useChangeroot                bool
	changerootDirectory          string
	dropPriviledges              bool
	targetUserID                 int
	tolerateForeignParentProcess bool
	allowedForeignRootPrograms   []string
	violation                    func(violation Violation, msg string)
	enableSeccomp                bool
	seccompPolicy                seccomp.Policy
	checkProcessees              bool
	unacceptableProcessees       []string
	tolerateDebugger             bool
	requireRootLaunch            bool
}

func NewEmptyPolicy() *Policy {
	return &Policy{tolerateForeignParentProcess: true}
}

// EnableRequireRootLaunch will configure the policy to mandate the
// process to be launched as root. Failing to do so will raise a violation.
func (p *Policy) EnableRequireRootLaunch() {
	p.requireRootLaunch = true
}

// EnableChangeroot will configure the policy to mandate a changeroot
// syscall into the specified directory to be executed upon activation
func (p *Policy) EnableChangeroot(directory string) {
	p.changerootDirectory = directory
	p.useChangeroot = true
}

// EnablePriviledgeDrop will configure the policy to mandate a setresuid
// syscall, changing the current user to the specified user id upon activation
func (p *Policy) EnablePriviledgeDrop(targetUserID int) {
	p.targetUserID = targetUserID
	p.dropPriviledges = true
}

// SetTolerateForeignParentProcess will configure the policy to either tolerate
// or reject running under a foreign parent process executable. For example if this is set
// to false running $ gdb <your-program> will cause a rejection.
func (p *Policy) SetTolerateForeignParentProcess(tolerate bool) {
	p.tolerateForeignParentProcess = tolerate
}

// SetAcceptableParentProcessees will configure the policy to not call the exit handler
// if running under one of the specified executables, even if the policy
// has SetTolerateForeignParentProcess(false).
func (p *Policy) SetAcceptableParentProcessees(proccessees []string) {
	p.allowedForeignRootPrograms = proccessees
}

// SetViolationHandler set the handler that is called when a policy
// violation was detected
func (p *Policy) SetViolationHandler(violationHandler func(Violation, string)) {
	p.violation = violationHandler
}

// EnableProcessScanning configures the policy to mandate that none of
// the specified processees are running during initialization
func (p *Policy) EnableProcessScanning(proccessees []string) {
	p.unacceptableProcessees = proccessees
	p.checkProcessees = true
}

// SetTolerateDebugger configures the policy to mandate wether or not a
// violation should be raised when a debugger is detected on our process
func (p *Policy) SetTolerateDebugger(tolerate bool) {
	p.tolerateDebugger = tolerate
}

// EnableSecureComputeMode will configure the policy to mandate running in
// Secure Compute Mode with the specified Seccomp Profile.
func (p *Policy) EnableSecureComputeMode(profile seccomp.Policy) {
	p.seccompPolicy = profile
	p.enableSeccomp = true
}

// apply will apply the policy
func (p *Policy) apply() {
	if p.requireRootLaunch && !p.runningAsRoot() {
		p.violation(ROOT_LAUNCH_REQUIRED, fmt.Sprintf("[VIOLATION] not launched as root"))
	}
	// if we dont tolerate debuggers, launch a routine that regularly
	// runs the internal debugger check based on TracerID
	if !p.tolerateDebugger {
		go func() {
			for {
				time.Sleep(time.Second)
				if p.hasDebuggerInternal() {
					p.violation(DEBBUGGER_DETECTED, "[VIOLATION] debugger detected")
				}
			}
		}()
	}

	// Begin by checking the chain of processees sitting above us
	if !p.tolerateForeignParentProcess {
		p.checkParentChain()
	}
	// Scan the system for unacceptable processees
	if p.checkProcessees {
		p.checkLocalProcessees()
	}
	// if we should apply a changeroot, we call that first, since it requires the most permissions
	if p.useChangeroot {
		p.changeroot()
	}
	// enable secure compute mode
	if p.enableSeccomp {
		p.enableSeccompPolicy()
	}
	// next, if we should drop priviledges do so, so we have as little priviledged code as possible
	if p.dropPriviledges {
		p.setresuid()
	}
}

// enableSeccompPolicy will enable the specified seccomp policy
func (p *Policy) enableSeccompPolicy() {
	if !seccomp.Supported() {
		p.violation(SECCOMP_UNSUPPORTED_BY_OS, "[VIOLATION] seccomp was mandated by policy but the system does not support the syscall")
	}
	filter := seccomp.Filter{
		NoNewPrivs: true, // this will make the seccomp filter irrevertable
		Flag:       seccomp.FilterFlagTSync,
		Policy:     p.seccompPolicy,
	}
	if err := seccomp.LoadFilter(filter); err != nil {
		p.violation(SECCOMP_FILTER_INSTALLATION_FAILED, fmt.Sprintf("[VIOLATION] could not install seccomp filter with error %v", err))
	}
}

// runningAsRoot will check if we are running as root. This
// check is somewhat naive and can be manipulated, which is okay
// since it is not security critical.
func (p *Policy) runningAsRoot() bool {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("[isRoot] Unable to get current user: %s", err)
	}
	return currentUser.Username == "root"
}

// checkLocalProcessees will check the running processees against the configured list of unacceptable processees
func (p *Policy) checkLocalProcessees() {
	// get all running processees
	processees, err := ps.Processes()
	if err != nil {
		p.violation(CANNOT_GET_LOCAL_PROCESSEES, fmt.Sprintf("[VIOLATIION] cannot read processees with error %v", err))
	}
	// map out the illegal processees
	illegalProcs := make(map[string]bool)
	for _, proc := range p.unacceptableProcessees {
		illegalProcs[proc] = true
	}
	// check for unacceptable processees
	for _, proc := range processees {
		if illegalProcs[proc.Executable()] {
			p.violation(UNACCEPTABLE_PROCESS_FOUND, fmt.Sprintf("[VIOLATIION] running with process '%v' is unacceptable", proc.Executable()))
		}
	}
}

// hasDebuggerInternal check if a debugger is present using the TracerID flag in the /proc/self/status
func (p *Policy) hasDebuggerInternal() bool {
	pid, err := getTracerPID()
	if err != nil {
		p.violation(COULD_NOT_ACCESS_PROC_SELF, fmt.Sprintf("[VIOLATIION] cannot read own proc fs with error %v", err))
	}
	return pid != 0
}

// checkParentChain will traverse the chain of parent processees and check them against
// a list of acceptable parent processees. If a non-acceptable parent process is found,
// a violation will be raised
func (p *Policy) checkParentChain() {
	// get the process id of the parent process
	pid := os.Getppid()

	// iterate the process chain sitting above us until we reach the kernel
	for pid != 0 {
		// grab the current process in the chain
		process, err := ps.FindProcess(pid)
		if err != nil {
			p.violation(PARENT_PROCESS_COULD_NOT_BE_ACCESSED, fmt.Sprintf("[VIOLATION] running under process that could not be accessed by findProcess with error %v", err))
		}
		// if no mathing process was found, the chain has terminated
		if process == nil {
			return
		}
		// get the name of its binary
		binaryName := process.Executable()
		// check if that name is acceptable
		acceptable := false
		for _, allowedName := range p.allowedForeignRootPrograms {
			if binaryName == allowedName {
				acceptable = true
				break
			}
		}
		if !acceptable {
			p.violation(RUNNING_UNDER_UNACCEPTABLE_PARENT_PROCESS, fmt.Sprintf("[VIOLATION] running under process '%v' was deemed unacceptable", binaryName))
		}
		pid = process.PPid()
	}
}

// changeroot syscall wrapper
func (p *Policy) changeroot() {
	if err := os.Chdir(p.changerootDirectory); err != nil {
		p.violation(COULD_NOT_CD_INTO_JAIL, fmt.Sprintf("[VIOLATION] failed to change directory into new root with error %v", err))
	}
	if err := syscall.Chroot(p.changerootDirectory); err != nil {
		p.violation(CHANGEROOT_SYSCALL_FAILED, fmt.Sprintf("[VIOLATION] changeroot syscall failed with error %v", err))
	}
}

// setresuid syscall wrapper
func (p *Policy) setresuid() {
	if err := syscall.Setresuid(p.targetUserID, p.targetUserID, p.targetUserID); err != nil {
		p.violation(SETRESUID_SYSCALL_FAILED, fmt.Sprintf("[VIOLATION] setresuid syscall failed with error %v", err))
	}
}

func getTracerPID() (int, error) {
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return -1, fmt.Errorf("can't open process status file: %w", err)
	}
	defer file.Close()
	for {
		var tpid int
		num, err := fmt.Fscanf(file, "TracerPid: %d\n", &tpid)
		if err == io.EOF {
			break
		}
		if num != 0 {
			return tpid, nil
		}
	}
	return -1, errors.New("unknown format of process status file")
}
