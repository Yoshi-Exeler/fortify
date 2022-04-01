package fortify

import (
	"errors"
	"fmt"
	"io"
	"os"
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
	criticalFailureHandler       func(error)
	tolerateForeignParentProcess bool
	allowedForeignRootPrograms   []string
	violationHandler             func(string)
	enableSeccomp                bool
	seccompPolicy                seccomp.Policy
	checkProcessees              bool
	unacceptableProcessees       []string
	tolerateDebugger             bool
}

func NewEmptyPolicy() *Policy {
	return &Policy{tolerateForeignParentProcess: true}
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
func (p *Policy) SetViolationHandler(violationHandler func(string)) {
	p.violationHandler = violationHandler
}

// SetUnacceptableProcessees configures the policy to mandate that none of
// the specified processees are running during initialization
func (p *Policy) SetUnacceptableProcessees(proccessees []string) {
	p.unacceptableProcessees = proccessees
	p.checkProcessees = true
}

// SetTolerateDebugger configures the policy to mandate wether or not a
// violation should be raised when a debugger is detected on our process
func (p *Policy) SetTolerateDebugger(tolerate bool) {
	p.tolerateDebugger = tolerate
}

// SetCriticalFailureHandler will configure the policy's critical failure handler,
// which will be called to handle our exit strategy in case of a critical failure
// during policy activation. Ususally this could just call log.Fatal.
// It is essential that the specified handler ends the application in some way.
func (p *Policy) SetCriticalFailureHandler(criticalFailureHandler func(error)) {
	p.criticalFailureHandler = criticalFailureHandler
}

// EnableSecureComputeMode will configure the policy to mandate running in
// Secure Compute Mode with the specified Seccomp Profile.
func (p *Policy) EnableSecureComputeMode(profile seccomp.Policy) {
	p.seccompPolicy = profile
	p.enableSeccomp = true
}

// apply will apply the policy
func (p *Policy) apply() {
	if !p.tolerateDebugger {
		go func() {
			for {
				time.Sleep(time.Second)
				if p.isDebuggerPresent() {
					p.violationHandler("[VIOLATION] debugger detected")
				}
			}
		}()
	}

	// Begin by checking the chain of processees sitting above us
	if !p.tolerateForeignParentProcess {
		p.checkParentChain(p.allowedForeignRootPrograms)
	}
	// Scan the system for unacceptable processees
	if p.checkProcessees {
		p.checkLocalProcessees(p.unacceptableProcessees)
	}
	// if we should apply a changeroot, we call that first, since it requires the most permissions
	if p.useChangeroot {
		p.changeroot(p.changerootDirectory)
	}
	// enable secure compute mode
	if p.enableSeccomp {
		p.enableSeccompPolicy(p.seccompPolicy)
	}
	// next, if we should drop priviledges do so, so we have as little priviledged code as possible
	if p.dropPriviledges {
		p.setresuid(p.targetUserID)
	}
}

func (p *Policy) enableSeccompPolicy(policy seccomp.Policy) {
	if !seccomp.Supported() {
		p.violationHandler("[VIOLATION] seccomp was mandated by policy but the system does not support the syscall")
	}
	filter := seccomp.Filter{
		NoNewPrivs: true, // this will make the seccomp filter irrevertable
		Flag:       seccomp.FilterFlagTSync,
		Policy:     policy,
	}
	if err := seccomp.LoadFilter(filter); err != nil {
		p.violationHandler(fmt.Sprintf("[VIOLATION] could not install seccomp filter with error %v", err))
	}
}

func (p *Policy) checkLocalProcessees(blacklist []string) {

}

func (p *Policy) isDebuggerPresent() bool {
	pid, err := getTracerPID()
	if err != nil {
		p.violationHandler(fmt.Sprintf("[VIOLATIION] cannot read own proc fs with error %v", err))
	}
	return pid != 0
}

// checkParentChain will traverse the chain of parent processees and check them against
// a list of acceptable parent processees. If a non-acceptable parent process is found,
// a violation will be raised
func (p *Policy) checkParentChain(allowed []string) {
	// get the process id of the parent process
	pid := os.Getppid()

	// iterate the process chain sitting above us until we reach the kernel
	for pid != 0 {
		// grab the current process in the chain
		process, err := ps.FindProcess(pid)
		if err != nil {
			p.violationHandler(fmt.Sprintf("[VIOLATION] running under process that could not be accessed by findProcess with error %v", err))
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
			p.violationHandler(fmt.Sprintf("[VIOLATION] running under process '%v' was deemed unacceptable", binaryName))
		}
		pid = process.PPid()
	}
}

// changeroot syscall wrapper
func (p *Policy) changeroot(dir string) {
	if err := os.Chdir(dir); err != nil {
		p.criticalFailureHandler(fmt.Errorf("[VIOLATION] failed to change directory into new root with error %v", err))
	}
	if err := syscall.Chroot(dir); err != nil {
		p.criticalFailureHandler(fmt.Errorf("[VIOLATION] changeroot syscall failed with error %v", err))
	}
}

// setresuid syscall wrapper
func (p *Policy) setresuid(uid int) {
	if err := syscall.Setresuid(uid, uid, uid); err != nil {
		p.criticalFailureHandler(fmt.Errorf("[VIOLATION] setresuid syscall failed with error %v", err))
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
