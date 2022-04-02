package fortify

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"syscall"

	"github.com/elastic/go-seccomp-bpf"
	ps "github.com/mitchellh/go-ps"
)

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
	fmt.Println("PT_SELF:", ptraceSelf())
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

func ptraceSelf() error {
	err := syscall.PtraceAttach(os.Getpid())
	if err != nil {
		return fmt.Errorf("%v:%v", os.Getpid(), err)
	}
	return nil
}
