package fortify

import (
	"time"

	"github.com/elastic/go-seccomp-bpf"
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

// NewEmptyPolicy returns a policy the mandates no constraints
func NewEmptyPolicy() *Policy {
	return &Policy{tolerateForeignParentProcess: true, tolerateDebugger: true}
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
// to false running $ gdb <your-program> will cause a violation. Use the
// SetAcceptableParentProcessees option to configure a list of acceptable parent processees.
func (p *Policy) SetTolerateForeignParentProcess(tolerate bool) {
	p.tolerateForeignParentProcess = tolerate
}

// SetAcceptableParentProcessees will configure the policy to not raise
// a violation if running under one of the specified executables,
// even if the policy has SetTolerateForeignParentProcess(false).
func (p *Policy) SetAcceptableParentProcessees(proccessees []string) {
	p.allowedForeignRootPrograms = proccessees
}

// SetViolationHandler sets the handler that is called when a policy
// violation was detected. The first parameter can be used to identify
// the type of violation that coccurred according to the violation enum.
// The second parameter is an error string describing the details of the
// violation. If the handler returns true, the process will be crashed,
// otherwise the violation will be ignored.
func (p *Policy) SetViolationHandler(violationHandler func(Violation, string) bool) {
	wrapped := func(v Violation, s string) {
		crash := violationHandler(v, s)
		if crash {
			CrashFuzzy()
		}
	}
	p.violation = wrapped
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
		p.violation(ROOT_LAUNCH_REQUIRED, "[VIOLATION] not launched as root")
	}
	// if we dont tolerate debuggers, launch both of our debugger detection routines
	if !p.tolerateDebugger {
		// spawn two timing routines running at 10 & 15 second intervals
		go p.detectTimeSkips(time.Second*10, 15)
		go p.detectTimeSkips(time.Second*5, 10)
		go func() {
			for {
				time.Sleep(time.Second)
				if p.hasTracerPID() {
					p.violation(DEBBUGGER_DETECTED_TRACER, "[VIOLATION] debugger detected, TracerPID is not 0")
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
