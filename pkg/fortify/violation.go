package fortify

type Violation byte

const (
	DEBBUGGER_DETECTED_TRACER                 Violation = 1
	SECCOMP_UNSUPPORTED_BY_OS                 Violation = 2
	SECCOMP_FILTER_INSTALLATION_FAILED        Violation = 3
	COULD_NOT_ACCESS_PROC_SELF                Violation = 4
	PARENT_PROCESS_COULD_NOT_BE_ACCESSED      Violation = 5
	RUNNING_UNDER_UNACCEPTABLE_PARENT_PROCESS Violation = 6
	COULD_NOT_CD_INTO_JAIL                    Violation = 7
	CHANGEROOT_SYSCALL_FAILED                 Violation = 8
	SETRESUID_SYSCALL_FAILED                  Violation = 9
	CANNOT_GET_LOCAL_PROCESSEES               Violation = 10
	UNACCEPTABLE_PROCESS_FOUND                Violation = 11
	ROOT_LAUNCH_REQUIRED                      Violation = 12
	DEBUGGER_DETECTED_TIMING                  Violation = 13
)
