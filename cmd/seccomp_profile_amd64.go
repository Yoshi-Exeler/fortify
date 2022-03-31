// Code generated by seccomp-profiler - DO NOT EDIT.

// +build linux,amd64

package main

import (
    "github.com/elastic/go-seccomp-bpf"
)

var SeccompProfile = seccomp.Policy{
    DefaultAction: seccomp.ActionErrno,
    Syscalls: []seccomp.SyscallGroup{
        {
            Action: seccomp.ActionAllow,
            Names:  []string{
                "arch_prctl",
                "clock_gettime",
                "clone",
                "close",
                "epoll_create",
                "epoll_create1",
                "epoll_ctl",
                "epoll_pwait",
                "exit",
                "exit_group",
                "fcntl",
                "futex",
                "getpid",
                "gettid",
                "kill",
                "madvise",
                "mincore",
                "mmap",
                "munmap",
                "nanosleep",
                "openat",
                "pipe",
                "pipe2",
                "read",
                "rt_sigaction",
                "rt_sigprocmask",
                "rt_sigreturn",
                "sched_getaffinity",
                "sched_yield",
                "sigaltstack",
                "tgkill",
                "write",
            },
        },
    },
}
