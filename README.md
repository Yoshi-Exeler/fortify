# fortify
Fortify is a fully featured process security package.

## Usage
First, create an empty policy:

`p := fortify.NewEmptyPolicy()`

Next, configure it using its methods:

`p.EnableChangeroot("/home/me/jail/")
p.SetTolerateDebugger(false)
...`

Finally, create a kernel with your policy and activate it:

`fortify.InitKernel(p)
k := fortify.GetKernel()
k.Activate()`

## Policy settings
This package provides features that allow you to secure the system from your process but also features that allow you to secure your process from users trying to analyse it (and perhaps bypass your drm scheme).

### Changeroot
Using the `p.EnabeChangeroot(dir string)` option, you can force the process to changeroot into the specified directory during policy activation.

### Privilege Drop
Using the `p.EnablePrivilegeDrop(uid int)` option, you can force the process to change its user with the Setresuid syscall to the specified user id during initialization.

### Seccomp
Using the `p.EnableSecureComputeMode(policy seccomp.Policy)` option, you can force the process to activate the specified seccomp filter policy during initialization.

### Local Process Blacklist
Using the `p.EnableProcessScanning(blacklist []string)` option, you can enable the validation of the processees running during the launch of the process against the specified blacklist.

### Parent Process Whitelist
Using the `p.SetTolerateForeignParentProcess(tolerate bool)` and the `p.SetAcceptableParentProcessees(whitelist []string)` option, you can enable the validation of the parent process chain against your configured whitelist during the launch of your process.

### Debugger Detection
Using the `p.SetTolerateDebugger(tolerate bool)` option, you can enable contious debugger detection.

## Violations
When one of the options above detects something that is against the specified policy (Seccomp enabled but not supported by os, Debugger detected when it is not tolerated etc) a violation will be raised. You can use the `p.ViolarionHanlder(handler func(Violation,string)bool)` option to configure the handler function that will be called when the policy is violated. If your handler function returns true, a fuzzy crash will be initiated.

## Fuzzy Crashes
Instead of just calling os.Exit or something similar, we can make it a bit harder for attackers trying to analyser our process. When the fuzzy crash function is called, it allocates a variable, takes its memory address and then starts writing zero words in escalating distance around the variable. The assumption here is that this will eventually cause our process to crash in some unexpected, inconsistent and hard to debug way.