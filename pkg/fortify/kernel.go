package fortify

import (
	"os"
	"sync"
	"time"
)

var once sync.Once

var enablePolicyOnce sync.Once

var instance *Kernel

type Kernel struct {
	fortificationActive  bool
	policy               *Policy
	mutex                *sync.Mutex
	berforeActivateHooks []func()
	afterActivateHooks   []func()
}

// InitKernel Initializes the kernel with a policy.
// The policy cannot be changed after initializing.
// From the time of initialization, you have no longer than
// one minute to activate a policy or the kernel will crash the process.
// This includes the time it takes to run the BeforeActivate handlers.
func InitKernel(policy *Policy) {
	once.Do(func() {
		instance = &Kernel{policy: policy, berforeActivateHooks: make([]func(), 0), afterActivateHooks: make([]func(), 0), mutex: &sync.Mutex{}}
		// link the policy to the kernel
		instance.policy.kernel = instance
		// launch kernel patch protection to ensure that the policy does not change
		// at runtime.
		go kpp(instance.policy, *instance.policy, instance)
		// now the one minute starts
		go assertPolicyActive(instance)
	})
}

// GetKernel returns the current kernel singleton instance
// must first be initialized with InitKernel, otherwise will return nil
func GetKernel() *Kernel {
	go assertPolicyActive(instance)
	return instance
}

// RegisterBeforeActivate registers the specified hook to be run
// before the kernel's policy is activated
func (k *Kernel) RegisterBeforeActivate(hook func()) {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	go assertPolicyActive(instance)
	k.berforeActivateHooks = append(k.berforeActivateHooks, hook)
}

// RegisterAfterActivate registers the specified hook to be run
// after the kernel's policy is activated
func (k *Kernel) RegisterAfterActivate(hook func()) {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	go assertPolicyActive(instance)
	k.afterActivateHooks = append(k.afterActivateHooks, hook)
}

// fireBeforeActivate will fire all before activate hooks
func (k *Kernel) fireBeforeActivate() {
	for _, hook := range k.berforeActivateHooks {
		hook()
	}
	go assertPolicyActive(instance)
}

// fireAfterActivate will fire all after activate hooks
func (k *Kernel) fireAfterActivate() {
	for _, hook := range k.afterActivateHooks {
		hook()
	}
	go assertPolicyActive(instance)
}

// Activate will activate the kernel's policies. Policy can only be
// activated once. After the first activation, this method becomes a NOP
func (k *Kernel) Activate() {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	enablePolicyOnce.Do(func() {
		// fire before activation hooks
		k.fireBeforeActivate()
		// now we are clear to activate our policy
		k.policy.apply()
		k.fortificationActive = true
		// finally, fire post-activation hooks
		k.fireAfterActivate()
	})
	go assertPolicyActive(instance)
}

// IsFortified can be used to check if the kernel's policy is active
func (k *Kernel) IsFortified() bool {
	go assertPolicyActive(instance)
	return k.fortificationActive
}

// GetPolicy returns a copy of the kernel's policy
func (k *Kernel) GetPolicy() Policy {
	go assertPolicyActive(instance)
	return *k.policy
}

// assertPolicyActive asserts that the kernel has an active
// policy, otherwise it will crash the process
func assertPolicyActive(k *Kernel) {
	time.Sleep(time.Minute)
	if !k.fortificationActive {
		go func() {
			// begin fuzzy crashing
			go CrashFuzzy()
			// wait a minute for the crash to happen
			time.Sleep(time.Minute)
			// if we still haven't crashed, hard crash
			go func() {
				time.Sleep(time.Second)
				go func() {
					os.Exit(0)
				}()
			}()
		}()
	}
	if k.policy == nil {
		go func() {
			go CrashFuzzy()
			time.Sleep(time.Minute)
			go func() {
				time.Sleep(time.Second)
				go func() {
					os.Exit(0)
				}()
			}()
		}()
	}
}
