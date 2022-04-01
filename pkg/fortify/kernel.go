package fortify

import "sync"

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
// The policy cannot be changed after initializing
func InitKernel(policy *Policy) {
	once.Do(func() {
		instance = &Kernel{policy: policy, berforeActivateHooks: make([]func(), 0), afterActivateHooks: make([]func(), 0), mutex: &sync.Mutex{}}
		// link the policy to the kernel
		instance.policy.kernel = instance
	})
}

// GetKernel returns the current kernel singleton instance
// must first be initialized with InitKernel, otherwise will return nil
func GetKernel() *Kernel {
	return instance
}

// RegisterBeforeActivate registers the specified hook to be run
// before the kernel's policy is activated
func (k *Kernel) RegisterBeforeActivate(hook func()) {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	k.berforeActivateHooks = append(k.berforeActivateHooks, hook)
}

// RegisterAfterActivate registers the specified hook to be run
// after the kernel's policy is activated
func (k *Kernel) RegisterAfterActivate(hook func()) {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	k.afterActivateHooks = append(k.afterActivateHooks, hook)
}

// fireBeforeActivate will fire all before activate hooks
func (k *Kernel) fireBeforeActivate() {
	for _, hook := range k.berforeActivateHooks {
		hook()
	}
}

// fireAfterActivate will fire all after activate hooks
func (k *Kernel) fireAfterActivate() {
	for _, hook := range k.afterActivateHooks {
		hook()
	}
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
}

// IsFortified can be used to check if the kernel's policy is active
func (k *Kernel) IsFortified() bool {
	return k.fortificationActive
}

// GetPolicy returns a copy of the kernel's policy
func (k *Kernel) GetPolicy() Policy {
	return *k.policy
}
