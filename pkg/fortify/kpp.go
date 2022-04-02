package fortify

import (
	"reflect"
	"time"
)

// kpp will regularly check that the kernel is still running the original policy
func kpp(policy *Policy, policyClone Policy, k *Kernel) {
	for {
		// if the memory address of the policy has changed, crash
		if k.policy != policy {
			CrashFuzzy()
		} else if !reflect.DeepEqual(*policy, policyClone) {
			CrashFuzzy()
		}
		time.Sleep(time.Minute)
	}
}
