package fortify

import (
	"fmt"
	"reflect"
	"time"
)

// kpp will regularly check that the kernel is still running the original policy
func kpp(policy *Policy, policyClone Policy, k *Kernel) {
	for {
		// if the memory address of the policy has changed, crash
		if k.policy != policy {
			fmt.Println("[DEBUG] crashing because policy address has changed")
			CrashFuzzy()
			// if any of the policies settings have changed, also crash
		} else if policy.changerootDirectory != policyClone.changerootDirectory ||
			policy.checkProcessees != policyClone.checkProcessees ||
			!reflect.DeepEqual(policy.allowedForeignRootPrograms, policyClone.allowedForeignRootPrograms) ||
			policy.dropPriviledges != policyClone.dropPriviledges ||
			policy.enableSeccomp != policyClone.enableSeccomp ||
			policy.kernel != policyClone.kernel ||
			policy.requireRootLaunch != policyClone.requireRootLaunch ||
			!reflect.DeepEqual(policy.seccompPolicy, policyClone.seccompPolicy) ||
			policy.targetUserID != policyClone.targetUserID ||
			policy.tolerateDebugger != policyClone.tolerateDebugger ||
			policy.tolerateForeignParentProcess != policyClone.tolerateForeignParentProcess ||
			!reflect.DeepEqual(policy.unacceptableProcessees, policyClone.unacceptableProcessees) ||
			policy.useChangeroot != policyClone.useChangeroot {
			fmt.Println("[DEBUG] crashing because policy has changed", *policy, policyClone)
			CrashFuzzy()
		}
		time.Sleep(time.Minute)
	}
}
