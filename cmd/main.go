package main

import (
	"fmt"
	"fortify/pkg/fortify"
	"log"
	"time"
)

func main() {

	p := fortify.NewEmptyPolicy()
	//p.EnableChangeroot("/home/ubuntu/workspace/fortify/cmd/jail")
	// if you need to find a user with some name, you could do that here
	p.EnablePriviledgeDrop(1000)
	p.SetTolerateDebugger(true)
	p.SetTolerateForeignParentProcess(false)
	// allow my regular execution chain
	p.SetAcceptableParentProcessees([]string{"sudo", "bash", "node", "sh", "sshd", "systemd", "dlv"})
	p.SetViolationHandler(func(v fortify.Violation, s string) {
		log.Fatal("exit handler:", s)
	})
	//p.EnableSecureComputeMode(&SeccompProfile)
	fortify.InitKernel(p)

	kernel := fortify.GetKernel()

	kernel.RegisterBeforeActivate(func() {
		fmt.Println("Before activate, you could read in some files here")
	})

	kernel.RegisterAfterActivate(func() {
		fmt.Println("After activate, you could setup your jail a bit here")
	})

	kernel.Activate()

	fmt.Println("This is a test application secured by fortify")

	num := 0

	for {
		time.Sleep(time.Second * 1)
		fmt.Println(num)
		num++
	}

}
