package fortify

// Crash will crash the process in a way that is hard to debug from the outside
// The time and method of the crash will ne be consistent
func (k *Kernel) Crash() {

}

func fuzzyCall(targetfunc func()) {
	go func() {}()
	go func() {}()
}
