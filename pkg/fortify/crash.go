package fortify

import (
	"fmt"
	"time"
	"unsafe"
)

var WORD_ZERO = [8]byte{0, 0, 0, 0, 0, 0, 0, 0}

const WRITE_DELAY = 1

// CrashFuzzy will crash the process in a way that is hard to debug from the outside.
// The time and reason of the crash will not be consistent
var CrashFuzzy = func() {
	fmt.Println("[DEBUG] a fuzzy crash has been initiated")
	// allocate a variable
	value := 1337
	// we are gonna start flipping bytes in escalating distance from this value,
	// assuming that this is variable is most likely somewhere in the middle of our
	// processees memory and we are eventually gonna flip something critical
	membase := unsafe.Pointer(&value)
	offset := uintptr(8)
	for {
		time.Sleep(time.Millisecond * WRITE_DELAY)
		// write an empty dword to this location
		*(*[8]byte)(unsafe.Pointer(uintptr(membase) + offset)) = WORD_ZERO
		*(*[8]byte)(unsafe.Pointer(uintptr(membase) - offset)) = WORD_ZERO
		// increment the offset
		offset++
	}
}
