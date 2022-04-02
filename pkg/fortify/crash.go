package fortify

import (
	"time"
	"unsafe"
)

var DW_ZERO = [4]byte{0, 0, 0, 0}

const WRITE_DELAY = 1

// Crash will crash the process in a way that is hard to debug from the outside.
// The time and reason of the crash will not be consistent
func (k *Kernel) Crash() {
	// allocate a variable
	value := 1337
	// we are gonna start flipping bytes in escalating distance from this value,
	// assuming that this is variable is most likely somewhere in the middle of our
	// processees memory and we are eventually gonna flip something critical
	membase := unsafe.Pointer(&value)
	flip := false
	offset := uintptr(8)
	for {
		time.Sleep(time.Millisecond * WRITE_DELAY)
		// current addrress is base + offset
		addr := unsafe.Pointer(uintptr(membase) + offset)
		// on every second iteration, we are gonna invert the offset
		if flip {
			addr = unsafe.Pointer(uintptr(membase) - offset)
		}
		// write an empty dword to this location
		*(*[4]byte)(addr) = DW_ZERO
		// increment the offset
		offset += 16
		flip = !flip
	}
}
