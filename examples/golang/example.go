package parser

import (
	"syscall"
	"unsafe"
)

func bad_ptr(value int) {
	ptr_size := unsafe.Sizeof(uintptr(0))
	ptr := (*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(&value)) - ptr_size))
	*ptr = 0xe
}

func MyFunc(data []byte) bool {
	var cnt int

	if len(data) <= 4 {
		return false
	}

	if data[0] == 'x' {
		cnt += 1
	}
	if data[1] == 'y' {
		cnt += 1
	}
	if data[2] == 'z' {
		cnt += 1
	}

	if cnt >= 3 {
		switch data[3] {
		case '0': // OOB read
			return data[50000] == 'g'
		case '1': // OOB write
			data[5000] = 'g'
		case '2':
			syscall.Kill(syscall.Getpid(), syscall.SIGSEGV)
		case '3':
			bad_ptr(1337)
		case '4':
			panic("panic")
		}
	}
	return false
}

func Fuzz(data []byte) int {
	MyFunc(data)
	return 0
}
