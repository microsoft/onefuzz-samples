package main

import "testing"

func FuzzCheck(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		Check(data)
	})
}
