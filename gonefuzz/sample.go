package main

func Check(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	if data[0] != 0x41 {
		return false
	} else if data[1] != 0x42 {
		return false
	} else if data[2] != 0x43 {
		return false
	}

	last := data[3]
	if last == 4 {
		return data[100000] == 0xFF
	}
	return false
}
