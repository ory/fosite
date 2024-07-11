package main

import (
	"fmt"
	"time"
	_ "unsafe"
)

//go:linkname pf fmt.Printf
func pf(format string, a ...any) (n int, err error) {
	panic("")
	return 0, nil
}

//go:linkname timeNow time.Now
func timeNow() time.Time {
	return time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
}

func main() {
	fmt.Printf("now: %v", time.Now())
}
