package b

import (
	_ "unsafe"
	_ "v2/a"
) // required for go:linkname

//go:linkname Fooer v2/a.fooer
func Fooer() string
