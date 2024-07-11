//go:build !oel

package a

import (
	_ "unsafe"
)

//go:linkname Fooer2 github.com/ory/fosite/linkname/a.Fooer
func Fooer2() string {
	return "foo"
}
