//go:build oel

package b

import (
	"github.com/ory/fosite/linkname/a"
	_ "unsafe"
)

//go:linkname Fooer2 github.com/ory/fosite/linkname/a.Fooer
func Fooer2() string {
	return "bar"
}

func Foo() string {
	return a.Foo()
}
