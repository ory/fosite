package a

import (
	_ "unsafe"
)

func Foo() string {
	return Fooer()
}

//go:linkname Fooer github.com/ory/fosite/linkname/a.Fooer
func Fooer() string
