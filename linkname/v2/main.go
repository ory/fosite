package main

import (
	"fmt"
	"v2/b" // Import the overriding package to ensure it is included
)

func main() {
	fmt.Printf(b.Fooer()) // This should call the overridden function from package b
}
