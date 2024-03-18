// inicializar proyecto
// go mod init gotests/hello

// instalar libreria
// cd hello/morestrings
// go build

// adds missing module requirements for imported packages
// cd hello/
// go mod tidy

// Instalar
// go install gotests/hello
package main

import (
	"fmt"

	"gotests/hello/morestrings"

	"github.com/google/go-cmp/cmp"
)

func main() {
	fmt.Println(morestrings.ReverseRunes("!oG ,olleH"))
	fmt.Println(cmp.Diff("Hello World", "Hello Go"))
}
