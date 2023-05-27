// inicializar proyecto
// go mod init example/user/hello

// instalar libreria
// cd $HOME/hello/morestrings
// go build

// adds missing module requirements for imported packages
// cd $HOME/hello/
// go mod tidy

// Instalar
// go install example/user/hello
package main

import (
	"fmt"

	"example/user/hello/morestrings"

	"github.com/google/go-cmp/cmp"
)

func main() {
	fmt.Println(morestrings.ReverseRunes("!oG ,olleH"))
	fmt.Println(cmp.Diff("Hello World", "Hello Go"))
}
