package main

import (
	"fmt"
	"path/filepath"
)

func main() {

	ms, err := filepath.Glob("/Users/teklof/go/src/github.com/*/Peerdoc")
	fmt.Println("glob err", err)
	fmt.Printf("%+v\n", ms)
}
