package main

import (
	"fmt"
	"os"

	"github.com/puiterwijk/gocertmgr/pkg/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
}
