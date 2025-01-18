package cmd

import (
	"fmt"
	"runtime/debug"
)

var Version string = "0.2.0"

func executeVersion() error {
	fmt.Printf("GoCertMgr Version: %s\n", Version)

	// Also show build info for debugging purposes
	if verInfo, ok := debug.ReadBuildInfo(); ok {
		fmt.Printf("\nBuild Information:\n%s\n", verInfo)
	}
	return nil
}
