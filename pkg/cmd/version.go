package cmd

import (
	"fmt"
	"runtime/debug"
)

func executeVersion() error {
	verInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return fmt.Errorf("failed to read build info")
	}
	fmt.Printf("Version: %s\n", verInfo.String())
	return nil
}
