package cmd

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/puiterwijk/gocertmgr/pkg/config"
)

func parseConfig(configFile string) (config *config.Config, err error) {
	cfgB, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("error opening config file %s: %v", configFile, err)
	}
	if err := json.Unmarshal(cfgB, &config); err != nil {
		return nil, fmt.Errorf("error parsing config file %s: %v", configFile, err)
	}
	if err := config.Check(); err != nil {
		return nil, fmt.Errorf("error checking config file %s: %v", configFile, err)
	}
	return config, nil
}

func Execute() error {
	fset := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	configFile := fset.String("config", "./certmgr.json", "config file (default is ./certmgr.json)")
	if err := fset.Parse(os.Args[1:]); err != nil {
		return err
	}

	cfg, err := parseConfig(*configFile)
	if err != nil {
		return err
	}

	if fset.NArg() == 0 {
		return errors.New("no command specified")
	}

	switch fset.Arg(0) {
	case "createkeyandcsr":
		return executeCreateKeyAndCsr(cfg, fset.Args()[1:])
	case "signcsr":
		return executeCreateCSR(cfg, fset.Args()[1:])
	case "createkeyandcert":
		return executeCreateKeyAndCert(cfg, fset.Args()[1:])
	default:
		return fmt.Errorf("unknown command %s. Supported: [createkeyandcert | createkeyandcsr | signcsr]", fset.Arg(0))
	}
}
