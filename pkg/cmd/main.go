package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/WatskeBart/gocertmgr/pkg/config"
)

const usageTemplate = `gocertmgr is a certificate management tool.

Usage:
  gocertmgr [flags] <command> [args]

Commands:
  createkeyandcsr   - Create a new key and CSR
  signcsr           - Sign a CSR
  createkeyandcert  - Create a new key and certificate
  topkcs12          - Convert to PKCS12 format
  version           - Show version information

Configuration:
  Root directory can be set in three ways (in order of precedence):
  1. CERTMGR_ROOT_DIR environment variable
  2. -config flag pointing to a JSON file
  3. Current working directory (default)

Examples:
  # Create a CA certificate
  gocertmgr createkeyandcert -cn "My Root CA" -selfsigned ca rootca

  # Create an intermediate CA signed by root
  gocertmgr createkeyandcsr intermediateca
  gocertmgr signcsr -cn "Intermediate CA" -signer rootca ca intermediateca

  # Create a server certificate
  gocertmgr createkeyandcert -cn "server.example.com" -dns server.example.com -signer intermediateca server servercert

Environment Variables:
  CERTMGR_ROOT_DIR  Directory for certificate storage
`

func parseConfig(configFile string) (*config.Config, error) {
	cfg := &config.Config{}

	if configFile != "" {
		cfgB, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("error opening config file %s: %v", configFile, err)
		}
		if err := json.Unmarshal(cfgB, cfg); err != nil {
			return nil, fmt.Errorf("error parsing config file %s: %v", configFile, err)
		}
	}

	if err := cfg.Check(); err != nil {
		return nil, fmt.Errorf("error checking configuration: %v", err)
	}
	return cfg, nil
}

func Execute() error {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usageTemplate)
	}

	fset := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	configFile := fset.String("config", "", "config file (optional)")
	help := fset.Bool("help", false, "show detailed help")

	if len(os.Args) == 1 {
		flag.Usage()
		return nil
	}

	if err := fset.Parse(os.Args[1:]); err != nil {
		return err
	}

	if *help {
		flag.Usage()
		return nil
	}

	cfg, err := parseConfig(*configFile)
	if err != nil {
		return err
	}

	if fset.NArg() == 0 {
		flag.Usage()
		return nil
	}

	switch fset.Arg(0) {
	case "createkeyandcsr":
		return executeCreateKeyAndCsr(cfg, fset.Args()[1:])
	case "signcsr":
		return executeCreateCSR(cfg, fset.Args()[1:])
	case "createkeyandcert":
		return executeCreateKeyAndCert(cfg, fset.Args()[1:])
	case "topkcs12":
		return executeTopKCS12(cfg, fset.Args()[1:])
	case "version":
		return executeVersion()
	default:
		return fmt.Errorf("unknown command %s. Supported: [createkeyandcert | createkeyandcsr | signcsr | topkcs12 | version]", fset.Arg(0))
	}
}
