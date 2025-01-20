package cmd

import (
	"crypto/x509"
	"flag"
	"fmt"

	"github.com/WatskeBart/gocertmgr/pkg/config"
)

func executeCreateKeyAndCert(config *config.Config, args []string) error {
	fset := flag.NewFlagSet("signcsr", flag.ExitOnError)
	signArgs := addSignArgs(fset)
	keyInfoFlags := addKeyInfoFlags(fset)
	if err := fset.Parse(args); err != nil {
		return err
	}

	if fset.NArg() != 2 {
		return fmt.Errorf("expected two argument: type (ca, server, client) and basename of the CSR")
	}

	key, err := keyInfoFlags.generateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	pubkey, err := getPublicKeyFromPrivate(key)
	if err != nil {
		return fmt.Errorf("failed to get public key from private key: %v", err)
	}

	tmpl, err := signArgs.createTemplate(config, fset.Arg(0))
	if err != nil {
		return err
	}

	var signerKey any
	var signerCert *x509.Certificate

	if *signArgs.selfSigned {
		signerKey = key
		signerCert = tmpl
	} else {
		signerKey, err = loadPrivateKey(config, *signArgs.signerBase)
		if err != nil {
			return fmt.Errorf("error loading signer key: %s", err)
		}
		signerCert, err = loadCert(config, *signArgs.signerBase)
		if err != nil {
			return fmt.Errorf("error loading signer cert: %s", err)
		}
	}

	if err := writePrivKey(config, fset.Arg(1), key); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	return signArgs.sign(config, fset.Arg(1), tmpl, pubkey, signerCert, signerKey)
}
