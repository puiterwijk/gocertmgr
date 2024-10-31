package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/puiterwijk/gocertmgr/pkg/config"
	"os"
)

type keyInfoFlags struct {
	keyType *string
	keySize *string
}

func (f keyInfoFlags) generateKey() (any, error) {
	switch *f.keyType {
	case "rsa":
		switch *f.keySize {
		case "default", "2048":
			return rsa.GenerateKey(rand.Reader, 2048)
		case "4096":
			return rsa.GenerateKey(rand.Reader, 4096)
		default:
			return nil, fmt.Errorf("unknown key size for rsa %s", *f.keySize)
		}
	case "ecc":
		switch *f.keySize {
		case "default", "secp256r1":
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "secp384r1":
			return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		default:
			return nil, fmt.Errorf("unknown key size for ecc %s", *f.keySize)
		}
	default:
		return nil, fmt.Errorf("unknown key type %s", *f.keyType)
	}
}

func addKeyInfoFlags(fset *flag.FlagSet) keyInfoFlags {
	return keyInfoFlags{
		keyType: fset.String("type", "rsa", "key type [ecc | rsa]"),
		keySize: fset.String("size", "default", "key size (for rsa: 2048 or 4096, for ecc: secp256r1 or secp384r1)"),
	}
}

func writePem(config *config.Config, outname string, format string, typeName string, body []byte) error {
	pemKey := &pem.Block{
		Type:  typeName,
		Bytes: body,
	}

	filePath := config.FilePath(format, outname)
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	if _, err := file.Write(pem.EncodeToMemory(pemKey)); err != nil {
		return fmt.Errorf("failed to write file %s: %w", filePath, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close file %s: %w", filePath, err)
	}
	return nil
}

const (
	fileFormatPrivKey = "%s.priv.pem"
	fileFormatCsr     = "%s.csr.pem"
	fileFormatCert    = "%s.cert.pem"
)

const (
	pemHeaderPrivKey = "PRIVATE KEY"
	pemHeaderCsr     = "CERTIFICATE REQUEST"
	pemHeaderCert    = "CERTIFICATE"
)

func writePrivKey(config *config.Config, outname string, key any) error {
	derKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}
	if err := writePem(config, outname, fileFormatPrivKey, pemHeaderPrivKey, derKey); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}
	return nil
}

func executeCreateKeyAndCsr(config *config.Config, args []string) error {
	fset := flag.NewFlagSet("createkey", flag.ExitOnError)
	keyInfoFlags := addKeyInfoFlags(fset)
	if err := fset.Parse(args); err != nil {
		return err
	}

	if fset.NArg() != 1 {
		return fmt.Errorf("expected exactly one argument: key file name")
	}

	key, err := keyInfoFlags.generateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: fset.Arg(0),
		},
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		return fmt.Errorf("failed to create csr: %w", err)
	}

	if err := writePrivKey(config, fset.Arg(0), key); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}
	if err := writePem(config, fset.Arg(0), fileFormatCsr, pemHeaderCsr, csr); err != nil {
		return fmt.Errorf("failed to write csr: %w", err)
	}

	return nil
}
