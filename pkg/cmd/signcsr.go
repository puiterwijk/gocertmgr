package cmd

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/puiterwijk/gocertmgr/pkg/config"
)

type signeeArgs struct {
	commonName *string
	dnsName    *string
}

type signArgs struct {
	signerBase *string
	signee     signeeArgs

	selfSigned *bool
	validity   *string
}

func (s signArgs) getValidityDuration() (*time.Duration, error) {
	valStr := *s.validity
	valStrL := len(valStr)
	if valStrL < 2 {
		return nil, fmt.Errorf("invalid validity string: %s", valStr)
	}

	nrS := valStr[:valStrL-1]
	unit := valStr[valStrL-1]

	nr, err := strconv.ParseInt(nrS, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid number for validity: %s", nrS)
	}

	dur := time.Duration(nr) * 24 * time.Hour
	if unit == 'd' {
		return &dur, nil
	}
	dur = dur * 31
	if unit == 'm' {
		return &dur, nil
	}
	dur = dur * 12
	if unit == 'y' {
		return &dur, nil
	}
	return nil, fmt.Errorf("invalid unit for validity: %c", unit)
}

func (s signArgs) createTemplate(config *config.Config, certType string) (*x509.Certificate, error) {
	if *s.selfSigned {
		if certType != "ca" {
			return nil, fmt.Errorf("non-CA cert cannot be selfsigned")
		}
		if *s.signerBase != "" {
			return nil, fmt.Errorf("self-signed certificates have no signer")
		}
	} else {
		if *s.signerBase == "" {
			return nil, fmt.Errorf("signed certificates must have a signer")
		}
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0), // TODO

		Subject: config.GetName(*s.signee.commonName),

		NotBefore: time.Now().Add(-1 * time.Minute).UTC(),

		// Assume no CA, can be overridden later
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Fill (Ext)KeyUsage
	switch certType {
	case "ca":
		tmpl.IsCA = true
		// For now, assume always unlimited/unrestricted CAs.
		// Might wnat to make this more verbose in the future
		tmpl.MaxPathLen = -1
		tmpl.MaxPathLenZero = false
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	case "server":
		tmpl.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "client":
		tmpl.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		return nil, fmt.Errorf("unsupported certificate type: %s (valid: ca, server, client)", certType)
	}

	if *s.signee.dnsName != "" {
		tmpl.DNSNames = strings.Split(*s.signee.dnsName, ",")
	}

	notAfter, err := s.getValidityDuration()
	if err != nil {
		return nil, fmt.Errorf("validity string invalid: %s", err)
	}
	tmpl.NotAfter = time.Now().Add(*notAfter).UTC()

	sernum, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}
	tmpl.SerialNumber = sernum

	return tmpl, nil
}

func loadPem(config *config.Config, expectedHeader string, format string, args ...any) ([]byte, error) {
	filePath := config.FilePath(format, args...)
	cts, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %s", filePath, err)
	}
	pemBlock, rest := pem.Decode(cts)
	if len(rest) != 0 {
		return nil, fmt.Errorf("failed to decode %s: has extra", filePath)
	}
	if pemBlock.Type != expectedHeader {
		return nil, fmt.Errorf("failed to decode %s: wrong header (%s, expected %s)", filePath, pemBlock.Type, expectedHeader)
	}
	return pemBlock.Bytes, nil
}

func loadPrivateKey(config *config.Config, keyBase string) (interface{}, error) {
	keyB, err := loadPem(config, pemHeaderPrivKey, fileFormatPrivKey, keyBase)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %s", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyB)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %s", err)
	}
	return key, nil
}

func getPublicKeyFromPrivate(key any) (any, error) {
	rsakey, ok := key.(*rsa.PrivateKey)
	if ok {
		return &rsakey.PublicKey, nil
	}
	ecckey, ok := key.(*ecdsa.PrivateKey)
	if ok {
		return &ecckey.PublicKey, nil
	}
	return nil, fmt.Errorf("unsupported key type: %T", key)
}

func loadCsr(config *config.Config, csrBase string) (*x509.CertificateRequest, error) {
	csrB, err := loadPem(config, pemHeaderCsr, fileFormatCsr, csrBase)
	if err != nil {
		return nil, fmt.Errorf("failed to load CSR: %s", err)
	}
	csr, err := x509.ParseCertificateRequest(csrB)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %s", err)
	}
	err = csr.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("failed to check CSR signature: %s", err)
	}
	return csr, nil
}

func loadCert(config *config.Config, certBase string) (*x509.Certificate, error) {
	certB, err := loadPem(config, pemHeaderCert, fileFormatCert, certBase)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(certB)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %s", err)
	}
	return cert, nil
}

func (s signArgs) sign(config *config.Config, outname string, tmpl *x509.Certificate, pubkey any, signer *x509.Certificate, signerKey any) error {
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, signer, pubkey, signerKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %s", err)
	}
	if err := writePem(config, outname, fileFormatCert, pemHeaderCert, cert); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}
	return nil
}

func addSignArgs(fset *flag.FlagSet) signArgs {
	return signArgs{
		signerBase: fset.String("signer", "", "The signer to use (basename of the key)"),

		signee: signeeArgs{
			commonName: fset.String("cn", "", "The common name of the certificate"),
			dnsName:    fset.String("dns", "", "The dns name of the certificate"),
		},

		selfSigned: fset.Bool("selfsigned", false, "Whether the certificate is selfsigned (only valid for CA)"),
		validity:   fset.String("validity", "1y", "Duration the certificate will be valid for, with suffix d, m or y"),
	}
}

func executeCreateCSR(config *config.Config, args []string) error {
	fset := flag.NewFlagSet("signcsr", flag.ExitOnError)
	signArgs := addSignArgs(fset)
	if err := fset.Parse(args); err != nil {
		return err
	}

	if fset.NArg() != 2 {
		return fmt.Errorf("expected two argument: type (ca, server, client) and basename of the CSR")
	}
	if *signArgs.selfSigned {
		return fmt.Errorf("CSR can't be selfsigned")
	}

	tmpl, err := signArgs.createTemplate(config, fset.Arg(0))
	if err != nil {
		return err
	}

	csr, err := loadCsr(config, fset.Arg(1))
	if err != nil {
		return fmt.Errorf("error loading CSR %s: %s", fset.Arg(1), err)
	}
	pubkey := csr.PublicKey

	signerKey, err := loadPrivateKey(config, *signArgs.signerBase)
	if err != nil {
		return fmt.Errorf("error loading signer key: %s", err)
	}
	signerCert, err := loadCert(config, *signArgs.signerBase)
	if err != nil {
		return fmt.Errorf("error loading signer cert: %s", err)
	}

	return signArgs.sign(config, fset.Arg(1), tmpl, pubkey, signerCert, signerKey)
}
