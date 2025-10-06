package cmd

import (
	"fmt"
	"os"

	"github.com/puiterwijk/gocertmgr/pkg/config"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func executeTopKCS12(config *config.Config, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("topkcs12 requires one argument: basename")
	}

	key, err := loadPrivateKey(config, args[0])
	if err != nil {
		return fmt.Errorf("error loading private key: %s", err)
	}
	cert, err := loadCert(config, args[0])
	if err != nil {
		return fmt.Errorf("error loading cert: %s", err)
	}

	bin, err := pkcs12.Modern.Encode(key, cert, nil, pkcs12.DefaultPassword)
	if err != nil {
		return fmt.Errorf("error encoding pkcs12: %s", err)
	}

	fmt.Println("Using password: ", pkcs12.DefaultPassword)

	filePath := config.FilePath(fileFormatPkcs12, args[0])
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	if _, err := file.Write(bin); err != nil {
		return fmt.Errorf("failed to write file %s: %w", filePath, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close file %s: %w", filePath, err)
	}

	return nil
}
