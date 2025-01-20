package config

import (
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	Rootdir string `json:"rootdir"`

	Identity CertificateIdentity `json:"identity"`
}

func (c *Config) Check() error {
	if envDir := os.Getenv("CERTMGR_ROOT_DIR"); envDir != "" {
		c.Rootdir = envDir
	}

	if c.Rootdir == "" {
		currentDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
		c.Rootdir = currentDir
	}

	return nil
}

func (c *Config) FilePath(pattern string, args ...interface{}) string {
	fname := fmt.Sprintf(pattern, args...)
	return filepath.Join(c.Rootdir, fname)
}
