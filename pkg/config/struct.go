package config

import (
	"fmt"
	"path/filepath"
)

type Config struct {
	Rootdir string `json:"rootdir"`

	Identity CertificateIdentity `json:"identity"`
}

func (c *Config) Check() error {
	if c.Rootdir == "" {
		return fmt.Errorf("rootdir is required")
	}
	return nil
}

func (c *Config) FilePath(pattern string, args ...interface{}) string {
	fname := fmt.Sprintf(pattern, args...)
	return filepath.Join(c.Rootdir, fname)
}
