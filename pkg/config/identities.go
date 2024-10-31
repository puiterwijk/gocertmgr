package config

import "crypto/x509/pkix"

type CertificateIdentity struct {
	Country            string `json:"country"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizational_unit"`
	Locality           string `json:"locality"`
	Province           string `json:"province"`
}

func maybeStringArray(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func (c *Config) GetName(commonName string) pkix.Name {
	return pkix.Name{
		Country:            maybeStringArray(c.Identity.Country),
		Organization:       maybeStringArray(c.Identity.Organization),
		OrganizationalUnit: maybeStringArray(c.Identity.OrganizationalUnit),
		Locality:           maybeStringArray(c.Identity.Locality),
		Province:           maybeStringArray(c.Identity.Province),
		CommonName:         commonName,
	}
}
