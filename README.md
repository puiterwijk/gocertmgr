[![CI](https://github.com/WatskeBart/gocertmgr/actions/workflows/ci.yaml/badge.svg)](https://github.com/WatskeBart/gocertmgr/actions/workflows/ci.yaml) [![CodeQL](https://github.com/WatskeBart/gocertmgr/actions/workflows/github-code-scanning/codeql/badge.svg?branch=main)](https://github.com/WatskeBart/gocertmgr/actions/workflows/github-code-scanning/codeql) [![Dependabot Updates](https://github.com/WatskeBart/gocertmgr/actions/workflows/dependabot/dependabot-updates/badge.svg?branch=main)](https://github.com/WatskeBart/gocertmgr/actions/workflows/dependabot/dependabot-updates)

# A certificate manager written in Go

Usage:
  gocertmgr [flags] command [args]

Commands:

- createkeyandcsr   - Create a new key and CSR
- signcsr           - Sign a CSR
- createkeyandcert  - Create a new key and certificate
- topkcs12          - Convert to PKCS12 format
- version           - Show version information

Configuration:

Root directory can be set in three ways (in order of precedence):

1. `CERTMGR_ROOT_DIR` environment variable
2. `-config` flag pointing to a JSON file
3. Current working directory (default)

## Examples:

### Create a CA certificate

`gocertmgr createkeyandcert -cn "My Root CA" -selfsigned ca rootca`

### Create an intermediate CA signed by root

`gocertmgr createkeyandcsr intermediateca
gocertmgr signcsr -cn "Intermediate CA" -signer rootca ca intermediateca`

### Create a server certificate

`gocertmgr createkeyandcert -cn "server.example.com" -dns server.example.com -signer intermediateca server servercert`