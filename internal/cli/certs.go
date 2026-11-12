package cli

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// maxCertFile bounds the --idp-cert file. A PEM certificate is a few
// kilobytes; even a bundle of several fits easily.
const maxCertFile = 1 << 20

// loadCerts reads the certificates the user trusts for the IdP.
//
// It accepts a PEM file with one or more CERTIFICATE blocks (several are
// allowed so both the old and new certificate can be supplied during a
// rollover), or the bare base64 that IdP metadata and admin consoles show.
// Errors never echo file content.
func loadCerts(path string) ([]*x509.Certificate, error) {
	f, err := os.Open(path) //nolint:gosec // the user names the file to read; that is the point of the flag
	if err != nil {
		return nil, fmt.Errorf("--idp-cert: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxCertFile+1))
	if err != nil {
		return nil, fmt.Errorf("--idp-cert: read %s: %w", path, err)
	}
	if len(data) > maxCertFile {
		return nil, fmt.Errorf("--idp-cert: %s is larger than 1 MiB; expected a certificate", path)
	}

	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			// A private key in this file is a mistake worth stopping for:
			// ssotrace never needs one, and the user may be about to share it.
			return nil, fmt.Errorf("--idp-cert: %s contains a %q block; give only the IdP's public certificate", path, block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("--idp-cert: %s: certificate %d could not be parsed", path, len(certs)+1)
		}
		certs = append(certs, c)
	}
	if len(certs) > 0 {
		return certs, nil
	}

	// No PEM blocks: try bare base64, as copied from metadata.
	der, err := base64.StdEncoding.DecodeString(string(bytes.Join(bytes.Fields(data), nil)))
	if err != nil {
		return nil, errors.New("--idp-cert: " + path + " is neither a PEM certificate nor base64 certificate data")
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("--idp-cert: " + path + " is base64 but not a certificate")
	}
	return []*x509.Certificate{c}, nil
}
