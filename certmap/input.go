// Package certmap inspects local certificate inventories without network access.
package certmap

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"sort"
)

const MaxBytes = 8 << 20
const MaxCertificates = 256
const MaxCertificateBytes = 1 << 20

// Bundle retains the digest of input bytes, but normalizes certificates by DER ID.
type Bundle struct {
	SHA256       string              `json:"sha256"`
	Certificates []*x509.Certificate `json:"-"`
	Duplicates   int                 `json:"duplicates"`
}

func digest(data []byte) string     { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func ID(c *x509.Certificate) string { return digest(c.Raw) }

// Load never reads more than MaxBytes+1 bytes, even for a growing file or pipe.
func Load(path string) (Bundle, error) {
	f, err := os.Open(path)
	if err != nil {
		return Bundle{}, errors.New("unable to open certificate input")
	}
	defer f.Close()
	return Read(f)
}
func Read(reader io.Reader) (Bundle, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxBytes+1))
	if err != nil {
		return Bundle{}, errors.New("unable to read certificate input")
	}
	return Parse(data)
}

// Parse rejects skipped PEM text, private keys, headers, malformed blocks and DER tails.
// PEM is deliberately strict: only whitespace may separate CERTIFICATE blocks.
func Parse(data []byte) (Bundle, error) {
	if len(data) > MaxBytes {
		return Bundle{}, errors.New("certificate input exceeds 8 MiB")
	}
	b := Bundle{SHA256: digest(data), Certificates: []*x509.Certificate{}}
	original := data
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return Bundle{}, errors.New("empty certificate input")
	}
	seen := map[string]bool{}
	blocks := 0
	add := func(der []byte) error {
		blocks++
		if blocks > MaxCertificates {
			return errors.New("input exceeds 256 certificate blocks")
		}
		if len(der) > MaxCertificateBytes {
			return errors.New("certificate exceeds 1 MiB")
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return errors.New("malformed X.509 certificate")
		}
		id := ID(c)
		if seen[id] {
			b.Duplicates++
			return nil
		}
		seen[id] = true
		b.Certificates = append(b.Certificates, c)
		return nil
	}
	if bytes.HasPrefix(data, []byte("-----BEGIN")) {
		for len(data) > 0 {
			const begin = "-----BEGIN CERTIFICATE-----"
			const end = "-----END CERTIFICATE-----"
			if !bytes.HasPrefix(data, []byte(begin)) {
				return Bundle{}, errors.New("only CERTIFICATE PEM blocks are accepted")
			}
			at := bytes.Index(data, []byte(end))
			if at < 0 {
				return Bundle{}, errors.New("unterminated certificate PEM block")
			}
			encoded := data[:at+len(end)]
			if bytes.Contains(encoded[len(begin):], []byte("-----BEGIN")) {
				return Bundle{}, errors.New("nested certificate PEM block")
			}
			block, rest := pem.Decode(encoded)
			if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return Bundle{}, errors.New("malformed certificate PEM block")
			}
			if err := add(block.Bytes); err != nil {
				return Bundle{}, err
			}
			data = bytes.TrimSpace(data[len(encoded):])
		}
	} else {
		// DER is binary: trimming would corrupt certificates whose final byte is whitespace.
		if err := add(original); err != nil {
			return Bundle{}, err
		}
	}
	sort.Slice(b.Certificates, func(i, j int) bool { return ID(b.Certificates[i]) < ID(b.Certificates[j]) })
	return b, nil
}
