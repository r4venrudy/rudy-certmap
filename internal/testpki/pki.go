// Package testpki generates synthetic certificates for tests and examples only.
// Private keys stay in memory and are never serialized.
package testpki

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

var At = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

type Authority struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

func Template(serial int64, name string, ca bool) *x509.Certificate {
	t := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name, Organization: []string{"Rudy Synthetic Examples"}},
		NotBefore: At.AddDate(-1, 0, 0), NotAfter: At.AddDate(1, 0, 0), BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature}
	if ca {
		t.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		t.MaxPathLen = 3
	} else {
		t.DNSNames = []string{"service.example.test"}
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	return t
}
func Issue(template *x509.Certificate, parent *Authority, key crypto.Signer) (Authority, error) {
	if key == nil {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return Authority{}, err
		}
		key = private
	}
	issuer := template
	signer := key
	if parent != nil {
		issuer = parent.Cert
		signer = parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), signer)
	if err != nil {
		return Authority{}, err
	}
	c, err := x509.ParseCertificate(der)
	return Authority{c, key}, err
}
func PEM(certs ...*x509.Certificate) []byte {
	out := []byte{}
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}
func Chain() (Authority, Authority, Authority, error) {
	root, err := Issue(Template(1, "Rudy Demo Root", true), nil, nil)
	if err != nil {
		return Authority{}, Authority{}, Authority{}, err
	}
	intermediate, err := Issue(Template(2, "Rudy Demo Intermediate", true), &root, nil)
	if err != nil {
		return Authority{}, Authority{}, Authority{}, err
	}
	leaf, err := Issue(Template(3, "Rudy Demo Service", false), &intermediate, nil)
	return root, intermediate, leaf, err
}
