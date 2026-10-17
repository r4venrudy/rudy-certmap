package certmap

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const Version = "0.1.0"
const MaxSignatureChecks = 8192
const MaxReportedPaths = 64

type Options struct {
	At            time.Time
	ExpiresWithin time.Duration
	DNSName       string
	Purpose       string
	Roots         *Bundle
	Intermediates *Bundle
}
type Finding struct {
	Rule        string `json:"rule"`
	Level       string `json:"level"`
	Certificate string `json:"certificate"`
	Message     string `json:"message"`
}
type Verification struct {
	Status  string     `json:"status"`
	Failure string     `json:"failure,omitempty"`
	Paths   [][]string `json:"paths"`
}
type Certificate struct {
	ID                 string       `json:"id"`
	SPKIPin            string       `json:"spkiPin"`
	Subject            string       `json:"subject"`
	Issuer             string       `json:"issuer"`
	Serial             string       `json:"serial"`
	Roles              []string     `json:"roles"`
	IsCA               bool         `json:"isCA"`
	SignedBySelf       bool         `json:"signedBySelf"`
	NotBefore          time.Time    `json:"notBefore"`
	NotAfter           time.Time    `json:"notAfter"`
	ExpiresInSeconds   int64        `json:"expiresInSeconds"`
	KeyAlgorithm       string       `json:"keyAlgorithm"`
	KeyBits            int          `json:"keyBits"`
	SignatureAlgorithm string       `json:"signatureAlgorithm"`
	DNSNames           []string     `json:"dnsNames"`
	IPAddresses        []string     `json:"ipAddresses"`
	Verification       Verification `json:"verification"`
}
type Edge struct {
	Child  string `json:"child"`
	Parent string `json:"parent"`
}
type KeyReuse struct {
	SPKIPin      string   `json:"spkiPin"`
	Certificates []string `json:"certificates"`
}
type Report struct {
	Schema               string            `json:"schema"`
	Version              string            `json:"version"`
	At                   time.Time         `json:"at"`
	DNSName              string            `json:"dnsName"`
	Purpose              string            `json:"purpose"`
	ExpiresWithinSeconds int64             `json:"expiresWithinSeconds"`
	Inputs               map[string]string `json:"inputs"`
	DuplicateBlocks      map[string]int    `json:"duplicateBlocks"`
	Certificates         []Certificate     `json:"certificates"`
	SignatureEdges       []Edge            `json:"signatureEdges"`
	SharedPublicKeys     []KeyReuse        `json:"sharedPublicKeys"`
	Findings             []Finding         `json:"findings"`
	Notices              []string          `json:"notices"`
}

func SPKIPin(c *x509.Certificate) string {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return "sha256/" + base64.StdEncoding.EncodeToString(h[:])
}
func sorted(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	return out
}
func secondsUntil(end, at time.Time) int64 {
	seconds := end.Unix() - at.Unix()
	if seconds > 0 && end.Nanosecond() < at.Nanosecond() {
		seconds--
	}
	if seconds < 0 && end.Nanosecond() > at.Nanosecond() {
		seconds++
	}
	return seconds
}

func keyInfo(c *x509.Certificate) (string, int, bool) {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen(), k.N.BitLen() < 2048
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize, k.Curve.Params().BitSize < 256
	case ed25519.PublicKey:
		return "Ed25519", 256, false
	case *dsa.PublicKey:
		return "DSA", k.P.BitLen(), true
	default:
		return c.PublicKeyAlgorithm.String(), 0, true
	}
}
func verifyFailure(err error) string {
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var critical x509.UnhandledCriticalExtension
	var algorithm x509.InsecureAlgorithmError
	switch {
	case errors.As(err, &unknown):
		return "unknown_authority"
	case errors.As(err, &hostname):
		return "hostname_mismatch"
	case errors.As(err, &critical):
		return "unhandled_critical_extension"
	case errors.As(err, &algorithm):
		return "insecure_signature_algorithm"
	case errors.As(err, &invalid):
		return "invalid_certificate"
	default:
		return "verification_failed"
	}
}

// Audit never uses system roots or downloads issuer/revocation data. Graph edges are
// signature relationships; only Verification.Paths have passed the selected policy.
func Audit(bundle Bundle, opts Options) (Report, error) {
	if opts.At.IsZero() {
		return Report{}, errors.New("an explicit evaluation time is required")
	}
	if opts.At.Year() < 1 || opts.At.Year() > 9999 {
		return Report{}, errors.New("evaluation year must be from 1 to 9999")
	}
	if opts.ExpiresWithin < 0 || opts.ExpiresWithin > 3650*24*time.Hour {
		return Report{}, errors.New("expiry window must be from 0 to 3650 days")
	}
	if len(opts.DNSName) > 253 || strings.ContainsAny(opts.DNSName, "\x00\r\n\t ") {
		return Report{}, errors.New("invalid DNS name or IP identity")
	}
	if opts.DNSName != "" && opts.Roots == nil {
		return Report{}, errors.New("identity verification requires explicit trust roots")
	}
	usage := x509.ExtKeyUsageServerAuth
	switch opts.Purpose {
	case "", "server":
		opts.Purpose = "server"
	case "client":
		usage = x509.ExtKeyUsageClientAuth
	case "any":
		usage = x509.ExtKeyUsageAny
	default:
		return Report{}, errors.New("purpose must be server, client or any")
	}
	report := Report{Schema: "rudy-certmap/audit/v1", Version: Version, At: opts.At.UTC(), DNSName: opts.DNSName, Purpose: opts.Purpose,
		ExpiresWithinSeconds: int64(opts.ExpiresWithin / time.Second), Inputs: map[string]string{}, DuplicateBlocks: map[string]int{},
		Certificates: []Certificate{}, SignatureEdges: []Edge{}, SharedPublicKeys: []KeyReuse{}, Findings: []Finding{},
		Notices: []string{"No network requests, system trust store, AIA fetching, OCSP, CRL or Certificate Transparency checks.",
			"Signature edges are not trust paths. Verified paths apply only to supplied anchors, identity, purpose and evaluation time.",
			"Certificate validity does not establish server possession of a private key or current deployment state.",
			"Shared SPKI means the same public key, not proof of a private-key compromise."}}
	certs := map[string]*x509.Certificate{}
	roles := map[string][]string{}
	addBundle := func(name string, b Bundle) error {
		if len(b.Certificates) == 0 || len(b.Certificates) > MaxCertificates {
			return errors.New("bundle must contain from 1 to 256 certificates")
		}
		report.Inputs[name] = b.SHA256
		report.DuplicateBlocks[name] = b.Duplicates
		for _, c := range b.Certificates {
			if c == nil {
				return errors.New("nil certificate in bundle")
			}
			id := ID(c)
			certs[id] = c
			roles[id] = append(roles[id], name)
		}
		return nil
	}
	if err := addBundle("inventory", bundle); err != nil {
		return Report{}, err
	}
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	if opts.Roots != nil {
		if err := addBundle("trust_roots", *opts.Roots); err != nil {
			return Report{}, err
		}
		for _, c := range opts.Roots.Certificates {
			if !c.IsCA || !c.BasicConstraintsValid || (c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageCertSign == 0) {
				return Report{}, errors.New("trust roots must be CA certificates with certificate-signing permission")
			}
			roots.AddCert(c)
		}
	}
	if opts.Intermediates != nil {
		if err := addBundle("intermediates", *opts.Intermediates); err != nil {
			return Report{}, err
		}
	}
	if len(certs) > MaxCertificates {
		return Report{}, errors.New("combined inventory exceeds 256 unique certificates")
	}
	ids := make([]string, 0, len(certs))
	for id, c := range certs {
		ids = append(ids, id)
		if c.IsCA {
			intermediates.AddCert(c)
		}
	}
	sort.Strings(ids)
	subjects := map[string][]string{}
	for _, id := range ids {
		c := certs[id]
		subjects[string(c.RawSubject)] = append(subjects[string(c.RawSubject)], id)
	}
	checks := 0
	for _, id := range ids {
		c := certs[id]
		for _, parentID := range subjects[string(c.RawIssuer)] {
			if id == parentID {
				continue
			}
			checks++
			if checks > MaxSignatureChecks {
				return Report{}, errors.New("issuer graph exceeds 8192 candidate signature checks")
			}
			if c.CheckSignatureFrom(certs[parentID]) == nil {
				report.SignatureEdges = append(report.SignatureEdges, Edge{id, parentID})
			}
		}
	}
	keys := map[string][]string{}
	for _, id := range ids {
		c := certs[id]
		algorithm, bits, weak := keyInfo(c)
		pin := SPKIPin(c)
		keys[pin] = append(keys[pin], id)
		ips := []string{}
		for _, ip := range c.IPAddresses {
			ips = append(ips, ip.String())
		}
		sort.Strings(ips)
		verification := Verification{Status: "not_checked", Paths: [][]string{}}
		add := func(rule, level, message string) {
			report.Findings = append(report.Findings, Finding{rule, level, id, message})
		}
		switch {
		case opts.At.After(c.NotAfter):
			add("CERT001", "error", "Certificate has expired at the evaluation time.")
		case opts.At.Before(c.NotBefore):
			add("CERT002", "error", "Certificate is not yet valid at the evaluation time.")
		case c.NotAfter.Sub(opts.At) <= opts.ExpiresWithin:
			add("CERT003", "warning", "Certificate expires within the configured window.")
		}
		if weak {
			add("CERT004", "warning", "Public key is below the RSA-2048 / ECDSA-256 baseline or uses an unsupported key family.")
		}
		if c.SignatureAlgorithm == x509.MD5WithRSA || c.SignatureAlgorithm == x509.SHA1WithRSA || c.SignatureAlgorithm == x509.DSAWithSHA1 || c.SignatureAlgorithm == x509.ECDSAWithSHA1 {
			add("CERT005", "warning", "Certificate declares an MD5 or SHA-1 signature algorithm.")
		}
		if c.IsCA && (!c.BasicConstraintsValid || (c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageCertSign == 0)) {
			add("CERT006", "error", "CA declaration lacks valid basic constraints or certificate-signing permission.")
		}
		isInventory := false
		for _, role := range roles[id] {
			if role == "inventory" {
				isInventory = true
			}
		}
		if !c.IsCA && isInventory {
			if opts.Purpose == "server" && len(c.DNSNames)+len(c.IPAddresses) == 0 {
				add("CERT008", "warning", "Server certificate declares no DNS or IP subject alternative names.")
			}
			if opts.Roots != nil {
				chains, err := c.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: opts.At, DNSName: opts.DNSName, KeyUsages: []x509.ExtKeyUsage{usage}})
				if err != nil {
					verification.Status = "failed"
					verification.Failure = verifyFailure(err)
					add("CERT007", "error", "Certificate has no verified path under the selected trust, identity, time and purpose settings.")
				} else {
					if len(chains) > MaxReportedPaths {
						return Report{}, errors.New("verification returned more than 64 trust paths")
					}
					verification.Status = "verified"
					for _, chain := range chains {
						path := []string{}
						for _, item := range chain {
							path = append(path, ID(item))
						}
						verification.Paths = append(verification.Paths, path)
					}
					sort.Slice(verification.Paths, func(i, j int) bool {
						return strings.Join(verification.Paths[i], "/") < strings.Join(verification.Paths[j], "/")
					})
				}
			}
		} else {
			verification.Status = "not_applicable"
		}
		self := bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
		report.Certificates = append(report.Certificates, Certificate{id, pin, c.Subject.String(), c.Issuer.String(), c.SerialNumber.Text(16), sorted(roles[id]), c.IsCA, self,
			c.NotBefore.UTC(), c.NotAfter.UTC(), secondsUntil(c.NotAfter, opts.At), algorithm, bits, c.SignatureAlgorithm.String(), sorted(c.DNSNames), ips, verification})
	}
	pins := make([]string, 0, len(keys))
	for pin := range keys {
		pins = append(pins, pin)
	}
	sort.Strings(pins)
	for _, pin := range pins {
		if len(keys[pin]) > 1 {
			report.SharedPublicKeys = append(report.SharedPublicKeys, KeyReuse{pin, keys[pin]})
		}
	}
	sort.Slice(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Certificate < b.Certificate
	})
	return report, nil
}

func Gate(findings []Finding, threshold string) (bool, error) {
	if threshold != "error" && threshold != "warning" && threshold != "none" {
		return false, fmt.Errorf("failure threshold must be error, warning or none")
	}
	for _, f := range findings {
		if threshold != "none" && (f.Level == "error" || threshold == "warning" && f.Level == "warning") {
			return true, nil
		}
	}
	return false, nil
}
