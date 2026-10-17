package certmap

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/r4venrudy/rudy-certmap/internal/testpki"
)

func chain(t testing.TB) (testpki.Authority, testpki.Authority, testpki.Authority) {
	t.Helper()
	r, i, l, err := testpki.Chain()
	if err != nil {
		t.Fatal(err)
	}
	return r, i, l
}
func bundle(t testing.TB, certs ...*x509.Certificate) Bundle {
	t.Helper()
	b, err := Parse(testpki.PEM(certs...))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func issue(t testing.TB, template *x509.Certificate, parent *testpki.Authority) testpki.Authority {
	t.Helper()
	a, err := testpki.Issue(template, parent, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func opts(roots Bundle) Options {
	return Options{At: testpki.At, Roots: &roots, DNSName: "service.example.test", Purpose: "server", ExpiresWithin: 30 * 24 * time.Hour}
}
func leafResult(t testing.TB, report Report, id string) Certificate {
	t.Helper()
	for _, c := range report.Certificates {
		if c.ID == id {
			return c
		}
	}
	t.Fatal("missing certificate")
	return Certificate{}
}
func has(report Report, rule string) bool {
	for _, f := range report.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestVerifiedChain(t *testing.T) {
	r, i, l := chain(t)
	report, err := Audit(bundle(t, l.Cert, i.Cert), opts(bundle(t, r.Cert)))
	if err != nil {
		t.Fatal(err)
	}
	c := leafResult(t, report, ID(l.Cert))
	if c.Verification.Status != "verified" || len(c.Verification.Paths) != 1 || len(c.Verification.Paths[0]) != 3 {
		t.Fatalf("wrong path: %+v", c.Verification)
	}
	if len(report.Findings) != 0 || len(report.SignatureEdges) != 2 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if !leafResult(t, report, ID(r.Cert)).SignedBySelf {
		t.Fatal("root signature not recognized")
	}
}
func TestMissingIntermediateAndWrongAnchor(t *testing.T) {
	r, i, l := chain(t)
	root := bundle(t, r.Cert)
	report, err := Audit(bundle(t, l.Cert), opts(root))
	if err != nil {
		t.Fatal(err)
	}
	if leafResult(t, report, ID(l.Cert)).Verification.Failure != "unknown_authority" || !has(report, "CERT007") {
		t.Fatal("missing intermediate accepted")
	}
	options := opts(root)
	extra := bundle(t, i.Cert)
	options.Intermediates = &extra
	report, err = Audit(bundle(t, l.Cert), options)
	if err != nil || leafResult(t, report, ID(l.Cert)).Verification.Status != "verified" {
		t.Fatal("extra intermediate failed", err)
	}
	other := issue(t, testpki.Template(9, "Other Root", true), nil)
	report, err = Audit(bundle(t, l.Cert, i.Cert), opts(bundle(t, other.Cert)))
	if err != nil || !has(report, "CERT007") {
		t.Fatal("wrong root accepted", err)
	}
}
func TestIdentityAndPurpose(t *testing.T) {
	r, i, l := chain(t)
	o := opts(bundle(t, r.Cert))
	o.DNSName = "wrong.example.test"
	report, err := Audit(bundle(t, l.Cert, i.Cert), o)
	if err != nil || leafResult(t, report, ID(l.Cert)).Verification.Failure != "hostname_mismatch" {
		t.Fatal("wrong identity accepted", err)
	}
	o.DNSName = "service.example.test"
	o.Purpose = "client"
	report, err = Audit(bundle(t, l.Cert, i.Cert), o)
	if err != nil || !has(report, "CERT007") {
		t.Fatal("server EKU used for client", err)
	}
	o.Purpose = "any"
	report, err = Audit(bundle(t, l.Cert, i.Cert), o)
	if err != nil || has(report, "CERT007") {
		t.Fatal("explicit any rejected", err)
	}
}
func TestNoImplicitTrust(t *testing.T) {
	r, i, l := chain(t)
	report, err := Audit(bundle(t, r.Cert, i.Cert, l.Cert), Options{At: testpki.At})
	if err != nil {
		t.Fatal(err)
	}
	if leafResult(t, report, ID(l.Cert)).Verification.Status != "not_checked" || has(report, "CERT007") {
		t.Fatal("implicit trust inferred")
	}
	_, err = Audit(bundle(t, l.Cert), Options{At: testpki.At, DNSName: "service.example.test"})
	if err == nil {
		t.Fatal("identity without trust accepted")
	}
}

func TestIPIdentityAndClientCertificate(t *testing.T) {
	r, i, _ := chain(t)
	template := testpki.Template(61, "IP service", false)
	template.DNSNames = nil
	template.IPAddresses = []net.IP{net.ParseIP("2001:db8::10")}
	leaf := issue(t, template, &i)
	o := opts(bundle(t, r.Cert))
	o.DNSName = "2001:db8::10"
	report, err := Audit(bundle(t, leaf.Cert, i.Cert), o)
	if err != nil || leafResult(t, report, ID(leaf.Cert)).Verification.Status != "verified" {
		t.Fatal("IP SAN verification failed", err)
	}
	o.DNSName = "2001:db8::11"
	report, err = Audit(bundle(t, leaf.Cert, i.Cert), o)
	if err != nil || !has(report, "CERT007") {
		t.Fatal("wrong IP accepted", err)
	}
	template = testpki.Template(62, "Client identity", false)
	template.DNSNames = nil
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	client := issue(t, template, &i)
	o.DNSName = ""
	o.Purpose = "client"
	report, err = Audit(bundle(t, client.Cert, i.Cert), o)
	if err != nil || has(report, "CERT007") || has(report, "CERT008") {
		t.Fatal("client-auth policy failed", err)
	}
}
func TestValidityAndExpiryGate(t *testing.T) {
	r, i, _ := chain(t)
	for _, test := range []struct {
		name, rule    string
		before, after time.Time
	}{
		{"expired", "CERT001", testpki.At.Add(-48 * time.Hour), testpki.At.Add(-time.Hour)},
		{"future", "CERT002", testpki.At.Add(time.Hour), testpki.At.Add(48 * time.Hour)},
		{"soon", "CERT003", testpki.At.Add(-time.Hour), testpki.At.Add(24 * time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			template := testpki.Template(12, test.name, false)
			template.NotBefore = test.before
			template.NotAfter = test.after
			l := issue(t, template, &i)
			report, err := Audit(bundle(t, l.Cert, i.Cert), opts(bundle(t, r.Cert)))
			if err != nil || !has(report, test.rule) {
				t.Fatal("validity finding missing", err)
			}
			fail, err := Gate(report.Findings, "warning")
			if err != nil || !fail {
				t.Fatal("gate did not fail")
			}
			fail, _ = Gate(report.Findings, "none")
			if fail {
				t.Fatal("none failed")
			}
		})
	}
	if _, err := Gate(nil, "typo"); err == nil {
		t.Fatal("unknown gate accepted")
	}
}
func TestNameAndPathConstraints(t *testing.T) {
	r, _, _ := chain(t)
	for _, name := range []string{"name", "path"} {
		t.Run(name, func(t *testing.T) {
			parent := testpki.Template(14, "Constrained CA", true)
			if name == "name" {
				parent.PermittedDNSDomainsCritical = true
				parent.PermittedDNSDomains = []string{"allowed.example.test"}
			} else {
				parent.MaxPathLen = 0
				parent.MaxPathLenZero = true
			}
			ca := issue(t, parent, &r)
			issuer := ca
			inventory := []*x509.Certificate{ca.Cert}
			if name == "path" {
				issuer = issue(t, testpki.Template(15, "Extra CA", true), &ca)
				inventory = append(inventory, issuer.Cert)
			}
			leaf := issue(t, testpki.Template(16, "Constrained leaf", false), &issuer)
			inventory = append(inventory, leaf.Cert)
			report, err := Audit(bundle(t, inventory...), opts(bundle(t, r.Cert)))
			if err != nil || !has(report, "CERT007") {
				t.Fatal("constraint bypass", err)
			}
		})
	}
}
func TestCriticalExtensionAndCommonName(t *testing.T) {
	r, i, _ := chain(t)
	for _, name := range []string{"critical", "cn-only"} {
		t.Run(name, func(t *testing.T) {
			template := testpki.Template(20, "service.example.test", false)
			if name == "critical" {
				template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 999}, Critical: true, Value: []byte{5, 0}}}
			} else {
				template.DNSNames = nil
			}
			leaf := issue(t, template, &i)
			report, err := Audit(bundle(t, leaf.Cert, i.Cert), opts(bundle(t, r.Cert)))
			if err != nil || !has(report, "CERT007") {
				t.Fatal("invalid identity/extension accepted", err)
			}
			if name == "cn-only" && !has(report, "CERT008") {
				t.Fatal("missing SAN not reported")
			}
		})
	}
}
func TestCrossSignedPaths(t *testing.T) {
	r, i, l := chain(t)
	other := issue(t, testpki.Template(30, "Second Root", true), nil)
	template := testpki.Template(31, "Rudy Demo Intermediate", true)
	cross, err := testpki.Issue(template, &other, i.Key)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Audit(bundle(t, i.Cert, cross.Cert, l.Cert), opts(bundle(t, r.Cert, other.Cert)))
	if err != nil {
		t.Fatal(err)
	}
	verification := leafResult(t, report, ID(l.Cert)).Verification
	if verification.Status != "verified" || len(verification.Paths) != 2 {
		t.Fatalf("lost cross-sign path: %+v", verification)
	}
	if len(report.SharedPublicKeys) != 1 {
		t.Fatal("shared cross-sign key missing")
	}
}
func TestIssuerNameIsNotProof(t *testing.T) {
	_, i, l := chain(t)
	impostor := issue(t, testpki.Template(40, "Rudy Demo Intermediate", true), nil)
	report, err := Audit(bundle(t, impostor.Cert, l.Cert), Options{At: testpki.At})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SignatureEdges) != 0 || bytes.Equal(i.Cert.RawSubjectPublicKeyInfo, impostor.Cert.RawSubjectPublicKeyInfo) {
		t.Fatal("issuer names treated as signatures")
	}
}
func TestWeakRSA(t *testing.T) {
	r, i, _ := chain(t)
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := testpki.Issue(testpki.Template(50, "Weak demo", false), &i, key)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Audit(bundle(t, leaf.Cert, i.Cert), opts(bundle(t, r.Cert)))
	if err != nil || !has(report, "CERT004") {
		t.Fatal("weak key not flagged", err)
	}
}
func TestInvalidOptionsAndRoots(t *testing.T) {
	_, _, l := chain(t)
	b := bundle(t, l.Cert)
	for _, o := range []Options{{}, {At: testpki.At, Purpose: "typo"}, {At: testpki.At, ExpiresWithin: -1}, {At: testpki.At, Roots: &b}, {At: testpki.At, DNSName: "bad\nname"}} {
		if _, err := Audit(b, o); err == nil {
			t.Fatal("invalid options accepted")
		}
	}
}
func TestDeterministicNormalizationAndDiff(t *testing.T) {
	r, i, l := chain(t)
	a := bundle(t, r.Cert, i.Cert, l.Cert)
	b := bundle(t, l.Cert, r.Cert, i.Cert, l.Cert)
	if b.Duplicates != 1 || len(b.Certificates) != 3 {
		t.Fatal("duplicate not normalized")
	}
	d := Diff(a, b)
	if len(d.Added)+len(d.Removed) != 0 || d.BeforeSHA256 == d.AfterSHA256 {
		t.Fatal("format-only inventory difference")
	}
	first, _ := Audit(a, Options{At: testpki.At})
	second, _ := Audit(b, Options{At: testpki.At})
	if !reflect.DeepEqual(first.Certificates, second.Certificates) || !reflect.DeepEqual(first.SignatureEdges, second.SignatureEdges) {
		t.Fatal("input order leaked")
	}
	renewed, err := testpki.Issue(testpki.Template(77, "Renewed Service", false), &i, l.Key)
	if err != nil {
		t.Fatal(err)
	}
	d = Diff(bundle(t, l.Cert), bundle(t, renewed.Cert))
	if len(d.Added) != 1 || len(d.Removed) != 1 || len(d.ReissuedKeys) != 1 {
		t.Fatal("renewal difference missing")
	}
}
func TestOutputSafetyAndSARIF(t *testing.T) {
	template := testpki.Template(80, "quote\"\nnode [evil=1]", false)
	leaf := issue(t, template, nil)
	report, err := Audit(bundle(t, leaf.Cert), Options{At: testpki.At.AddDate(2, 0, 0)})
	if err != nil {
		t.Fatal(err)
	}
	dot := DOT(report)
	if !strings.Contains(dot, `\"`) || !strings.HasPrefix(dot, "digraph certmap") {
		t.Fatal("DOT quote not escaped")
	}
	data, err := JSON(SARIF(report))
	if err != nil || !json.Valid(data) {
		t.Fatal("invalid SARIF JSON")
	}
	var sarif map[string]any
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatal(err)
	}
	run := sarif["runs"].([]any)[0].(map[string]any)
	if len(run["results"].([]any)) != len(report.Findings) {
		t.Fatal("SARIF lost findings")
	}
	result := run["results"].([]any)[0].(map[string]any)
	fingerprint := result["partialFingerprints"].(map[string]any)["certmap/v1"].(string)
	if len(fingerprint) != 64 {
		t.Fatal("bad fingerprint")
	}
}
func TestStrictParser(t *testing.T) {
	_, _, l := chain(t)
	valid := testpki.PEM(l.Cert)
	cases := map[string][]byte{"empty": nil, "garbage": []byte("junk"), "prefix": append([]byte("junk\n"), valid...), "suffix": append(append([]byte{}, valid...), []byte("junk")...),
		"private": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), "header": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"X": "Y"}, Bytes: l.Cert.Raw}),
		"bad-base64": []byte("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----"), "der-tail": append(append([]byte{}, l.Cert.Raw...), 0),
		"nested": append([]byte("-----BEGIN CERTIFICATE-----\n"), valid...), "overflow": make([]byte, MaxBytes+1), "block-limit": bytes.Repeat(valid, MaxCertificates+1)}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(data); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	if _, err := Parse(l.Cert.Raw); err != nil {
		t.Fatal("DER rejected", err)
	}
	if _, err := Parse(append([]byte(" \n"), valid...)); err != nil {
		t.Fatal("PEM whitespace rejected", err)
	}
}

func TestDERWhitespaceSignatureAndSize(t *testing.T) {
	_, _, leaf := chain(t)
	der := append([]byte{}, leaf.Cert.Raw...)
	// The parser may inventory an invalid signature; binary whitespace is still data.
	der[len(der)-1] = '\n'
	if _, err := Parse(der); err != nil {
		t.Fatal("binary tail was trimmed", err)
	}
	oversized := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: make([]byte, MaxCertificateBytes+1)})
	if _, err := Parse(oversized); err == nil {
		t.Fatal("oversized certificate accepted")
	}
}

func TestLongValidityAndFractionalSeconds(t *testing.T) {
	before := time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC)
	after := time.Date(2600, 1, 1, 0, 0, 0, 0, time.UTC)
	if secondsUntil(after, before) != after.Unix()-before.Unix() {
		t.Fatal("duration saturated")
	}
	if secondsUntil(testpki.At.Add(time.Second), testpki.At.Add(time.Millisecond)) != 0 {
		t.Fatal("positive fractional truncation")
	}
	if secondsUntil(testpki.At.Add(-time.Second), testpki.At.Add(-time.Millisecond)) != 0 {
		t.Fatal("negative fractional truncation")
	}
}

type endless struct{ read int }

func (r *endless) Read(p []byte) (int, error) {
	r.read += len(p)
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

type broken struct{}

func (broken) Read([]byte) (int, error) { return 0, errors.New("secret path") }
func TestBoundedReader(t *testing.T) {
	reader := &endless{}
	if _, err := Read(reader); err == nil || reader.read > MaxBytes+1 {
		t.Fatal("reader exceeded byte bound")
	}
	if _, err := Read(broken{}); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("reader detail leaked")
	}
	if _, err := Read(io.LimitReader(strings.NewReader("x"), 0)); err == nil {
		t.Fatal("empty read accepted")
	}
}
func TestGraphComplexityBound(t *testing.T) {
	root := issue(t, testpki.Template(100, "Repeated Issuer", true), nil)
	certs := []*x509.Certificate{root.Cert}
	for n := int64(101); n < 200; n++ {
		c, err := testpki.Issue(testpki.Template(n, "Repeated Issuer", true), &root, root.Key)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, c.Cert)
	}
	if _, err := Audit(bundle(t, certs...), Options{At: testpki.At}); err == nil || !strings.Contains(err.Error(), "8192") {
		t.Fatal("graph complexity bound missing", err)
	}
}
func FuzzParse(f *testing.F) {
	_, _, l := chain(f)
	f.Add(l.Cert.Raw)
	f.Add(testpki.PEM(l.Cert))
	f.Add([]byte("not a certificate"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16384 {
			t.Skip()
		}
		b, err := Parse(data)
		if err == nil {
			if len(b.Certificates) == 0 {
				t.Fatal("empty success")
			}
			for _, c := range b.Certificates {
				if c == nil || len(c.Raw) == 0 {
					t.Fatal("invalid success")
				}
			}
		}
	})
}
