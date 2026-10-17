package cli

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/r4venrudy/rudy-certmap/internal/testpki"
)

func fixture(t *testing.T) (string, string) {
	t.Helper()
	r, i, l, err := testpki.Chain()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, certs ...*x509.Certificate) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, testpki.PEM(certs...), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	return write("bundle.pem", l.Cert, i.Cert), write("root.pem", r.Cert)
}
func TestCommandsAndGates(t *testing.T) {
	inventory, roots := fixture(t)
	for _, test := range []struct {
		name string
		args []string
		code int
	}{
		{"json", []string{"inspect", "--roots", roots, "--dns-name", "service.example.test", inventory}, 0},
		{"sarif", []string{"inspect", "--format", "sarif", inventory}, 0},
		{"dot", []string{"inspect", "--format", "dot", inventory}, 0},
		{"wrong-host", []string{"inspect", "--roots", roots, "--dns-name", "wrong.test", inventory}, 1},
		{"collection", []string{"inspect", "--roots", roots, "--dns-name", "wrong.test", "--fail-on", "none", inventory}, 0},
		{"diff", []string{"diff", "--fail-on-change", inventory, inventory}, 0},
		{"changed", []string{"diff", "--fail-on-change", inventory, roots}, 1},
		{"help", []string{"inspect", "--help"}, 0},
		{"version", []string{"--version"}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := Run(test.args, &out, &errOut, func() time.Time { return testpki.At })
			if code != test.code || errOut.Len() != 0 || out.Len() == 0 {
				t.Fatalf("code %d, diagnostic %s", code, errOut.String())
			}
			if test.name != "help" && test.name != "version" && test.name != "dot" && !json.Valid(out.Bytes()) {
				t.Fatal("non-JSON report")
			}
		})
	}
}
func TestRejectedUsageHasNoReport(t *testing.T) {
	inventory, _ := fixture(t)
	cases := [][]string{{"wat"}, {"inspect"}, {"inspect", "missing-file"}, {"inspect", "--format", "html", inventory}, {"inspect", "--fail-on", "typo", inventory},
		{"inspect", "--at", "invalid", inventory}, {"inspect", "--expires-within", "-1", inventory}, {"inspect", "--expires-within", "3651", inventory},
		{"inspect", "--purpose", "typo", inventory}, {"inspect", "--unknown-secret=123", inventory}, {"inspect", "--dns-name", "service.test", inventory}, {"diff", inventory}}
	for _, args := range cases {
		t.Run(strings.Join(args[:1], ""), func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			code := Run(args, &out, &diagnostic, func() time.Time { return testpki.At })
			if code != 2 || out.Len() != 0 || diagnostic.Len() == 0 {
				t.Fatalf("bad rejection: %v => %d %s", args, code, out.String())
			}
			if strings.Contains(diagnostic.String(), "secret=123") {
				t.Fatal("argument echoed")
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestOutputFailure(t *testing.T) {
	inventory, _ := fixture(t)
	var diagnostic bytes.Buffer
	if code := Run([]string{"inspect", inventory}, failingWriter{}, &diagnostic, func() time.Time { return testpki.At }); code != 2 {
		t.Fatal("output failure reported as success")
	}
}
func TestExplicitTimeDeterminism(t *testing.T) {
	inventory, _ := fixture(t)
	var a, b, diagnostic bytes.Buffer
	args := []string{"inspect", "--at", testpki.At.Format(time.RFC3339), inventory}
	Run(args, &a, &diagnostic, time.Now)
	Run(args, &b, &diagnostic, func() time.Time { return testpki.At.AddDate(10, 0, 0) })
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("explicit-time reports depend on wall clock")
	}
}
func TestExecutable(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess build")
	}
	inventory, roots := fixture(t)
	exe := filepath.Join(t.TempDir(), "certmap.exe")
	command := exec.Command("go", "build", "-o", exe, "../../cmd/certmap")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %s %v", output, err)
	}
	command = exec.Command(exe, "inspect", "--roots", roots, "--dns-name", "service.example.test", "--at", testpki.At.Format(time.RFC3339), inventory)
	output, err := command.Output()
	if err != nil || !json.Valid(output) {
		t.Fatalf("executable failed: %s %v", output, err)
	}
}
