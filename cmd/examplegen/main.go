// Generates public synthetic fixtures. It never writes private keys.
package main

import (
	"crypto/x509"
	"fmt"
	"github.com/r4venrudy/rudy-certmap/internal/testpki"
	"os"
	"path/filepath"
)

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: examplegen <new-directory>")
	}
	dir := os.Args[1]
	if err := os.Mkdir(dir, 0755); err != nil {
		return fmt.Errorf("example directory must not already exist")
	}
	root, intermediate, leaf, err := testpki.Chain()
	if err != nil {
		return err
	}
	soon := testpki.Template(5, "Rudy Demo Rotated Service", false)
	soon.NotAfter = testpki.At.AddDate(0, 0, 14)
	replacement, err := testpki.Issue(soon, &intermediate, leaf.Key)
	if err != nil {
		return err
	}
	for name, certs := range map[string][]*x509.Certificate{"roots.pem": {root.Cert}, "bundle.pem": {leaf.Cert, intermediate.Cert}, "rotated.pem": {replacement.Cert, intermediate.Cert}, "missing-intermediate.pem": {leaf.Cert}} {
		if err := os.WriteFile(filepath.Join(dir, name), testpki.PEM(certs...), 0644); err != nil {
			return err
		}
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
