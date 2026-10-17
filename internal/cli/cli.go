// Package cli implements command behavior with injectable I/O and time.
package cli

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/r4venrudy/rudy-certmap/certmap"
)

const help = `RUDY / CERTMAP — offline certificate trust and rotation review

  certmap inspect [options] bundle.pem
    --roots file.pem             explicit trust anchors; never system roots
    --intermediates file.pem     additional chain-building certificates
    --dns-name name              verify a DNS/IP identity; requires --roots
    --purpose server|client|any   default server (any disables EKU restrictions)
    --at RFC3339                 evaluation time; default current UTC time
    --expires-within days        expiry warning window, 0..3650; default 30
    --format json|sarif|dot       default json
    --fail-on error|warning|none  default error
  certmap diff [--fail-on-change] before.pem after.pem
  certmap --version

Place options before file arguments. Inputs: strict certificate-only PEM or one DER.
Exit: 0 completed, 1 policy/diff gate reached, 2 input/usage/output error.
No network, system roots, private keys, revocation or live-server checks.
`

func Run(args []string, out, errOut io.Writer, now func() time.Time) int {
	fail := func(message string) int { fmt.Fprintln(errOut, message); return 2 }
	if len(args) == 0 || len(args) == 1 && (args[0] == "--help" || args[0] == "help") {
		if _, err := io.WriteString(out, help); err != nil {
			return fail("Unable to write output.")
		}
		return 0
	}
	if len(args) == 1 && args[0] == "--version" {
		if _, err := fmt.Fprintln(out, "certmap "+certmap.Version); err != nil {
			return fail("Unable to write output.")
		}
		return 0
	}
	var buffer bytes.Buffer
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(&buffer)
	emit := func(data []byte, gate bool) int {
		if _, err := out.Write(data); err != nil {
			return fail("Unable to write output.")
		}
		if gate {
			return 1
		}
		return 0
	}
	parse := func() int {
		if err := fs.Parse(args[1:]); err != nil {
			if err == flag.ErrHelp {
				if _, writeErr := io.WriteString(out, help); writeErr != nil {
					return fail("Unable to write output.")
				}
				return 0
			}
			return fail("Invalid command options. Use --help.")
		}
		return -1
	}
	switch args[0] {
	case "inspect":
		roots := fs.String("roots", "", "trust roots")
		extra := fs.String("intermediates", "", "additional intermediates")
		dns := fs.String("dns-name", "", "DNS/IP identity")
		purpose := fs.String("purpose", "server", "certificate purpose")
		at := fs.String("at", "", "RFC3339 time")
		days := fs.Int("expires-within", 30, "warning window in days")
		format := fs.String("format", "json", "report format")
		threshold := fs.String("fail-on", "error", "failure threshold")
		if code := parse(); code >= 0 {
			return code
		}
		if fs.NArg() != 1 {
			return fail("Inspect requires one certificate inventory.")
		}
		if *days < 0 || *days > 3650 {
			return fail("Expiry window must be from 0 to 3650 days.")
		}
		if *format != "json" && *format != "sarif" && *format != "dot" {
			return fail("Unsupported output format.")
		}
		if _, err := certmap.Gate(nil, *threshold); err != nil {
			return fail(err.Error())
		}
		evaluation := now().UTC()
		if *at != "" {
			var err error
			evaluation, err = time.Parse(time.RFC3339, *at)
			if err != nil {
				return fail("Evaluation time must be RFC3339.")
			}
		}
		b, err := certmap.Load(fs.Arg(0))
		if err != nil {
			return fail(err.Error())
		}
		opts := certmap.Options{At: evaluation, DNSName: *dns, Purpose: *purpose, ExpiresWithin: time.Duration(*days) * 24 * time.Hour}
		if *roots != "" {
			bundle, err := certmap.Load(*roots)
			if err != nil {
				return fail(err.Error())
			}
			opts.Roots = &bundle
		}
		if *extra != "" {
			bundle, err := certmap.Load(*extra)
			if err != nil {
				return fail(err.Error())
			}
			opts.Intermediates = &bundle
		}
		report, err := certmap.Audit(b, opts)
		if err != nil {
			return fail(err.Error())
		}
		gate, _ := certmap.Gate(report.Findings, *threshold)
		var data []byte
		if *format == "dot" {
			data = []byte(certmap.DOT(report))
		} else if *format == "sarif" {
			data, err = certmap.JSON(certmap.SARIF(report))
		} else {
			data, err = certmap.JSON(report)
		}
		if err != nil {
			return fail("Unable to encode report.")
		}
		return emit(data, gate)
	case "diff":
		gate := fs.Bool("fail-on-change", false, "exit 1 for inventory differences")
		if code := parse(); code >= 0 {
			return code
		}
		if fs.NArg() != 2 {
			return fail("Diff requires before and after inventories.")
		}
		before, err := certmap.Load(fs.Arg(0))
		if err != nil {
			return fail(err.Error())
		}
		after, err := certmap.Load(fs.Arg(1))
		if err != nil {
			return fail(err.Error())
		}
		report := certmap.Diff(before, after)
		data, err := certmap.JSON(report)
		if err != nil {
			return fail("Unable to encode diff.")
		}
		return emit(data, *gate && len(report.Added)+len(report.Removed) > 0)
	default:
		return fail("Unknown command. Use --help.")
	}
}
