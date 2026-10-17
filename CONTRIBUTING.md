# Contributing

Use Go 1.26 or newer and the standard library. Keep certificate policy separate
from cryptographic implementation; changes must preserve explicit trust and the
documented distinction between graph edges and verified paths.

Before a pull request, run `gofmt -w .`, `go vet ./...`, `go test ./... -cover`, and
`go test -race ./...` on a supported host. For parser changes also run
`go test ./certmap -run '^$' -fuzz '^FuzzParse$' -fuzztime 10s -parallel 2`.
Use generated synthetic PKIs for regression tests. Never submit private keys or
private infrastructure certificates. Include tests for the failed behavior and
update the contract if output or policy semantics change.
