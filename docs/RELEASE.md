Rudy CertMap v0.1.0 — developer preview

Offline certificate inventory, cryptographic issuer graphs, explicit-anchor
X.509 path verification, SPKI rotation comparisons, JSON/SARIF/DOT and CI gates.
The analysis core is Go with standard-library dependencies only.

Archives include a standalone binary, public synthetic examples, license and
documentation. Verify archive bytes against SHA256SUMS.txt before extracting.

CI tests Go 1.26 and 1.27 on Linux, Windows and macOS before packaging. Linux
ARM64 and macOS Intel binaries are cross-compiled. This preview does not check
revocation, CT, live deployment, private-key possession or system/browser trust.
