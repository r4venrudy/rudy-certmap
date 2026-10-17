# Security boundaries

CertMap is an offline reviewer for public certificate material you are entitled
to handle. It does not scan hosts, collect credentials, execute certificates or
load private keys. It uses Go's standard X.509 and cryptographic implementations.

Trust is explicit. No root becomes trusted by being present in an inventory, and
no default system trust or network fetching fills missing information. Identity,
EKU and time are visible report settings. Inventory and signature observations
must not be presented as proof of deployment, revocation status or key possession.

Treat certificate names and extensions as untrusted input. Do not remove parser
bounds, diagnostic separation or DOT/JSON escaping. Avoid publishing confidential
organization names or internal SANs from private inventories in bug reports.

For suspected vulnerabilities, use the repository's private vulnerability report
feature when available or contact the maintainer through [Rudy Systems](https://rudy.systems).
Supply a minimal synthetic reproducer and the Go version. Do not include real
private keys, credentials or customer certificate inventories.
