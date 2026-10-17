# CertMap contract · v1

## Inputs

One binary DER certificate, or PEM containing only CERTIFICATE blocks separated
by whitespace. Unknown PEM block types, PEM headers, skipped non-whitespace text,
malformed blocks, concatenated DER and DER trailing bytes are rejected. Private
keys and CSRs are not accepted. DER signatures are inventoried before they are
verified: parsing success does not establish signature validity.

| Resource | Limit |
| --- | ---: |
| Each input file | 8 MiB, enforced during reading |
| Each DER certificate | 1 MiB |
| Blocks in each PEM input, including duplicates | 256 |
| Unique certificates across all three inputs | 256 |
| Candidate graph signature checks | 8192 |
| Verified paths per inventory leaf | 64 |
| Expiry warning window | 0–3650 days |

Limit violations reject the entire report with exit 2. Go's verifier has its own
path-building bounds. Graph construction may reject a highly ambiguous same-name
inventory before attempting leaf verification. Bounds do not imply a hard
wall-clock guarantee for arbitrary input.

SHA-256 of the original file bytes identifies each input; SHA-256 of certificate
DER identifies each certificate. SPKI pins are `sha256/` followed by standard
base64 of the SHA-256 digest of the subjectPublicKeyInfo DER. Deduplication is by
certificate DER identity; duplicate block counts are retained per input.

## Trust and graph semantics

All provided certificates appear in the report with one or more roles: inventory,
intermediates and trust_roots. The main inventory must be nonempty. Explicit
trust anchors must be CA certificates with valid basic constraints and signing
permission when key usage is present. Anchors need not be self-signed: explicitly
trusting an intermediate makes it an anchor. This is operator policy.

The tool builds a fresh trust pool and never reads the system pool. All provided
CA certificates may help construct intermediate paths, but only certificates
from `--roots` are trusted anchors. Verification runs only for inventory non-CAs.
Without roots those leaves are `not_checked`; CAs and extra non-inventory leaves
are `not_applicable`. `verified` applies to the selected evaluation time, DNS/IP
identity (if provided) and EKU. `any` deliberately disables EKU restrictions.

Edges match issuer/subject DER and pass `CheckSignatureFrom`, including the
parent's CA/signing checks. A signature edge is not a complete trust-path result.
Self-signatures are reported separately and are not implicit trust. Shared SPKI
groups are observations, not evidence of compromised keys or ownership.

No network, OCSP, CRL, AIA fetching, live TLS handshakes, CT logs or deployment
discovery occurs. A verified path is not a complete browser/WebPKI audit.

## Report schemas

`rudy-certmap/audit/v1` contains an evaluation time and policy, original input
digests, duplicate counts, normalized certificate summaries, signature edges,
shared public keys, findings and coverage notices. Paths list leaf-to-anchor
certificate IDs. Certificates, edges, paths and findings have deterministic
ordering. Explicit `--at` is required for byte-stable reports across runs; Go
version changes may change verifier behavior or subject rendering.

Verification failure classes are stable broad categories: unknown_authority,
hostname_mismatch, invalid_certificate, unhandled_critical_extension,
insecure_signature_algorithm and verification_failed. The library's detailed
error text is not exposed. Broad categories may reflect different underlying
constraint or algorithm failures across Go versions.

`rudy-certmap/diff/v1` compares certificate DER identities. PEM order, wrapping
and duplicate blocks do not change the certificate set. Added/removed identities
are sorted. `reissuedKeys` lists public-key pins present on both sides whose
certificate sets changed; the term does not establish issuer or owner continuity.
Input byte digests may change while the semantic diff remains empty.

SARIF 2.1.0 retains rule/certificate fingerprints and evaluation context with no
invented physical source location. DOT renders signature edges and escapes node
labels; Graphviz is an optional external renderer. A report may contain identity
or organization information from the certificates; review before sharing it.

## Rules

| ID | Level | Condition |
| --- | --- | --- |
| CERT001 | error | Evaluation time is after notAfter |
| CERT002 | error | Evaluation time is before notBefore |
| CERT003 | warning | Valid certificate expires within the configured window |
| CERT004 | warning | RSA <2048, ECDSA <256, DSA or an unsupported key family |
| CERT005 | warning | MD5/SHA-1 signature algorithm |
| CERT006 | error | CA flag lacks basic constraints or signing permission |
| CERT007 | error | Inventory leaf has no verified path under explicit policy |
| CERT008 | warning | Server-purpose inventory leaf lacks DNS/IP SANs |

Metadata findings cover all provided certificates, including anchors and extra
intermediates. They are policy priorities, not CVSS scores. Expiry durations are
integer seconds, truncated toward zero; validity decisions compare full times.

## Public library

Use `Parse`/`Read`/`Load` to construct bundles, then `Audit` or `Diff`. Bundle
certificate objects should be treated as immutable parsed input. `Audit` requires
an explicit nonzero time and returns structured findings without writing files.
`Gate` selects error/warning/none behavior; `JSON`, `SARIF` and `DOT` render reports.
The CLI supplies current time when no explicit time is given.
