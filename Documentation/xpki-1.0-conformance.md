# xpki v1.0 conformance

How `github.com/effective-security/xpki` v1.0 (release notes:
`xpki/Documentation/RELEASE_NOTES_1.0.md`, finding IDs `XPKI-NNN`) affects
this module, what was changed on 2026-10-06 to conform, and what remains
open. `go.mod` pins `xpki v1.0.310`.

## What was verified

| Check                                                      | Result                                                                                                                                 |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `go build ./...`, `go vet ./...`                           | Pass after the `kube-openapi` fix below. Every xpki symbol kubeca calls exists with the same signature in v1.0.                        |
| `go test ./...` and `go test -race ./...`                  | Pass after the `internal/certinit` fixture fix below.                                                                                  |
| `golangci-lint run ./...` (v2.13.2)                        | 0 issues.                                                                                                                              |
| `helm lint`, `helm template` with `examples/kubeca/local.yaml` | Renders; the `ca-config.kubeca.yaml` ConfigMap carries the updated profiles.                                                           |
| Against a cluster or a KMS                                 | **Not run.** No kind cluster or local-kms is available here; the controller has no tests (ROADMAP). Validate on a dev cluster before release. |

## Changes made

### Build: `kube-openapi` snapshot skew (not an xpki change)

`go.mod` pinned `k8s.io/kube-openapi v0.0.0-20261006145848-eb06d4f03a2d`,
which imports `sigs.k8s.io/structured-merge-diff/v7`, while
`k8s.io/apimachinery v0.37.1` and `controller-runtime v0.25.2` build against
`v6`; `apimachinery`'s `managedfields/internal/typeconverter.go` failed to
compile. Downgraded `kube-openapi` to the snapshot `k8s.io v0.37.1`
requires (`v0.0.0-20260721132016-d427ff9ee9ad`) and ran `go mod tidy`, which
also dropped `structured-merge-diff/v7`. Rule going forward: ROADMAP, "Build
and CI parity".

### `internal/certinit` test fixture (XPKI-059)

`csr.Provider.CreateRequestAndExportKey` now fails on an invalid SAN instead
of issuing it. `TestCreate` used a Pod with no namespace and no IP and a
Service with no name, which produced `..pod.test` and
`pod1.domain.com..svc.test` (empty DNS labels). The fixture now has a
namespace, a Pod IP, a selecting Service with a ClusterIP and an external
IP, a non-matching Service, a selector-less Service, a duplicate `-san`
value and a label list with malformed entries. The test captures the
created CSR, parses it with `csr.ParsePEM` and asserts the exact DNS, IP,
URI and email lists (order preserved, duplicate dropped), the usages, the
signer name, the labels and the CSR name pattern, and checks the three
files in `CertDir`. It also covers the `Denied` condition and the two
signer-name errors. Files go under `t.TempDir()` instead of
`/tmp/tests/certinit`.

### Chart profiles: `allowed_extensions` (XPKI-049, XPKI-050)

`examples/kubeca/etc/ca-config.kubeca.yaml` listed `2.5.29.17` (SAN) and
`1.3.6.1.5.5.7.1.1` (AIA) in every profile's `allowed_extensions`. In v1.0
the SAN extension is profile-owned and always dropped from a CSR (names are
copied through `allowed_fields` instead), and `kubecertinit` sends no AIA
extension, so the entries did nothing and suggested the wrong mental model.
They were removed (an empty list allows no CSR extension, which is the
intended policy) and the field comments now describe the v1.0 rules,
`allowed_uri` and `allowed_profiles`. Issued certificates do not change.

### Code comments

Finding IDs from [FINDINGS.md](../FINDINGS.md) were added next to the code
they describe; `doc.go` files were added to every package.

## Release-note items and their effect on kubeca

| xpki item                                                                 | kubeca use                                                                                                                     | Effect and status                                                                                                                                                                                                                                                                      |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **authority** XPKI-049/050: CSR extensions never copied unless allow-listed; one extension per OID | The controller passes the CSR with `SignRequest{Request, Profile}` only. `kubecertinit` CSRs carry a SAN extension and nothing else. | Names still flow through `allowed_fields` (`uri`, `dns`, `ip` in the chart). Chart entries removed (above). A client CSR with other extensions is now rejected (see KUBECA-013 for the retry behavior).                                                                                 |
| **authority** XPKI-054: explicit `NotBefore`/`NotAfter` must fit the profile window | Not set by the controller.                                                                                                     | No effect. The operator must compute `NotAfter = NotBefore + duration` with `NotBefore = now (to the minute) − backdate`, see `Documentation/design/operator.md`.                                                                                                                      |
| **authority** XPKI-057: populated `allowed_profiles` filters every profile | Not set in the chart.                                                                                                          | No effect; documented in the chart comments.                                                                                                                                                                                                                                           |
| **authority** XPKI-055: `Authority` safe for concurrent use; `Profiles()`/`Issuers()` return copies | `GetIssuerByProfile`, `Issuer.Label`, `Issuer.PEM`, `Issuer.Sign`.                                                             | No effect today (`MaxConcurrentReconciles` is 1). Allows the operator to reconcile concurrently.                                                                                                                                                                                       |
| **authority** XPKI-058: `IssuerConfig.Type` JSON key is `type`             | YAML config only.                                                                                                              | No effect.                                                                                                                                                                                                                                                                             |
| **csr** XPKI-059: SAN validation and dedup; `SetSAN` deprecated           | `csr.CertificateRequest{SAN: ...}` through `CreateRequestAndExportKey`; `Issuer.Sign` validates CSR names.                     | `kubecertinit` fails fast on an invalid `-san` or derived name (test updated). Production inputs are valid; the headless `None` name is no longer added (v0.8). The controller rejects malformed client CSRs permanently, which today means endless retries with `SigningFailed` events (KUBECA-013).                           |
| **cryptoprov** XPKI-016/026/113: registry synchronized; duplicates and nil are errors; providers self-register | `cryptoprov.Register` in `cmd/kubeca/main.go`, `cryptoprov.Load(hsmCfg, nil)`.                                                 | The explicit `SoftHSM`/`AWSKMS`/`GCPKMS` registrations returned `already registered`; v0.8 registers only the aliases and exits on an error. `Load` with one config is unaffected.                                                                                                                           |
| **awskmscrypto** XPKI-025/031..034: `Sign` checks options before any RPC; `NewSigner` needs `SigningAlgorithms`; credentials from the SDK default chain | Used only through `cryptoprov.Load` and `authority` (`GetKey`), which pass the key's algorithms.                                 | No code change. The chart's IRSA annotation (`eks.amazonaws.com/role-arn`) relies on the default chain, which v1.0 uses. `EnumKeys` is not called.                                                                                                                                      |
| **gcpkmscrypto** XPKI-018..025/116..124: `Keyring` required; versioned key ids; `Endpoint` applied | Registered, not configured in the chart.                                                                                        | A GCP deployment must set `Keyring` in the token config and may pin `K/cryptoKeyVersions/N` in the issuer `key:` URI; a bare id resolves to the newest enabled version.                                                                                                                 |
| **crypto11** XPKI-001..011/110: ref-counted modules, bounded pools, re-login | `SoftHSM`/`PKCS11` registered, not configured in the chart.                                                                     | A PKCS#11 config needs `TokenSerial` or `TokenLabel`.                                                                                                                                                                                                                                  |
| **certutil** XPKI-041: system roots no longer implicit                    | `certutil.ParseChainFromPEM` only (no bundler).                                                                                | No effect.                                                                                                                                                                                                                                                                             |
| **x/print**, **metricskey**                                               | `print.Certificate(s)`, `metricskey.PerfCASignRequest`.                                                                        | Unchanged.                                                                                                                                                                                                                                                                             |
| **errors**: xpki returns `github.com/cockroachdb/errors` values           | kubeca wraps them with `github.com/pkg/errors`.                                                                                | `errors.Is`/`As` work across both; stack formatting differs. Migration in ROADMAP.                                                                                                                                                                                                      |
| **jwt**, **dpop**, **accesstoken**, **oauth2client**, **dataprotection**, **armor**, **testca** changes; go-jose v4 | Not used.                                                                                                                      | None.                                                                                                                                                                                                                                                                                  |
| **build** XPKI-097: version linked with `-ldflags`                        | `internal/version` was generated from a template and not linked.                                                                | Adopted in v0.8: `make build` sets `LDFLAGS`, both commands have `-version`.                                                                                                                                                                                                           |
| **build** XPKI-095/096: pinned tools, `make lint` in CI, `fmt-check`      | `Makefile` pins golangci-lint v2.13.2 (xpki's pin) and `.golangci.yaml` matches xpki's; CI runs `build covtest` only.           | ROADMAP, "Build and CI parity".                                                                                                                                                                                                                                                        |

## Contract summary for signing code

Keep these rules in mind when changing the controller or writing the
operator (details in `xpki/authority/README.md`):

- The CSR is untrusted: subject and names are copied only as
  `allowed_fields` permits and must match `allowed_names`, `allowed_dns`,
  `allowed_uri`, `allowed_email` when set; extensions only when listed in
  `allowed_extensions` (empty allows none); SAN, KU, EKU, basic constraints,
  SKI, AKI and OCSP no-check always come from the profile.
- The `SignRequest` is trusted: a non-nil `SAN` replaces the CSR names, its
  `Extensions` are allowed by an empty list, `Subject` is merged.
- Validity: with no explicit times, `NotBefore = now rounded to the minute −
  backdate` (profile `backdate`, default 5m) and `NotAfter = NotBefore +
  expiry`. Explicit times must satisfy `NotBefore ≥ now − backdate`,
  `NotAfter > NotBefore` and `NotAfter − NotBefore ≤ expiry`; `NotAfter` is
  clipped to the issuer's `NotAfter`. Invalid windows are rejected, never
  adjusted.
- Every name is validated and deduplicated (`csr.ParseSAN`); a URI must
  contain `://`.
- `Authority`, `Issuer.Sign` and `inmemcrypto` are safe for concurrent use.
