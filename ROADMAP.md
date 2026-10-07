# Roadmap

Open work only. Shipped behavior is documented in [README.md](README.md),
[`Documentation/codemap.md`](Documentation/codemap.md) and the release notes
(`Documentation/RELEASE_NOTES_<version>.md`); open defects in
[FINDINGS.md](FINDINGS.md); what remains of the operator plan in
[PLAN.md](PLAN.md). Completed milestones live in git history.

Items here are larger than a bug fix: they change an API, a contract, the
chart, or the shape of the module. A defect that can be fixed in place
belongs in FINDINGS.

## Operator: shipped in v0.9, what remains

The `ClusterIssuer` and `Certificate` CRDs, the Certificate, ClusterIssuer
and Pod controllers and the Pod mutating webhook shipped in v0.9
([`Documentation/RELEASE_NOTES_0.9.md`](Documentation/RELEASE_NOTES_0.9.md),
design in [`Documentation/design/operator.md`](Documentation/design/operator.md)).
Batch P7 of [PLAN.md](PLAN.md) holds the remaining hardening: an e2e job in
CI, alerting snippets, the migration guide and trust-bundle versioning.
Larger follow-ups:

- A `ValidatingAdmissionPolicy` (CEL) generated from the `ClusterIssuer`
  policy, so a bad `Certificate` spec is rejected at admission instead of
  in the `Ready` condition.
- In-Pod keys: a `CertificateRequest`-style resource carrying a CSR with
  a sidecar or CSI driver generating the key; the Certificate controller
  then only signs.
- A `kubectl` plugin for `renew-requested` and `kubectl get certs -o wide`
  style summaries.

## kubecertinit (deprecated)

The init-container flow is deprecated since v0.9 and kept for the
migration period. Remaining: the key file mode and the Pod
`securityContext` it needs (KUBECA-003, decision pending). No new flags or
behavior; removal after the last documented deployment has migrated.

## Controller tests: envtest and e2e

Unit tests cover every controller with the fake client and an in-memory
Authority (`internal/testauthority`), and `internal/operator/envtest_test.go`
validates the CRDs (CEL rules, status subresource) against a real API
server when `KUBEBUILDER_ASSETS` is set (`make envtest`). Still open:

- Run the ClusterIssuer and Certificate controllers themselves under
  envtest (manager, informers, owner-reference garbage collection), not
  only the CRDs.
- The minikube e2e (`make minikube-all`) is manual; PLAN.md P7 moves it to
  a kind + local-kms job in CI.

## Build and CI parity with xpki

- Pin the remaining tool versions in `Makefile` variables
  (`COV_REPORT_VERSION`, `GOVULNCHECK_VERSION`), as xpki v1.0 does
  (XPKI-096). golangci-lint, controller-gen and setup-envtest are pinned.
- CI runs `make lint`, `fmt-check`, `make manifests` with `git diff
  --exit-code` and the envtest tests since v0.9; the race detector is
  still local only.
- Enforce the coverage gate: `MIN_TESTCOV` is declared in
  `.github/workflows/build.yml` but nothing reads it.
- Drop the `version` step from the CI `Prepare` line (it only prints now).
- Keep `k8s.io/*`, `sigs.k8s.io/controller-runtime`, `controller-tools`
  and `k8s.io/kube-openapi` moving together: the October 2026 `go get -u`
  pulled a `kube-openapi` snapshot that needs `structured-merge-diff/v7`
  while `apimachinery v0.37.1` needs `v6`, which broke the build until the
  pin was reverted (see `Documentation/xpki-1.0-conformance.md`). Add a CI
  build on the Dependabot group and keep `kube-openapi` out of version
  bumps unless the k8s group moves.

## Chart

- The certs Secret (`certs.secretName`) is documented in `values.yaml`
  but still created outside the chart; template it from values (or a
  `existingSecret` toggle) for installs that keep the CA files in a
  secret manager.
- Helm never upgrades `crds/`; document or automate `kubectl apply -f
  examples/kubeca/crds` in the upgrade path (a pre-upgrade hook Job).

## Trust distribution and CA rotation

The root bundle now ships with every certificate (`ca.crt` in the Secret)
and in the ConfigMap of `ClusterIssuer.spec.caBundle`. Still open: the
authority is loaded once at startup from the mounted files, so a new
issuer certificate needs a restart; a file watcher with `Authority`
rebuild and the `CAChanged` re-issuance it triggers, and bundle versioning
for the rotation overlap (old and new root in `ca.crt` for one lifetime).

## Observability

The operator metrics of the design (`kubeca_certificate_*`,
`kubeca_issuance_*`, `kubeca_clusterissuer_ca_expiration_timestamp_seconds`)
are served. Open: alert rules and a dashboard snippet (PLAN.md P7), and a
`kubeca_csr_signed_total{signer,profile,result}` counter for the CSR
signer, which today only has xpki's `perf_ca_signreq`.
