# Roadmap

Open work only. Shipped behavior is documented in [README.md](README.md),
[`Documentation/codemap.md`](Documentation/codemap.md) and the release notes
(`Documentation/RELEASE_NOTES_<version>.md`); open defects in
[FINDINGS.md](FINDINGS.md); the execution plan of the operator in
[PLAN.md](PLAN.md). Completed milestones live in git history.

Items here are larger than a bug fix: they change an API, a contract, the
chart, or the shape of the module. A defect that can be fixed in place
belongs in FINDINGS.

## KubeCA Operator: short-lived certificates with renewal

The init-container flow issues one certificate at Pod start and never
renews it, so profiles carry year-long expiries (`8760h` in the chart). The
operator adds two CRDs (`ClusterIssuer`, `Certificate`), a Certificate
controller that issues into a `kubernetes.io/tls` Secret and renews it
before expiry, a Pod controller and a mutating webhook that create
Certificates for labeled Pods, all in the same `kubeca` binary and manager.
Target: 24-hour certificates renewed 8 hours before expiry.

- Design: [`Documentation/design/operator.md`](Documentation/design/operator.md)
  and [`operator-api.md`](Documentation/design/operator-api.md).
- Plan, phases and open decisions: [PLAN.md](PLAN.md).
- Examples: [`examples/operator`](examples/operator).

The CSR signing controller stays for clients that use the Kubernetes CSR
API directly and for the migration period of `kubecertinit`.

## CSR approval policy (KUBECA-001, decided)

Decision (FINDINGS KUBECA-001): approval must be automatic, option (a).
The controller approves a CSR when every name it carries is one the
requester may have, and denies it otherwise:

- Requester: `spec.username` is `system:serviceaccount:<ns>:<sa>` (reject
  other principals unless a flag allows them).
- Allowed names: for the Pods of that ServiceAccount in that namespace,
  the Pod IP, `<ip-dashed>.<ns>.pod.<domain>`,
  `<hostname>.<subdomain>.<ns>.svc[.<domain>]`, the names and IPs of the
  Services selecting those Pods (the `internal/certinit` derivation, moved
  to a shared `internal/k8snames` package), the SPIFFE URI
  `spiffe://<trust-domain>/ns/<ns>/sa/<sa>`, plus a configurable allow-list
  (`localhost`, `127.0.0.1`) for names every workload may use.
- Outcome: `Approved` then sign; or `Denied` with reason `NamesNotAllowed`
  and the offending names in the message, which `kubecertinit` reports and
  exits on.
- Rollout: a flag (`-approve=off|audit|enforce`) defaulting to `off` keeps
  the current implicit approval; `audit` logs and emits an event for CSRs
  that would be denied; `enforce` denies. Flip the default to `enforce`
  when the operator ships (PLAN.md D-7).
- RBAC: the controller needs `get/list/watch` on Pods and Services
  cluster-wide and `update` on `certificatesigningrequests/approval` plus
  `approve` on the `signers` (the `kubeca:csr-approver` role in the chart,
  KUBECA-012).
- KUBECA-013 ships in the same change: signing errors after approval set
  `Failed` when xpki reports a policy or parse error, retry otherwise. xpki
  returns untyped errors today; request typed sentinel errors from
  `authority.Issuer.Sign` (an xpki change) or classify conservatively.

## kubecertinit hardening

- Default for `-timeout` and a watch instead of the 5-second poll
  (KUBECA-006, decision pending).
- Key file mode and the Pod `securityContext` it needs (KUBECA-003,
  decision pending).
- Move `getNamesForPod` and `serviceNames` into `internal/k8snames`, shared
  with the approver above and the operator's Pod controller (PLAN.md,
  batch P5).

## Error handling: migrate to `github.com/cockroachdb/errors`

`internal/certinit` and `internal/controller` import `github.com/pkg/errors`;
xpki v1.0 returns `cockroachdb/errors` values. `errors.Is`/`As` interoperate,
but wrapping conventions and `%+v` output differ. Switch both packages in
one change (the call sites are `errors.New`, `Errorf`, `Wrapf`,
`WithMessage`, `WithMessagef` and `WithStack`), then remove the dependency
from `go.mod`.

## Controller tests

`internal/controller` has no tests. Add reconcile tests with
`controller-runtime`'s fake client and an `inmemcrypto`-backed
`authority.Authority` built from `testca` certificates: signer-name mapping,
the NotFound/Denied/already-signed/no-signer branches, the status patch
content (leaf plus issuer chain), the `Signed` and `SigningFailed` events,
and the approver once it exists. `envtest` comes with the operator
(PLAN.md, batch P1).

## Build and CI parity with xpki

- Pin the remaining tool versions in `Makefile` variables
  (`COV_REPORT_VERSION`, `GOVULNCHECK_VERSION`), as xpki v1.0 does
  (XPKI-096). golangci-lint is pinned (`GOLANGCI_LINT_VERSION`, xpki's
  v2.13.2) and `.golangci.yaml` exists.
- Run `make lint` and a `git diff --exit-code` check in CI (XPKI-095), and
  add `fmt-check` so CI never reformats the checkout.
- Enforce the coverage gate: `MIN_TESTCOV` is declared in
  `.github/workflows/build.yml` but nothing reads it.
- Drop `goveralls` from `make tools` (coveralls was removed from CI), and
  the `version` step from the CI `Prepare` line (it only prints now).
- Keep `k8s.io/*`, `sigs.k8s.io/controller-runtime` and `k8s.io/kube-openapi`
  moving together: the October 2026 `go get -u` pulled a `kube-openapi`
  snapshot that needs `structured-merge-diff/v7` while `apimachinery
  v0.37.1` needs `v6`, which broke the build until the pin was reverted
  (see `Documentation/xpki-1.0-conformance.md`). Add a CI build on the
  Dependabot group and keep `kube-openapi` out of version bumps unless the
  k8s group moves.

## Chart clean-up

KUBECA-012 remaining: an HPA template for `autoscaling` or its removal,
the certs Secret templated from values or documented in `values.yaml`, and
a `csr-creator` ClusterRole for workloads so the README's copy is not the
only source. The operator adds `crds/`, operator RBAC and webhook templates
(PLAN.md, batch P4).

## Trust distribution and CA rotation

Certificates carry the issuer chain, but clients need the root to verify
peers. Publish the issuer's root bundle into a ConfigMap per namespace (the
operator's `ClusterIssuer.spec.caBundle`) and document how a CA key
rotation is rolled out: the authority is loaded once at startup from the
mounted files, so a new issuer certificate needs a restart today; a file
watcher with `Authority` rebuild, and re-issuance of Certificates whose
issuing CA changed, come after the operator's first release.

## Observability

Add issuance counters by signer, profile and result (`kubeca_csr_signed_total`
and the operator metrics in the design).
