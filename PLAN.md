# KubeCA Operator: execution plan

Plan for the work described in
[`Documentation/design/operator.md`](Documentation/design/operator.md) and
[`operator-api.md`](Documentation/design/operator-api.md). It holds open
work only: when a batch ships, remove its rows, record the validation in
the commit or PR, and summarize the change in
`Documentation/RELEASE_NOTES_<version>.md`. Decisions move into the design
documents when taken. Defects found on the way go to
[FINDINGS.md](FINDINGS.md) with the next free ID.

Batches P0 to P6 shipped in v0.9
([`Documentation/RELEASE_NOTES_0.9.md`](Documentation/RELEASE_NOTES_0.9.md)).
Decisions D-1 to D-9 were taken with them and are recorded in
`operator.md` ("Decisions taken"); D-6 was taken with a variation (the
webhook serving certificate is issued in process, not as a `Certificate`
object) and D-7 with the chart defaulting to `approve: enforce` while the
binary keeps `off`.

## Batches

| Batch | Scope                   | Deliverables                                                                                                                                                                                                                                                                                                                                      | Tests and acceptance                                                                                                           | Depends on | Size | Risk |
| ----- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ---------- | ---- | ---- |
| P7    | Hardening and release   | e2e job in CI (kind + local-kms, the `e2e-5m` profile of `examples/kubeca/minikube.yaml` proving renewal and key rotation, as `scripts/minikube_test.sh` does by hand); controllers under envtest (manager, informers, owner GC); alert rules and dashboard snippet for the operator metrics; migration guide finalized (README, "Migrating from the init container"); trust bundle versioning for CA rotation overlap; chart pre-upgrade hook for `crds/` | e2e green in CI; `make lint`, `make test RACE=true`; docs reviewed against `kubectl explain certificates.kubeca.effectivesecurity` | v0.9       | M    | low  |

## File layout (actual)

```text
api/v1alpha1/                  types, constants, deepcopy (generated)
config/crd/bases/              generated CRDs (source of examples/kubeca/crds)
config/rbac/role.yaml          generated from the +kubebuilder:rbac markers; the chart roles are hand-written and compared by review
internal/operator/             Setup, Scheme, CacheOptions, WebhookServer; envtest_test.go (CRD validation)
internal/operator/policy/      pure policy evaluation
internal/operator/index/       field indexes shared by the controllers
internal/operator/metrics/     Prometheus metrics
internal/operator/issuer/      ClusterIssuer controller
internal/operator/certificate/ Certificate controller (reconciler.go, issuance.go, secret.go, renewal.go)
internal/operator/pod/         Pod controller
internal/operator/webhook/     Pod mutator, serving-certificate bootstrap
internal/k8snames/             Pod/Service name discovery (shared with certinit and the approver)
internal/signerr/              permanent vs transient classification of xpki Sign errors
internal/testauthority/        test-only in-memory Authority built from its testdata/ca-config.yaml (the chart's profiles)
internal/controller/           CSR signer with the in-process approver
examples/kubeca/crds/, templates/role-operator.yaml, templates/webhook.yaml
examples/shop/                 application-side demo kept in sync with the API document; e2e/ for the e2e test
examples/kubeca/               the chart: CRDs, controller, RBAC, profiles, ClusterIssuer (values.clusterIssuers)
Documentation/design/          kept in sync with the implementation
```

Package rules: `api/` imports nothing from `internal/`; `internal/operator/*`
imports `api/`, `internal/k8snames`, `internal/signerr`, xpki and
controller-runtime; the controllers do not import each other (shared
helpers go to `policy`, `index`, `metrics` or `k8snames`). Constants
(group, labels, annotations, conditions, reasons) exist once, in
`api/v1alpha1/constants.go`.

## Tooling and CI

- `controller-gen` (sigs.k8s.io/controller-tools, `CONTROLLER_GEN_VERSION`)
  is pinned in `Makefile`; `make generate` runs `object` (deepcopy, through
  the `go:generate` directive in `api/v1alpha1/doc.go`) and `make
  manifests` runs `crd`, `rbac` and `webhook` into `config/` and copies the
  CRDs into the chart. Generated files are committed.
- `setup-envtest` (`SETUP_ENVTEST_VERSION`) is pinned; `make envtest`
  downloads the control-plane binaries for `ENVTEST_K8S_VERSION` (1.37.x)
  into `bin/envtest`, and `KUBEBUILDER_ASSETS` is exported to `go test`
  (the envtest tests skip without it).
- Open (P7): the CI job running `make lint manifests envtest`, `git diff
  --exit-code` and the kind + local-kms e2e.
- Dependabot: keep `k8s.io/*`, `sigs.k8s.io/*` and `k8s.io/kube-openapi`
  in one group so they move together (see the conformance report).

## Validation protocol

1. Every batch: `make lint`, `make test RACE=true`, `go vet`, chart
   `helm lint` + `helm template`, and the batch's acceptance list.
2. Prove behavior with a fake clock, never with `time.Sleep`; renewal and
   jitter tests inject `clock.Clock`. xpki validates `NotBefore` against
   the real clock, so the fake clocks of the issuance tests start at the
   real time.
3. Issuance tests use the `inmemcrypto`-backed Authority of
   `internal/testauthority`, built from `testca` certificates and the
   profiles of `internal/testauthority/testdata/ca-config.yaml` (loaded through
   `authority.LoadConfig` from a temp file so the example stays valid).
4. Before a release, run `make minikube-all` (local-kms, ceremony, chart,
   operator and init-container workloads) and record the result in the
   release notes; P7 automates it.
5. Record validation limits honestly (no KMS, no cluster) in the PR.

## Rollout and migration

1. v0.9 ships the operator enabled in the chart (`operator.enabled`,
   `operator.webhook.enabled`) with the CRDs in `crds/`; the CSR signer
   keeps running with `csrSigner.approve: enforce` (the binary default is
   `off`; set `audit` first on clusters with CSR clients whose names the
   approver cannot derive).
2. Pilot one namespace with `certificate.yaml`-style objects and a
   reloading application; watch `kubeca_certificate_expiration_timestamp_seconds`
   and renewal events for at least two lifetimes.
3. Move workloads from the init container to Secret volumes or the inject
   label (file names unchanged); shorten profiles only after the last init
   container using them is gone.
4. When no CSR client remains, start with `csrSigner.enabled: false`
   (`-disable-csr-signer`) and remove the `csr-creator` bindings.

## Risks

| Risk                                                                | Mitigation                                                                                            |
| ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Applications do not reload files and fail at `notAfter`             | Migration guide requires a reloader; alert on expiration; pilot per namespace                         |
| `Secret` watch and cache selectors mis-configured → missed renewals | Fake-clock tests, informer resync as a safety net, expiration gauge alert                             |
| Webhook outage blocks Pod creation (`failurePolicy: Fail`)          | Two replicas, PDB, label scoping, `operator.webhook.failurePolicy: Ignore` alternative                |
| KMS throttling during mass renewal after a CA change                | Jitter, bounded concurrency (4 workers), retry with backoff                                            |
| Policy regex mistakes deny everything                               | `PolicyViolation` is explicit in status and events; `InvalidPolicy` on the issuer; examples carry tested defaults |
| Scope creep into in-Pod keys or trust bundles                       | Listed in ROADMAP as follow-ups; not in P7                                                            |

## Out of scope

In-Pod keys and CSI driver, namespaced `Issuer`, CA hot reload, revocation,
a `kubectl` plugin, multi-cluster trust. See "Future work" in the design
and [ROADMAP.md](ROADMAP.md).
