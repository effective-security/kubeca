# KubeCA Operator: execution plan

Plan for the work described in
[`Documentation/design/operator.md`](Documentation/design/operator.md) and
[`operator-api.md`](Documentation/design/operator-api.md). It holds open
work only: when a batch ships, remove its rows, record the validation in
the commit or PR, and summarize the change in
`Documentation/RELEASE_NOTES_<version>.md`. Decisions move into the design
documents when taken. Defects found on the way go to
[FINDINGS.md](FINDINGS.md) with the next free ID.

## Decisions needed before P1

| ID  | Question                                             | Recommended                                                                                                                                                    | Blocks |
| --- | ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| D-1 | API group                                            | `kubeca.effectivesecurity`                                                                                                                                     | P1     |
| D-2 | Key generated in the operator, stored in a Secret    | Yes; in-Pod keys are future work                                                                                                                               | P1     |
| D-3 | Same binary and manager (`-enable-operator`)         | Yes                                                                                                                                                            | P4     |
| D-4 | Pod flow: label-driven controller, then webhook      | Yes (P5 then P6)                                                                                                                                               | P5     |
| D-5 | Defaults: 24 h / renew at 8 h / ECDSA P-256 / rotate | Yes                                                                                                                                                            | P1     |
| D-6 | Webhook `failurePolicy: Fail`, self-issued cert      | Yes, with 2 replicas and a PodDisruptionBudget                                                                                                                 | P6     |
| D-7 | KUBECA-001: CSR approval                             | Decided (FINDINGS): automatic in-controller approver, option (a); ships opt-in (`-approve=off`) per ROADMAP, default `enforce` at the operator's first release | P4     |
| D-8 | `ClusterIssuer` only                                 | Yes                                                                                                                                                            | P1     |
| D-9 | SPIFFE trust domain on the ClusterIssuer             | Yes                                                                                                                                                            | P2     |

The recommendations are the defaults the examples and the API document
already use; a different answer changes those files first.

## Batches

Each batch is one reviewable change with one owner, its own tests and a
documentation update (README, codemap, examples) in the same change. Sizes:
S (a day), M (a few days), L (a week or more) for one engineer.

| Batch | Scope                                       | Deliverables                                                                                                                                                                                                                                                                                                                                   | Tests and acceptance                                                                                                                                                                                                                                                                                                                                                          | Depends on | Size | Risk   |
| ----- | ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ---- | ------ |
| P0    | Foundations (this change) and tooling       | Docs (done), build fix (done); `Makefile`: `CONTROLLER_GEN_VERSION`, `ENVTEST_K8S_VERSION`, targets `generate` (deepcopy), `manifests` (CRDs, RBAC into `config/`), `envtest` (setup-envtest), `.golangci.yml`; CI runs `make lint manifests` and `git diff --exit-code`                                                                       | `make lint` clean; CI green with the new targets on an empty `api/`                                                                                                                                                                                                                                                                                                           | decisions  | S    | low    |
| P1    | API types and CRDs                          | `api/v1alpha1/{groupversion_info,certificate_types,clusterissuer_types,constants}.go` with markers, `zz_generated.deepcopy.go`; `config/crd/bases/*.yaml`; `examples/kubeca/crds/`; printer columns; CEL rules; defaults                                                                                                                       | `envtest`: create/validate both kinds, CEL rejections (no names, `renewBefore ≥ duration`, bad sizes), status subresource; `kubectl explain` text reviewed                                                                                                                                                                                                                    | P0         | M    | low    |
| P2    | Policy and ClusterIssuer controller         | `internal/operator/policy` (pure evaluation, regex substitution, duration bounds); `internal/operator/issuer` reconciler: resolve `issuerLabel` in the `Authority`, status (`Ready`, CA PEMs, SKID, `caNotAfter`, profiles), `CAExpiring`; enqueue Certificates of an issuer on status change                                                  | Table tests for policy (namespace selector, each regex type, substitution, `maxDuration`); reconcile tests with the fake client and an `inmemcrypto` Authority from `testca`; `CAExpiring` with a fake clock                                                                                                                                                                  | P1         | M    | low    |
| P3    | Certificate controller                      | `internal/operator/certificate`: `needsIssuance`, key generation, SAN assembly + `csr.ParseSAN`, validity computation, `Issuer.Sign`, Secret write (`CreateOrUpdate`, owner ref, conflict detection via `APIReader`), status, events, metrics, jittered `RequeueAfter`, transient/permanent error split, `Owns(Secret)`                        | Table tests for `needsIssuance` (every trigger) and validity (`NotAfter − NotBefore ≤ expiry`, backdate); fake-clock renewal test: issue at T, no-op at T+1 h, renewal at T+16 h ± jitter, new key, `revision` 2; Secret deleted → re-issue; conflict → `SecretConflict`; permanent error → no requeue; `make test RACE=true` with concurrent reconciles of different objects | P2         | L    | medium |
| P4    | Manager integration, chart, migration guide | `cmd/kubeca`: `-enable-operator`, `-disable-csr-signer`, the approver flag default (D-7), `-cluster-domain`; cache `ByObject` selectors; leader election on by default in operator mode; chart: CRDs, operator RBAC (CRDs, secrets, events, leases, services, pods), values, `replicas`; `examples/operator` validated; README and codemap     | `helm lint`/`template`; on a kind cluster with local-kms: apply `clusterissuer.yaml`, `certificate.yaml`, `deployment.yaml`; Pod starts; Secret keys present; `kubectl get certs` columns; delete the Secret → re-issued; `-disable-csr-signer` leaves CSRs pending                                                                                                           | P3         | M    | medium |
| P5    | Pod controller and shared names             | `internal/k8snames` (moved from `certinit` with no behavior change; shared with the KUBECA-001 approver); `internal/operator/pod`: label selector cache, Certificate per Pod owned by the Pod, SPIFFE URI, IP SAN once known, update on IP/Service change; `pod.yaml` (bare Pod) and `statefulset.yaml` (shared wildcard Certificate) examples | Name-derivation table tests (moved and extended); reconcile tests: Pod without IP → DNS-only cert, IP appears → `SpecChanged`; Pod deleted → Certificate gone; kind: the bare-Pod example starts with `<pod>-tls`, the StatefulSet example shares one wildcard certificate                                                                                                    | P3         | M    | low    |
| P6    | Mutating webhook                            | `internal/operator/webhook`: Pod mutator (secret-name generation, volume and mounts, annotations), serving certificate as a `Certificate` in the operator namespace, `caBundle` patch, chart `MutatingWebhookConfiguration`, PDB, 2 replicas; `deployment-injected.yaml` example                                                               | Admission unit tests (`admission.Request` → JSON patch); `envtest` with the webhook installed; kind: Deployment example starts with injected mounts, renewal updates the files                                                                                                                                                                                                | P4, P5     | M    | medium |
| P7    | Hardening and release                       | e2e job in CI (kind + local-kms, 2-minute profile with 40 s `renewBefore` proving renewal and key rotation), trust bundle ConfigMap (`spec.caBundle`), alerts and dashboards snippet, migration guide finalized, `RELEASE_NOTES`, chart version, images, FINDINGS/ROADMAP updates, decision rows removed                                       | e2e green in CI; docs reviewed against `kubectl explain`; `make lint`, `make test RACE=true`                                                                                                                                                                                                                                                                                  | P6         | M    | low    |

Sequencing: P0 → P1 → P2 → P3 → P4 is the critical path (a usable
`Certificate` → Secret → Pod flow). P5 and P6 add per-Pod identity and can
follow a first release of P4. P7 closes the release.

## File layout (target)

```text
api/v1alpha1/                 types, constants, deepcopy (generated)
config/crd/bases/             generated CRDs (source of examples/kubeca/crds)
config/rbac/role.yaml         generated from markers; compared against the chart in CI
internal/operator/policy/     pure policy evaluation
internal/operator/issuer/     ClusterIssuer controller
internal/operator/certificate/ Certificate controller (issuance.go, secret.go, renewal.go, metrics.go)
internal/operator/pod/        Pod controller
internal/operator/webhook/    Pod mutator, serving-certificate bootstrap
internal/k8snames/            Pod/Service name discovery (shared with certinit)
internal/controller/          existing CSR signer (unchanged API)
examples/kubeca/crds/, templates/operator-*.yaml, templates/webhook-*.yaml
examples/operator/            kept in sync with the API document
Documentation/design/         kept in sync with the implementation
```

Package rules: `api/` imports nothing from `internal/`; `internal/operator/*`
imports `api/`, `internal/k8snames`, xpki and controller-runtime; the
controllers do not import each other (shared helpers go to `policy` or
`k8snames`). Constants (group, labels, annotations, conditions, reasons)
exist once, in `api/v1alpha1/constants.go`.

## Tooling and CI changes

- `controller-gen` (sigs.k8s.io/controller-tools) pinned in `Makefile`;
  `make generate` runs `object` (deepcopy) and `make manifests` runs `crd`,
  `rbac` and `webhook` generators. Generated files are committed; CI
  verifies `git diff --exit-code` after regenerating.
- `setup-envtest` pinned; `make envtest` downloads the control-plane
  binaries for `ENVTEST_K8S_VERSION` (match the `k8s.io` module minor,
  1.37) into `bin/` and exports `KUBEBUILDER_ASSETS` for `go test`.
- e2e (P7): GitHub Actions job with `helm/kind-action`, a `local-kms`
  container (as xpki's `docker-compose.yml`), the chart installed from the
  checkout with a CA generated by `hsm-tool` against local-kms, and a Go
  test under `e2e/` with a build tag.
- Dependabot: keep `k8s.io/*`, `sigs.k8s.io/*` and `k8s.io/kube-openapi` in
  one group so they move together (see the conformance report).

## Validation protocol

1. Every batch: `make lint`, `make test RACE=true`, `go vet`, chart
   `helm lint` + `helm template`, and the batch's acceptance list above.
2. Prove behavior with a fake clock, never with `time.Sleep`; renewal and
   jitter tests inject `clock.Clock`.
3. Issuance tests use an `inmemcrypto`-backed Authority built from `testca`
   certificates and the profiles of `examples/operator/ca-config-24h.yaml`
   (loaded through `authority.LoadConfig` from a temp file so the example
   stays valid).
4. Before P4 is declared done, run the kind + local-kms scenario by hand
   and record the commands in the PR; P7 automates it.
5. Record validation limits honestly (no KMS, no cluster) in the PR.

## Rollout and migration

1. Ship P4 as `v0.8` with the operator opt-in (`-enable-operator=false`
   default) and the CRDs in the chart; the CSR signer behaves as today.
2. Pilot one namespace with `certificate.yaml`-style objects and a
   reloading application; watch `kubeca_certificate_expiration_timestamp_seconds`
   and renewal events for at least two lifetimes.
3. Move workloads from the init container to Secret volumes
   (file names unchanged); shorten profiles only after the last init
   container using them is gone.
4. Ship P6; enable the webhook per namespace with the inject label.
5. Set the approver to `enforce` (D-7) and remove the `csr-creator`
   bindings when the CSR API is no longer used.

## Risks

| Risk                                                                | Mitigation                                                                                            |
| ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Applications do not reload files and fail at `notAfter`             | Migration guide requires a reloader; alert on expiration; pilot per namespace                         |
| `Secret` watch and cache selectors mis-configured → missed renewals | Fake-clock tests, informer resync as a safety net, expiration gauge alert                             |
| xpki validity rejection (`NotAfter` beyond expiry)                  | Explicit `NotBefore`/`NotAfter` computed from the profile; table tests against `validityWindow` rules |
| Webhook outage blocks Pod creation (`failurePolicy: Fail`)          | Two replicas, PDB, label scoping, documented `Ignore` alternative                                     |
| KMS throttling during mass renewal after a CA change                | Jitter, bounded concurrency, retry with backoff                                                       |
| Policy regex mistakes deny everything                               | `PolicyViolation` is explicit in status and events; examples carry tested defaults                    |
| Scope creep into in-Pod keys or trust bundles                       | Listed as future work; not in P1..P7                                                                  |

## Out of scope

In-Pod keys and CSI driver, namespaced `Issuer`, CA hot reload, revocation,
a `kubectl` plugin, multi-cluster trust. See "Future work" in the design.
