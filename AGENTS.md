# RULES OF CONDUCT

This module (`github.com/effective-security/kubeca`) is a Kubernetes CA
built on `github.com/effective-security/xpki`. It ships two commands and
a test tool:

- `cmd/kubeca`: one controller-runtime manager with an xpki
  `authority.Authority` whose keys live in AWS KMS, GCP KMS or a PKCS#11
  token. It runs the operator (`-enable-operator`: the `ClusterIssuer`,
  `Certificate` and Pod controllers of `kubeca.effectivesecurity/v1alpha1`
  and the Pod mutating webhook, `-enable-webhook`) and the
  `certificates.k8s.io/v1` CSR signer with its in-process approver
  (`-approve`), which serves the deprecated init-container flow.
- `cmd/kubecertinit` (deprecated since v0.9, kept for the migration): an
  init container that generates a key, submits a CSR for its Pod and waits
  for the certificate.
- `cmd/certmonitor` (test tool, image built locally only): watches a key
  pair with porto's `tlsconfig` reloader and prints the certificate when
  it starts and on every renewal; the workloads of `examples/shop` and
  the init-container dummy deployment run it. Its image is distroless, so
  the minikube test reads logs and Secrets, never `kubectl exec`.

Packages: `api/v1alpha1` (types, constants, generated deepcopy; imports
only `k8s.io/apimachinery`), `internal/operator` (manager wiring, cache
selectors, envtest CRD test) with `policy`, `index`, `metrics`, `issuer`,
`certificate`, `pod` and `webhook`, `internal/controller` (the CSR signer
and approver), `internal/certinit` (the init-container flow),
`internal/k8snames` (Pod and Service name derivation), `internal/signerr`
(xpki error classification), `internal/testauthority` (test-only in-memory
CA), `internal/logr` (xlog to go-logr adapter) and `internal/version`. The
Helm chart is `examples/kubeca`; generated CRDs and RBAC live in `config/`.
There is no database, no generated mock tree and no protobuf. What remains
of the operator plan is in [`PLAN.md`](PLAN.md) (batch P7).

Dependency direction is one way: `cmd/*` imports `internal/*`; `api/`
imports nothing from `internal/`; `internal/operator/*` imports `api/`,
`internal/k8snames`, `internal/signerr` and the sibling helpers `policy`,
`index`, `metrics`; the controllers (`issuer`, `certificate`, `pod`,
`webhook`, `internal/controller`) never import each other;
`internal/controller` imports `k8snames` and `signerr`; `internal/certinit`
imports `k8snames`; `internal/testauthority` is imported by tests only.
xpki is used through `authority`, `csr`, `cryptoprov` (+ `awskmscrypto`,
`gcpkmscrypto`, `crypto11`, `inmemcrypto`), `certutil`, `testca`, `x/print`
and `metricskey`.

## NAVIGATION

1. Read the matching concept row in
   [`Documentation/codemap.md`](Documentation/codemap.md), then that package's
   entry points, invariants and test notes. Read only the relevant sections.
2. Prefer codebase-memory-mcp for code discovery when available:
   `search_graph` for symbols, `trace_path` for callers/callees,
   `get_code_snippet` for source, `query_graph` for complex relationships,
   and `get_architecture` for an overview. Run `index_repository` if the
   repository is not indexed. Check coverage and paginate narrow queries.
3. Read the owning source and its tests before expanding scope. Fall back to
   `rg` for literals, documentation/configuration, graph coverage gaps, or a
   concept absent from the map; scope searches to the owning package first.
   Add any missing ownership or invariant to the codemap in the same change.
4. Read [`FINDINGS.md`](FINDINGS.md) before changing surprising behavior.
   [`ROADMAP.md`](ROADMAP.md) owns active planned work; [`PLAN.md`](PLAN.md)
   owns what remains of the operator plan.
5. For the xpki contract (what a profile allows, what a CSR may carry, how
   validity is computed) read
   [`Documentation/xpki-1.0-conformance.md`](Documentation/xpki-1.0-conformance.md)
   and the xpki release notes it cites before touching signing code. The
   operator puts the names in the CSR and never sets `SignRequest.SAN`, so
   the profile regexes and `allowed_fields` stay the CA-side gate.

## CODING GUIDELINES

### Style

- Target Go 1.27 (`go.mod`). Use the standard library where it now covers a
  helper: `slices.Contains`, `cmp.Or`, `maps.Copy`, `strings.SplitSeq`,
  `min`/`max`, range-over-int, `math/rand/v2`, `crypto/rand`. Do not add
  calls to functions marked `Deprecated` in the stdlib, in
  `github.com/effective-security/*`, in `k8s.io/*` or in
  `sigs.k8s.io/controller-runtime`; `golangci-lint run` (staticcheck SA1019)
  must stay clean. `mgr.GetEventRecorderFor` is the one accepted exception
  and carries a `nolint:staticcheck` comment.
- Do not use long one-liners for map or struct population; split
  key-value pairs on new lines for readability.
- Do not use many hardcoded strings or integers; define `const` at the
  top of the file or in the package. Kubernetes label, annotation,
  condition and reason names of the operator live in
  `api/v1alpha1/constants.go` and nowhere else.
- Memoize into variables; do not call functions with the same parameters
  more than once.
- Use `any`, not `interface{}` (`make fmt` rewrites it).

### Kubernetes controllers

- Reconcilers are idempotent and side-effect free on the object they read:
  patch status through `Status().Patch` with `client.MergeFrom`, never
  `Update` the whole object, and return an error only for transient
  failures (API server, KMS). A permanent failure (policy, bad spec, a
  request xpki rejects on its content, `internal/signerr`) is recorded on
  the object (condition, event) and returns `ctrl.Result{}` without an
  error, otherwise controller-runtime retries it forever. The watch of
  the reconciled kind must not pass status-only updates (the Certificate
  controller's `CertificateChanged` predicate): a status that changes on
  every failure (`failedAttempts`) would otherwise re-enqueue the object
  at once, bypassing both "no retry" and the error backoff.
- Do not trust a field of an object for authorization because the
  controller would have written it that way: owner references,
  annotations and names are written by whoever creates the object. Bind
  the output to the trusted source (the Pod's own Secret) and, where it
  matters, restrict the writers at admission (the chart's
  `ValidatingAdmissionPolicy`, tested under envtest).
- Never log a private key, a Secret's data or a bearer token. Logging a
  certificate's text is fine at `DEBUG`; keep `INFO` and above to one line
  per issuance with `serial`, `issuer`, `profile` and the object key.
- RBAC: every API access has a `+kubebuilder:rbac` marker in the
  reconciler; `make manifests` aggregates them into
  `config/rbac/role.yaml`. The chart roles
  (`examples/kubeca/templates/role-*.yaml`) are hand-written and must be
  updated in the same change; review them against `config/rbac/role.yaml`.
- Informer caches are restricted in `operator.CacheOptions` (Secrets and
  ConfigMaps to `managed=true`, Pods to `inject=true`, `managedFields`
  stripped). A controller that needs an object outside its selector reads
  it with `mgr.GetAPIReader()` (the Certificate controller's conflict
  check, the approver's Pod list), never by widening the cache.
- Constants for the group, labels, annotations, conditions and reasons
  exist once in `api/v1alpha1/constants.go`; events use the condition
  reasons.

### Logging

- Use the repo's structured `xlog` style with package-level loggers and
  `logger.ContextKV` when a context is available.
- Use snake_case log keys. Keep the keys already in use: `reason`, `status`,
  `err`, `ns`, `pod`, `signer`, `issuer`, `profile`, `file`, `name`,
  `serial`, `not_after`, `trigger`.
- Keep log keys stable inside a package. Do not switch between keys such as
  `reason` and `message` for the same concept, and keep a key's value type
  stable.
- Avoid per-object `INFO` logs in loops and in retries; use `DEBUG` for
  repetitive trace details (`needsIssuance` decisions, requeue times).

### Errors

- Use `github.com/cockroachdb/errors` for error creation and wrapping, the
  package xpki v1.0 returns. Every package was migrated in v0.9;
  `github.com/pkg/errors` must not be imported again (it stays in `go.mod`
  only as an indirect dependency).
- Wrap external errors (filesystem, YAML/JSON, Kubernetes API, KMS) using
  either:
  - `errors.WithMessage(err, "unable to read file")` for static context.
  - `errors.WithMessagef(err, "failed to resolve file %s", path)` when
    context includes dynamic values.
- Errors originated from internal sentinel types must also be wrapped so
  the stack is preserved. For `var ErrNotFound = errors.New("not found")`
  do not simply `return ErrNotFound`.
- Compare errors with `errors.Is` / `errors.As`, never `==`, a type
  assertion or a string match: Kubernetes errors go through
  `k8s.io/apimachinery/pkg/api/errors` (`apierrors.IsNotFound`),
  controller-runtime's `*controllerutil.AlreadyOwnedError` through
  `errors.As`. The one accepted string match is `internal/signerr`, which
  classifies xpki's untyped `Sign` errors and documents every substring.
- Never ignore errors from serialization, filesystem, or network calls in
  library paths that already return `error`. Helpers that intentionally
  swallow errors must keep that behavior documented in
  `Documentation/codemap.md`.
- Keep error strings accurate after refactors. Do not leave stale package
  or function names in runtime errors.
- Library code does not panic on bad input or bad configuration; it
  returns an error. The only intentional panics are `init()`-time table
  construction and `Request.requestName` when `crypto/rand` fails.
- Every outgoing HTTP call takes a `context.Context` and a client with a
  timeout; Kubernetes calls take the reconcile or command context, not
  `context.Background()`.
- Credentials: private keys and KMS credentials are never logged; files
  holding keys are written with mode `0600` (the webhook serving key; the
  init container's `0644` is KUBECA-003 and needs a decision before it
  changes); random values come from `crypto/rand`.

### Tests

- Build tests using `assert` and `require` from
  `github.com/stretchr/testify`; suites use `testify/suite`.
- Assert exact behavior, including key absence versus empty values and
  the real `err` from the call being tested.
- Prefer table tests for conversion and formatting helpers.
- Use `package foo_test` for black-box tests and `package foo` only when a
  test needs unexported seams (`internal/operator/certificate/renewal_test.go`
  for `needsIssuance`).
- Controller tests use `sigs.k8s.io/controller-runtime/pkg/client/fake`
  (`WithStatusSubresource`, `WithIndex` for the indexes of
  `internal/operator/index` and the Pod `spec.serviceAccountName` field,
  `WithInterceptorFuncs` for API failures), `record.NewFakeRecorder` for
  events, `k8s.io/utils/clock/testing` for time and
  `internal/testauthority` for signing. The fake clocks of issuance tests
  start at the real time: xpki validates `NotBefore` against `time.Now()`,
  and building an Authority verifies the CA chain against it too, so derive
  a test CA's validity from `time.Now()`, never from a fixed date.
  The init container's clients are narrow interfaces (`certinit.MinPods`,
  `MinServices`, `MinCertificates`) mocked with hand-written `testify/mock`
  types. There is no gomock tree and no `make generate` for mocks.
- `internal/operator/envtest_test.go` (CRDs and the chart's admission
  policy, with users from `envtest.Environment.AddUser`) and
  `manager_test.go` (the operator manager with `testauthority`: watches,
  predicates, retries a fake client cannot show) need the envtest
  binaries (`make envtest`, exported `KUBEBUILDER_ASSETS`) and skip
  without them; no other test needs a cluster, a KMS or Docker. A
  behaviour that depends on watch events (what enqueues a reconcile)
  needs a manager test; a single `Reconcile` call cannot show a loop.
- Write files under `t.TempDir()`, never under a fixed `/tmp` path.
- Cover shared state with a test that actually races, and run
  `make test RACE=true` before proposing a change to shared state
  (authority registry use, caches, the logr sink, the webhook serving
  certificate, concurrent reconciles).
- Add `t.Parallel()` only for tests with independent state; tests that set
  the global xlog formatter (`internal/logr`) stay serial.
- Avoid `time.Sleep`; use `require.Eventually` where appropriate.
- Validate chart changes with
  `helm lint examples/kubeca -f examples/kubeca/local.yaml` and
  `helm template kubeca examples/kubeca -f examples/kubeca/local.yaml
  --api-versions admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy`
  (without the flag, `helm template` skips the admission policy).

### Tools

- `make tools` : install govulncheck, cov-report, hsm-tool, xpki-tool,
  golangci-lint (`GOLANGCI_LINT_VERSION`), controller-gen
  (`CONTROLLER_GEN_VERSION`) and setup-envtest (`SETUP_ENVTEST_VERSION`)
- `make version` : print the version string `make build` links in
- `make build` : build `bin/kubeca` and `bin/kubecertinit` with the version
  in `LDFLAGS` (`-version` prints it)
- `make fmt` : gofmt with the `interface{} -> any` rewrite
- `make generate` : `go generate` (controller-gen deepcopy of `api/`) and fmt
- `make manifests` : CRDs, aggregated RBAC and webhook manifests into
  `config/`, CRDs copied into `examples/kubeca/crds`
- `make envtest` : download the envtest control-plane binaries
  (`ENVTEST_K8S_VERSION`) into `bin/envtest`
- `make test` : unit tests (`RACE=true` adds the race detector; the envtest
  test runs when the binaries are installed)
- `make testshort` : tests with `-test.short`
- `make lint` : fmt, go vet, govulncheck, golangci-lint
- `make covtest` : coverage run; `make covtest coverage` opens the HTML report
- `make change_log` : write `change_log.txt` (copied into the images)
- `make docker` : build both images from `Dockerfile.kubeca` and
  `Dockerfile.kubecertinit` (needs `make build change_log` first)
- `make build_certmonitor` : build `bin/certmonitor`; `make minikube-images`
  builds it and loads `Dockerfile.certmonitor` as
  `effectivesecurity/certmonitor:main`
- `make all` : clean, tools, generate, build, test, change_log
- `make start-local-kms` / `stop-local-kms` : the two local-kms emulators of
  `docker-compose.yml`
- `make kubeca-ceremony-local` : root and G1 certificates into `.tmp/`
  (`Documentation/key-ceremony.md`)
- `make minikube-images` / `minikube-deploy` / `minikube-test` /
  `minikube-clean` : the local end-to-end test (README, "Local test with
  minikube"); `make minikube-all` runs everything

CI (`.github/workflows/build.yml`) runs `make vars tools folders generate
manifests envtest version change_log`, fails when `api/`, `config/` or
`examples/kubeca/crds` differ from the generated output (`git diff
--exit-code`), then `make fmt-check vet lint` and `make build covtest`, on
every pull request and on pushes to `main`; a pull request that changes
only Markdown, images or `Documentation/` is skipped. Pushes to `main`
build and push the two images to Docker Hub (`effectivesecurity/kubeca`,
`effectivesecurity/kubecertinit`) and tag the commit
`v<.VERSION>.<commit count>` when `.VERSION` changed. CI does not run the
race detector; run `make test RACE=true` locally.

### Documentation

- Every package, including commands, has a handwritten `doc.go` with a
  package/command comment and, where the package has a non-obvious entry
  point, a short usage example.
- Document all exported types, functions, interfaces, and interface
  methods. Say what a symbol is _for_, not just what it is named.
- Keep samples in `doc.go`, the root `README.md`, `examples/` and
  `Documentation/` accurate against the current flags, API, CRDs and
  chart. A wrong sample is worse than no sample; render a changed chart
  sample with `helm template`, apply a changed manifest to a cluster (or
  at least `kubectl apply --dry-run=server` against the CRDs) and compile a
  changed Go sample before committing it.
- When you add a package, add it to the package table in the root
  `README.md`, add `doc.go`, and add a section plus concept-index rows in
  `Documentation/codemap.md`. A new API field needs the kubebuilder
  markers, `make generate manifests`, the API document and the examples
  in the same change.
- When you find a defect you are not fixing in the same change, add it to
  `FINDINGS.md` with the next free ID and reference the ID from a code
  comment. Larger API or contract changes go to `ROADMAP.md`.

#### Track bugs and issues status

- `FINDINGS.md`, `PLAN.md` and `ROADMAP.md` hold open work only. In the same
  change as each verified fix, remove the finding from `FINDINGS.md` and its
  rows from `PLAN.md`, and summarize it in the release notes of the next
  version, `Documentation/RELEASE_NOTES_<version>.md` (the fix, the new
  behavior, and what deployments must change). Record the actual validation
  in the commit or PR. Never reuse finding IDs.
- Record validation limits honestly: if a change was not run against a
  cluster or a KMS, say so.

#### Keep `Documentation/codemap.md` current

Update the codemap in the **same change** when you add functionality or
make a major change, including:

- New, removed, or renamed package, subpackage, or file that owns a
  concept.
- New, moved, or renamed exported entry-point type, func, or interface.
- Changed invariants: panic vs error, process-global state (crypto provider
  registry, xlog formatter, controller-runtime logger, scheme, Prometheus
  registry), locking, config file format, flags, signer-name format, Secret
  keys, labels, annotations, condition reasons, RBAC rules, cache selectors,
  goroutine/callback rules, or internal imports between packages.
- Changed test layout or fixture conventions.

The map must stay the navigation index: concept → file → entry points →
invariants. If you had to grep to find something that belongs there, add
the row.

## REPOSITORY MAP

Start here instead of grepping the tree.

- **[`Documentation/codemap.md`](Documentation/codemap.md)** — concept
  index, per-package files and entry points, invariants, chart layout,
  build and CI.
- **[`README.md`](README.md)** — overview, install, the operator
  (`ClusterIssuer`, `Certificate`, Pod flow), configuration, operations,
  the deprecated init-container flow and the migration.
- **[`Documentation/design/`](Documentation/design/README.md)** — the
  operator design and API, and the deprecated init-container design.
- **[`Documentation/xpki-1.0-conformance.md`](Documentation/xpki-1.0-conformance.md)**
  — what xpki v1.0 changed for this module and how each item was handled.
- **`Documentation/RELEASE_NOTES_<version>.md`** — what each version
  changed and what deployments must do.
- **[`examples/`](examples/README.md)** — chart, operator manifests, the
  deprecated init-container manifests.
- **[`FINDINGS.md`](FINDINGS.md)** — open defects, referenced by ID from
  code comments. Read it before "fixing" surprising behavior: it may
  already be recorded, with the compatibility decision still open.
- **[`PLAN.md`](PLAN.md)** — what remains of the operator plan.
- **[`ROADMAP.md`](ROADMAP.md)** — larger planned work.
- Package `doc.go` in each package.

## IMPORTANT

- Do not commit or ask to commit any changes unless you have explicit
  instructions to do so.
- Review your changes before declaring the current task as DONE.
