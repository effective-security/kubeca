# Code map

Navigation index for agents and new contributors: concept → file → entry
points → invariants. Start here instead of grepping the tree. If you had to
grep for something that belongs in this map, add the row in the same change
(see [AGENTS.md](../AGENTS.md)).

- High level purpose, install and operations: [README.md](../README.md)
- Current and planned designs: [design/](design/README.md)
- xpki v1.0 contract and conformance: [xpki-1.0-conformance.md](xpki-1.0-conformance.md)
- Release notes: [RELEASE_NOTES_0.8.md](RELEASE_NOTES_0.8.md)
- Open defects, referenced by ID from code comments: [FINDINGS.md](../FINDINGS.md)
- Larger planned work: [ROADMAP.md](../ROADMAP.md); operator execution plan: [PLAN.md](../PLAN.md)

## Module layout

`github.com/effective-security/kubeca`, Go 1.27. Two commands, four internal
packages, one Helm chart.

| Path                   | Purpose                                                                                           |
| ---------------------- | ------------------------------------------------------------------------------------------------- |
| `cmd/kubeca/`          | CSR signing controller: flags, provider aliases, log setup, manager start                         |
| `cmd/kubecertinit/`    | Init container: flags, log setup, timeout context, `certinit.Request.Create`                      |
| `internal/controller/` | controller-runtime manager, xpki authority loading, `CertificateSigningRequest` reconciler        |
| `internal/certinit/`   | Pod/Service name discovery, key + CSR generation, CSR submission and wait, file output            |
| `internal/logr/`       | `xlog.KeyValueLogger` → `logr.LogSink` adapter used as the manager logger                         |
| `internal/version/`    | Build version: linked by `make build` (`-ldflags`), module/VCS fallback; `-version` on both commands |
| `examples/kubeca/`     | Chart: Deployment, ConfigMaps from `etc/`, ServiceAccount, cluster RBAC, leader-election Role     |
| `examples/`            | Manifests for the init-container flow (incl. the minikube dummy workload) and the planned operator |
| `etc/`                 | Key ceremony inputs: bootstrap CA profiles, CSR profiles (`dev`, `prod`), local-kms token configs  |
| `scripts/`             | Key ceremony (`gen_root.sh`, `gen_ca.sh`, `make_kubeca*.sh`) and minikube test (`minikube_*.sh`, `wait_tcp.sh`) |
| `docker-compose.yml`   | Two local-kms emulators: kms1 (root, 14599) and kms2 (issuing, 24599)                              |
| `Documentation/`       | This map, conformance report, release notes, `design/`                                            |
| `.project/`            | `gomod-project.mk` (shared make targets, version string), `config.yml` (org and project name)     |

Dependency direction (non-test): `cmd/kubeca` → `internal/controller` →
`internal/logr`; `cmd/kubecertinit` → `internal/certinit`; both commands →
`internal/version`. External: `internal/controller` uses xpki `authority`,
`csr`, `cryptoprov`, `metricskey`, `x/print`, porto `xhttp/marshal`,
`controller-runtime`, `client-go/tools/record`; `internal/certinit` uses xpki
`csr`, `certutil`, `cryptoprov/inmemcrypto`, `x/print`, `client-go`;
`cmd/kubeca` imports the xpki providers `crypto11`, `awskmscrypto`,
`gcpkmscrypto` (their `init()` registers them). Errors:
`github.com/pkg/errors` (migration to `cockroachdb/errors` in ROADMAP).

## Concept index

| Concept                                        | File(s)                                                  | Entry points                                                                                                         |
| ---------------------------------------------- | -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Controller process, flags, provider aliases    | `cmd/kubeca/main.go`                                     | `main`, `providerAliases`; flags `-ca-cfg`, `-hsm-cfg`, `-metrics-addr`, `-enable-leader-election`, `-leader-election-id`, `-debug`, `-stackdriver`, `-version` |
| Init-container process, flags                  | `cmd/kubecertinit/main.go`                               | `main`; flags `-namespace`, `-pod-name`, `-signer`, `-cert-dir`, `-san`, `-service-names`, `-query-k8s`, `-cluster-domain`, `-include-unqualified`, `-labels`, `-usages`, `-timeout`, `-kubeconfig`, `-stackdriver`, `-version` |
| Manager setup, CA and crypto loading           | `internal/controller/controller.go`                      | `CertificateSigningRequestControllerFlags`, `StartCertificateSigningRequestController`, `scheme`, `controllerName`  |
| CSR reconcile and signing                      | `internal/controller/certificatesigningrequest.go`       | `CertificateSigningRequestSigningReconciler`, `Reconcile`, `SetupWithManager`, `findIssuer`, `isCertificateRequestApproved`, `getCertApprovalCondition`, `eventReasonSigned`, `eventReasonSigningFailed` |
| Signer name ↔ issuer/profile                   | `internal/controller/certificatesigningrequest.go`, `internal/certinit/certreq.go` | `findIssuer` (`<label>/<profile>` → `Authority.GetIssuerByProfile`), `requestCertificate` (same split), `profileUsages` |
| Init request parameters, Kubernetes clients    | `internal/certinit/certinit.go`                          | `Request`, `Request.Create`, `CertClient`, `MinPods`, `MinServices`, `MinCertificates`, `NewClient`                   |
| Pod and Service name discovery                 | `internal/certinit/certinit.go`                          | `getNamesForPod`, `serviceNames`, `ipToName`, `splitList`                                                            |
| Key and CSR generation, CSR submit and wait    | `internal/certinit/certreq.go`                           | `requestCertificate`, `waitForCertificate`, `requestName`, `usages`, `pollInterval`                                  |
| Output files of the init container             | `internal/certinit/certreq.go`                           | `tls.key` (`keyFileMode` 0644, KUBECA-003), `tls.csr`, `tls.crt` under `Request.CertDir`                             |
| go-logr adapter                                | `internal/logr/logr.go`                                  | `New`, `prov`, `xlogLevel`                                                                                           |
| Build version                                  | `internal/version/current.go`, `versioninfo.go`          | `Current`, `Info`, `Info.PopulateFromBuild`, `buildVersion`, linker variable `build`                                 |
| CA configuration and profiles                  | `examples/kubeca/etc/ca-config.kubeca.yaml`              | `authority.issuers[].label` (= signer domain), `profiles.<name>` (= signer path); rendered through `tpl`             |
| KMS / HSM token configuration                  | `examples/kubeca/etc/aws-kms-us-west-2.yaml`, `aws-dev-kms-local.yaml` | `manufacturer`, `model`, `attributes` (`Region`, `Endpoint`)                                              |
| Controller deployment and config mounts        | `examples/kubeca/templates/deployment.yml`, `configmap-etc.yaml`, `configmap.yaml` | `/kubeca/etc` from the `-etc` ConfigMap, `/kubeca/certs` from the external Secret `<fullname>-certs-secret-tf`, env from `config.common` |
| Controller RBAC                                | `examples/kubeca/templates/role-csr-signer.yaml`, `role-csr-approver.yaml`, `role-leader-election.yaml`, `rolebinding.yaml`, `serviceaccount.yaml` | `kubeca:csr-signer` (get/list/watch CSRs, update/patch `status`, `sign` on `signers` `kubeca.svc/*`, events), `kubeca:csr-approver` (unused until KUBECA-001), `<fullname>-leader-election` (leases, events) |
| Workload RBAC (init container)                 | `examples/initcontainer/rbac.yaml`, README               | `kubeca:csr-creator` ClusterRole (create/get/list/watch CSRs) and the namespaced `kubeca:pod-names` Role (get/list pods and services) |
| Images                                         | `Dockerfile.kubeca`, `Dockerfile.kubecertinit`           | distroless `base-debian12:nonroot`, `/app/<binary>` + `change_log.txt`                                               |
| Build, version string, CI                      | `Makefile` (`LDFLAGS`), `.project/gomod-project.mk`, `.VERSION`, `.github/workflows/build.yml`, `settag.yml` | `make build/test/lint/covtest/version/change_log/docker`; version `v<.VERSION>.<commit count>[-dirty]` |
| Key ceremony                                   | `scripts/gen_root.sh`, `scripts/gen_ca.sh`, `etc/ca-config.bootstrap.yaml`, `etc/csr_profile/` | `make kubeca-ceremony-local`, `kubeca-root-aws`, `kubeca-g1-aws`; `Documentation/key-ceremony.md`     |
| Local end-to-end test (minikube)               | `scripts/minikube_{images,deploy,test,clean}.sh`, `examples/kubeca/minikube.yaml`, `examples/initcontainer/dummy-deployment.yaml` | `make minikube-all`; verifies CSR signing, files in the Pod, chain, JSON log format |
| Planned operator API and controllers           | `Documentation/design/operator-api.md`, `operator.md`, `PLAN.md` | `api/v1alpha1` (`Certificate`, `ClusterIssuer`), `internal/operator/*` (not yet in the tree)                 |

## Package cmd/kubeca

`main` registers the provider aliases, parses flags, prints the version
and exits with `-version`, sets the xlog formatter (JSON or Stackdriver,
with caller), sets the controller-runtime logger to a zap logger
(`UseDevMode(-debug)`), logs the version, and calls
`controller.StartCertificateSigningRequestController`. A panic is recovered
and printed; errors exit with status 1.

Invariants:

- Process-global state: the xpki provider registry (the blank-imported
  providers register `SoftHSM`, `AWSKMS`, `GCPKMS` in `init()`;
  `providerAliases` adds `PKCS11`; a registration error exits 1), the xlog
  formatter and global level (`-debug` sets `DEBUG`), and the
  controller-runtime global logger, which is the same xlog adapter as the
  manager logger so every line has the xlog JSON shape.
- Flag defaults point at `/kubeca/etc/ca-config.yaml` and
  `/kubeca/etc/aws-kms-us-west-2.json`; the chart passes both explicitly
  (`.yaml`).

## Package cmd/kubecertinit

`main` parses flags into `certinit.Request`, prints the version and exits
with `-version`, sets the formatter, logs the version, builds a client with
`certinit.NewClient(-kubeconfig, -namespace)` (empty kubeconfig means
in-cluster) and runs `Request.Create` with a context that `-timeout` bounds
(`0`, the default, never ends it). Exit status 2 on any error. Intended as
an init container; see [design/initcontainer.md](design/initcontainer.md).

## Package internal/controller

### Files

| File                            | Role                                                                                                   |
| ------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `controller.go`                 | `scheme` (certificates/v1 + core/v1), flags struct, manager construction, `cryptoprov.Load`, `authority.LoadConfig`, `authority.NewAuthority`, reconciler registration, `mgr.Start` with the signal handler |
| `certificatesigningrequest.go`  | `CertificateSigningRequestSigningReconciler` (`client.Client`, `Scheme`, `Authority`, `EventRecorder`), `Reconcile`, `findIssuer`, approval helpers, event reasons |

### Reconcile contract

For each `CertificateSigningRequest` event (cluster-scoped, `For(&capi.CertificateSigningRequest{})`,
one worker):

1. `Get` the CSR; NotFound returns without error (the object was deleted
   after the event).
2. Skip (no error) when: `DeletionTimestamp` set; `spec.signerName` empty;
   `status.certificate` already set; a `Denied` condition exists. An
   `Approved` condition is **not** required (KUBECA-001, decided: an
   automatic approver is planned, see ROADMAP).
3. `findIssuer`: split `signerName` on `/` into exactly two tokens,
   `Authority.GetIssuerByProfile(profile)`, accept only if
   `issuer.Label() == label`. Unknown signer: skip with an `INFO` log.
4. `issuer.Sign(csr.SignRequest{Request: spec.request, Profile: profile})`.
   Names and subject come from the CSR under the profile's
   `allowed_fields` and regexes; `spec.usages` is ignored (the profile sets
   usages). Any error emits a `Warning`/`SigningFailed` event with the
   error message and is returned, so controller-runtime retries with
   backoff for ever (KUBECA-013).
5. Patch `status.certificate` (`client.MergeFrom`) with the leaf PEM
   followed by `issuer.PEM()` (the issuing certificate plus the `ca_bundle`
   intermediates, not the root), trimmed. Emit the `Normal`/`Signed` event.
   Record `metricskey.PerfCASignRequest` (`perf_ca_signreq{issuer,profile}`).
   Log one `NOTICE` line (`status=signed`, `name`, `issuer`, `profile`,
   `serial`, `not_after`, `elapsed`) and the certificate text at `DEBUG`.

Invariants:

- Metrics are served by the manager at `-metrics-addr` (default `:9090`).
- Leader election uses the controller-runtime default resource lock
  (Leases) under `-leader-election-id`; the chart binds a namespaced Role
  on `leases` to the controller.
- Both the manager logger and the global controller-runtime logger are
  `logr.New(logger)` (xlog), so metrics-server and leader-election lines
  share the format (`src=controller-runtime.metrics`).
- RBAC needed: `certificatesigningrequests` get/list/watch,
  `certificatesigningrequests/status` update/patch, `signers` `sign` for
  the issuer labels (`kubeca.svc/*`), `events` create/patch, and `leases`
  when leader election is on.

Tests: none (ROADMAP, "Controller tests").

## Package internal/certinit

### Files

| File          | Role                                                                                                                        |
| ------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `certinit.go` | `Request` (flag mirror plus `san`, `labelsMap`), `CertClient` and the three `Min*` interfaces, `NewClient`, `Request.Create`, `splitList`, `serviceNames`, `getNamesForPod`, `ipToName` |
| `certreq.go`  | `usages` (profile → `capi.KeyUsage` list), `profileUsages`, `requestCertificate` (key, CSR, files, submit), `waitForCertificate`, `requestName`, file and poll constants |
| `doc.go`      | Package comment and usage                                                                                                   |

### Flow (`Request.Create`)

1. Require `Namespace`, `PodName`, `SignerName`.
2. Parse `-labels` (`k=v,...`, items and keys/values trimmed; entries
   without `=`, with an empty key or with `=` in the value are dropped).
3. With `-query-k8s`: `Pods.Get(ctx, PodName)` then `getNamesForPod`:
   `<ip-with-dashes>.<ns>.pod.<domain>`; `<hostname>.<subdomain>.<ns>.svc.<domain>`
   when both are set (plus the unqualified `.svc` form with
   `-include-unqualified`); for every Service whose selector matches the
   Pod labels: `<svc>.<ns>.svc.<domain>` (plus unqualified), the
   `ExternalName` or the `ClusterIP` (a headless `None` and an empty
   ClusterIP are skipped), and every `ExternalIP`. Services without a
   selector are ignored; Endpoints are not consulted.
4. For each `-service-names` entry: `<name>.<ns>.svc.<domain>` (plus
   unqualified).
5. Append the comma-separated `-san` values (DNS, IP, URI with `://`, or
   email; classified, validated and deduplicated by xpki).
6. `requestCertificate`: signer must be `<label>/<profile>`; usages from
   `Request.Usages` when set, else the built-in table (`peer`, `server`,
   `client`; any other profile needs `-usages`); ECDSA P-256 key through
   `csr.NewProvider(inmemcrypto)`; write `tls.key` (`keyFileMode` 0644,
   KUBECA-003) and `tls.csr`; build the CSR object (`spec.request`,
   `spec.usages`, `spec.signerName`, `metadata.labels`); name
   `<pod>-<ns>-<5 chars of [0-9a-z]>` from `crypto/rand` (panics if the
   reader fails); `Get` then `Create` when missing.
7. `waitForCertificate`: `Get` every `pollInterval` (5 s) until
   `status.certificate` is set; a `Denied` or `Failed` condition, a
   deleted CSR (`apierrors.IsNotFound`) or a done context (`-timeout`) is an
   error; other `Get` errors are logged and retried. Then write `tls.crt`.

Invariants:

- Only `Pods.Get`, `Services.List` and `CertificateSigningRequests.Get/Create`
  are used; `NewClient` wires them from `kubernetes.NewForConfig`. Every
  call takes the caller's context.
- xpki v1.0 rejects an invalid or empty name before the CSR is created, so
  a malformed `-san` fails fast; duplicates are dropped
  ([xpki-1.0-conformance.md](xpki-1.0-conformance.md)).
- Files are written with `os.WriteFile`; an existing `CertDir` is required.
- Without `-timeout` the wait never ends (KUBECA-006).

Tests: `certinit_test.go` (black box) mocks the three interfaces with
`testify/mock`. `TestCreate` captures the created CSR and asserts the exact
SAN lists parsed from it (query-k8s names, a headless Service, service-names,
`-san`, duplicates dropped), the usages, trimmed labels, no `spec.extra`, the
name pattern and the output files; `TestCreateUsages`, `TestCreateDeniedCSR`,
`TestCreateFailedCSR`, `TestCreateDeletedCSR` and `TestCreateContextDone`
cover the other exits. `issuingCertificates` builds the NotFound → Create →
issued mock sequence. Files go under `t.TempDir()`.

## Package internal/logr

`New(logger xlog.KeyValueLogger) logr.Logger` wraps an immutable `prov`
sink (`logger`, `name`). `Info` logs at the level `xlogLevel` maps from the
logr verbosity (0 → `INFO`, 1 → `TRACE`, 2+ → `DEBUG`) with `msg`; `Error`
at `ERROR` with `msg` and `err` (omitted for a nil error); `WithValues`
derives a new xlog logger; `WithName` appends a dot-separated element to
`name`, logged as the first entry under `src`. `Enabled` is always true:
xlog's global level filters at write time. The test sets the global xlog
formatter and must not run in parallel with other formatter users.

## Package internal/version

`current.go`: the linker variable `build` (`-X
github.com/effective-security/kubeca/internal/version.build=...`, set by
`make build` from `GIT_VERSION`), `buildVersion` (linker value, else the
main module version from `debug.ReadBuildInfo`, else
`devel-<revision>[-dirty]`, else `devel`), `Current`. `versioninfo.go`:
`Info{Major, Minor, Commit, Build, Runtime}`; `PopulateFromBuild` parses
`[v]<major>.<minor>.<commit>[-...]` and leaves zeros for anything else (it
never panics); `GreaterOrEqual` compares major/minor; `Float` is
`major.minor` × 1e6 plus the commit, for ordering only (no callers).
Tests: `current_test.go` (`buildVersion` table, `Current`),
`versioninfo_test.go`.

## Helm chart `examples/kubeca`

| File                             | Role                                                                                                                  |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `Chart.yaml`                     | `kubeca` 0.1.1                                                                                                        |
| `values.yaml`                    | image, `imagePullSecrets`, `command` (flags), `replicaCount.default`, `nodeSelector/tolerations/affinity.default`, `serviceAccount`, `config.common` (env), `issuers.kubeca.{cert,key,ca_bundle,root_bundle}` paths under `/kubeca/certs`; `autoscaling` is unused (KUBECA-012) |
| `local.yaml`, `aws-dev.yaml`, `minikube.yaml` | Value overlays: local-kms endpoint with dummy AWS credentials; IRSA role annotations; the minikube test     |
| `etc/ca-config.kubeca.yaml`      | xpki CA config: issuer `kubeca.svc` (files from the certs Secret, no AIA) and profiles `peer`, `server`, `client` (8760h, backdate 30m, `allowed_fields`) |
| `etc/aws-kms-us-west-2.yaml`, `etc/aws-dev-kms-local.yaml` | `AWSKMS` token configs                                                                                     |
| `templates/configmap-etc.yaml`   | Every `etc/*` file, rendered with `tpl`, as `<name with dots and underscores replaced by dashes>` keys                 |
| `templates/configmap.yaml`       | One ConfigMap per `config.<name>` map (env for `common`)                                                               |
| `templates/deployment.yml`       | `replicaCount.default` replicas, `command` from values, mounts `/kubeca/etc` (ConfigMap) and `/kubeca/certs` (Secret `<fullname>-certs-secret-tf`, external), optional pull secrets, node selector, tolerations, affinity |
| `templates/serviceaccount.yaml`  | ServiceAccount with annotations (IRSA)                                                                                |
| `templates/role-csr-signer.yaml`, `role-csr-approver.yaml`, `rolebinding.yaml` | ClusterRoles and ClusterRoleBindings (no `namespace`)                                   |
| `templates/role-leader-election.yaml` | Role and RoleBinding on `leases` and events in the release namespace                                             |

Invariants: the issuer label in `ca-config` must equal the domain part of
the `signers` `resourceNames` in the RBAC (`kubeca.svc/*`) and of the
`-signer` workloads use. The certs Secret keys must match
`values.issuers.kubeca.*` paths. Render with
`helm template kubeca examples/kubeca -f examples/kubeca/local.yaml`.

## Build, images and CI

- `make build` produces `bin/kubeca` and `bin/kubecertinit` with
  `LDFLAGS` setting the version; `make version` prints the version string;
  `make change_log` writes `change_log.txt`; `make docker` builds
  `effectivesecurity/kubeca:main` and `effectivesecurity/kubecertinit:main`
  from distroless `nonroot` images that copy the binary and the change log
  into `/app`.
- Version string: `v<.VERSION>.<git rev-list --count>[-<hostname>]` from
  `.project/gomod-project.mk` (`GIT_VERSION`); `.VERSION` is `v0.8`.
- CI (`.github/workflows/build.yml`): on PRs and pushes to `main`, skip
  when only docs changed, then `make vars tools folders generate version
  change_log` and `make build covtest`; on `main` pushes, build and push
  both images (tags: branch, sha, semver) and create the `v<.VERSION>.<n>`
  tag when `.VERSION` changed. `settag.yml` creates a tag on demand.
  `MIN_TESTCOV=80` is declared but not enforced (ROADMAP). Dependabot
  groups `aws`, `es`, `go`, `google`, `k8s.io` (`*k8s.io/*`), actions and
  docker weekly.

## Tests

| Package              | Tests                                                                                                              | Fixtures                                     |
| -------------------- | ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------- |
| `internal/certinit`  | `TestCreateFail`, `TestCreate`, `TestCreateUsages`, `TestCreateDeniedCSR`, `TestCreateFailedCSR`, `TestCreateDeletedCSR`, `TestCreateContextDone` | testify mocks, `t.TempDir()`, in-memory keys |
| `internal/logr`      | `TestLogr`                                                                                                         | global xlog formatter (serial)               |
| `internal/version`   | `TestBuildVersion`, `TestCurrent`, `TestInfo_ParseBuild`, `TestInfo_GreaterOrEqual`                                | none                                         |
| `internal/controller` | none                                                                                                              | planned: fake client + `inmemcrypto` authority |

`make test RACE=true` passes. No unit test needs a cluster, a KMS or Docker.

## Key ceremony and local test

- `etc/ca-config.bootstrap.yaml`: profiles `ROOT` and `L1_CA`;
  `etc/csr_profile/<dev|prod>/kubeca_{root,ca_g1}.yaml`: subjects and keys;
  `etc/aws-dev-kms-local{1,2}.yaml`: emulator token configs (model
  `effective-security-test`, which the runtime config must repeat because
  the key URI is resolved by manufacturer and model).
- `scripts/gen_root.sh` (self-signed root on the root KMS) and
  `scripts/gen_ca.sh` (key and CSR on the issuing KMS, signature on the root
  KMS, chain validation); wrappers `make_kubeca.sh`, `make_kubeca_g1.sh`;
  make targets `start-local-kms`, `kubeca-ceremony-local`,
  `kubeca-root-aws`, `kubeca-g1-aws`. Outputs in `.tmp/` (ignored).
- `scripts/minikube_images.sh` (docker build + `minikube image load`),
  `minikube_deploy.sh` (namespace, certs Secret, `helm upgrade --install`
  with `examples/kubeca/minikube.yaml`, restart and settle check),
  `minikube_test.sh` (dummy workload, CSR, files, chain, log-format check),
  `minikube_clean.sh`; `make minikube-all`. The Pod reaches kms2 through
  `host.minikube.internal`.
- See [key-ceremony.md](key-ceremony.md) and the README.
