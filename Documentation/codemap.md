# Code map

Navigation index for agents and new contributors: concept → file → entry
points → invariants. Start here instead of grepping the tree. If you had to
grep for something that belongs in this map, add the row in the same change
(see [AGENTS.md](../AGENTS.md)).

- High level purpose, install and operations: [README.md](../README.md)
- Designs: [design/](design/README.md) (operator, API, deprecated init container)
- xpki v1.0 contract and conformance: [xpki-1.0-conformance.md](xpki-1.0-conformance.md)
- Release notes: [RELEASE_NOTES_0.9.md](RELEASE_NOTES_0.9.md), [RELEASE_NOTES_0.8.md](RELEASE_NOTES_0.8.md)
- Open defects, referenced by ID from code comments: [FINDINGS.md](../FINDINGS.md)
- Larger planned work: [ROADMAP.md](../ROADMAP.md); what remains of the operator plan: [PLAN.md](../PLAN.md)

## Module layout

`github.com/effective-security/kubeca`, Go 1.27. Two commands and a test
tool, one API package, eleven internal packages, one Helm chart.

| Path                              | Purpose                                                                                                       |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `cmd/kubeca/`                     | The controller process: flags, provider aliases, log setup, manager construction, CSR signer and operator registration |
| `cmd/kubecertinit/`               | Init container (deprecated): flags, log setup, timeout context, `certinit.Request.Create`                     |
| `cmd/certmonitor/`                | Test tool: prints a key pair's certificate at start and on every reload (porto `tlsconfig` reloader)         |
| `api/v1alpha1/`                   | `Certificate` and `ClusterIssuer` types, constants, generated deepcopy; imports only `k8s.io/apimachinery`    |
| `config/crd/bases/`, `config/rbac/` | Generated CRDs (copied to the chart) and the aggregated RBAC of the `+kubebuilder:rbac` markers (reference for the chart roles) |
| `internal/operator/`              | Manager wiring (`Setup`, scheme, cache selectors, webhook server) and the envtest CRD test                     |
| `internal/operator/issuer/`       | ClusterIssuer controller                                                                                      |
| `internal/operator/certificate/`  | Certificate controller                                                                                        |
| `internal/operator/pod/`          | Pod controller                                                                                                |
| `internal/operator/webhook/`      | Pod mutating webhook and its serving certificate                                                              |
| `internal/operator/policy/`       | Pure policy evaluation                                                                                        |
| `internal/operator/index/`        | Field indexes on Certificates                                                                                 |
| `internal/operator/metrics/`      | Prometheus metrics of the operator                                                                            |
| `internal/controller/`            | CSR signer with the in-process approver (KUBECA-001) and the `Failed` condition (KUBECA-013)                  |
| `internal/certinit/`              | The init-container flow (deprecated since v0.9): key + CSR generation, CSR submission and watch, file output  |
| `internal/k8snames/`              | Pod and Service name derivation, shared by `certinit`, the approver and the Pod controller                    |
| `internal/signerr/`               | Permanent vs transient classification of xpki `Issuer.Sign` errors                                             |
| `internal/testauthority/`         | Test-only in-memory Authority (testca root and issuing CA, example profiles)                                  |
| `internal/logr/`                  | `xlog.KeyValueLogger` → `logr.LogSink` adapter used as the manager logger                                     |
| `internal/version/`               | Build version: linked by `make build` (`-ldflags`), module/VCS fallback; `-version` on both commands          |
| `examples/kubeca/`                | Chart, the whole CA side: CRDs, Deployment, ConfigMaps from `etc/`, ServiceAccount, cluster RBAC, leader-election Role, webhook Service and configuration, `ClusterIssuer`s; `README.md` has the install sequence |
| `examples/shop/`                  | Application-side demo of the operator in the `shop` namespace (Certificates, inject label, StatefulSet) and `e2e/` for the minikube test |
| `examples/initcontainer/`         | Deprecated init-container manifests and the minikube dummy workload; every `examples/` directory has a `README.md` with its files and deploy order |
| `etc/`                            | Key ceremony inputs: bootstrap CA profiles, CSR profiles (`dev`, `prod`), local-kms token configs             |
| `scripts/`                        | Key ceremony (`gen_root.sh`, `gen_ca.sh`, `make_kubeca*.sh`) and minikube test (`minikube_*.sh`, `wait_tcp.sh`) |
| `docker-compose.yml`              | Two local-kms emulators: kms1 (root, 14599) and kms2 (issuing, 24599)                                         |
| `Documentation/`                  | This map, conformance report, release notes, `design/`                                                        |
| `.project/`                       | `gomod-project.mk` (shared make targets, version string), `config.yml` (org and project name)                 |

Dependency direction (non-test): `cmd/kubeca` → `internal/controller`,
`internal/operator`, `internal/k8snames`, `internal/logr`,
`internal/version`; `cmd/kubecertinit` → `internal/certinit`,
`internal/k8snames`, `internal/version`; `cmd/certmonitor` → no internal
package (porto `pkg/tlsconfig` only); `internal/operator` →
`internal/operator/{issuer,certificate,pod,webhook,index}`,
`internal/k8snames`; the operator controllers → `api/v1alpha1`,
`internal/operator/{policy,index,metrics}`, `internal/k8snames`,
`internal/signerr` (certificate), never each other;
`internal/operator/policy` → `api/v1alpha1`, `internal/k8snames`
(`DefaultClusterDomain`); `internal/controller`
→ `internal/k8snames`, `internal/signerr`; `internal/certinit` →
`internal/k8snames`; `api/v1alpha1` → `k8s.io/apimachinery` only.
`internal/testauthority` is imported by tests only. External:
`internal/controller` and the operator use xpki `authority`, `csr`,
`certutil`, `metricskey`, `x/print`, controller-runtime,
`client-go/tools/record`, `k8s.io/utils/clock`, `prometheus/client_golang`
(metrics); `internal/certinit` uses xpki `csr`, `certutil`,
`cryptoprov/inmemcrypto`, `x/print`, `client-go`; `cmd/kubeca` imports the
xpki providers `crypto11`, `awskmscrypto`, `gcpkmscrypto` (their `init()`
registers them); `internal/testauthority` uses xpki `testca`,
`cryptoprov/inmemcrypto`. Errors: `github.com/cockroachdb/errors`
everywhere (`github.com/pkg/errors` is an indirect dependency only).

## Concept index

| Concept                                        | File(s)                                                  | Entry points                                                                                                         |
| ---------------------------------------------- | -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Controller process, flags, provider aliases    | `cmd/kubeca/main.go`, `run.go`                           | `main`, `flags`, `run`, `providerAliases`, `explicitFlags`; flags `-ca-cfg`, `-hsm-cfg`, `-metrics-addr`, `-health-probe-addr`, `-enable-leader-election`, `-leader-election-id`, `-disable-csr-signer`, `-approve`, `-approve-allowed-names`, `-cluster-domain`, `-enable-operator`, `-enable-webhook`, `-webhook-port`, `-webhook-cert-dir`, `-webhook-service`, `-webhook-namespace`, `-webhook-signer`, `-webhook-config`, `-debug`, `-stackdriver`, `-version` |
| Init-container process, flags (deprecated)     | `cmd/kubecertinit/main.go`                               | `main`; flags `-namespace`, `-pod-name`, `-signer`, `-cert-dir`, `-san`, `-service-names`, `-query-k8s`, `-cluster-domain`, `-include-unqualified`, `-labels`, `-usages`, `-timeout` (default 10m), `-kubeconfig`, `-stackdriver`, `-version` |
| API group, kinds, scheme registration          | `api/v1alpha1/groupversion_info.go`, `doc.go`            | `GroupVersion`, `SchemeBuilder` (apimachinery `runtime.NewSchemeBuilder`), `AddToScheme`; `go:generate controller-gen object` |
| Labels, annotations, conditions, reasons, events, Secret keys, defaults | `api/v1alpha1/constants.go`                     | `GroupName`, `Label*`, `Annotation*`, `Condition*`, `Reason*`, `Event*`, `SecretKey*` (spelled out, pinned to corev1 by `TestSecretKeys`), `DefaultMountPath`, `DefaultSecretSuffix`, `GeneratedSecretPrefix`, `InjectedVolumeName`, `KeyAlgorithm*`, `RotationPolicy*` |
| Pod flow object names                          | `api/v1alpha1/names.go`                                  | `PodSecretName`, `PodCertificateName` (shared by the Pod controller, the webhook and the Certificate controller's owner check), `boundedName` (253 characters, prefix + `-` + 8 hex of SHA-256) |
| Certificate API                                | `api/v1alpha1/certificate_types.go`                      | `Certificate`, `CertificateSpec`, `CertificateStatus`, `IssuerReference`, `KubernetesNames`, `PrivateKeySpec`, `SecretTemplate`, `SecretNameOrDefault`, `KeyAlgorithmOrDefault`, `RotationPolicyOrDefault`; CEL markers |
| ClusterIssuer API                              | `api/v1alpha1/clusterissuer_types.go`                    | `ClusterIssuer`, `ClusterIssuerSpec`, `ClusterIssuerStatus`, `IssuerPolicy`, `SPIFFESpec`, `CABundleSpec`, `ProfileStatus`, `TrustDomain`, `ExposesProfile` |
| Generated CRDs and RBAC                        | `config/crd/bases/*.yaml`, `config/rbac/role.yaml`, `examples/kubeca/crds/` | `make manifests`; the chart roles are hand-written copies of `role.yaml` split by component                 |
| Operator wiring, cache selectors, webhook server | `internal/operator/setup.go`                           | `Options`, `WebhookOptions`, `Scheme`, `AddToScheme`, `CacheOptions`, `WebhookServer`, `Setup`, `DefaultWebhookPort`, `DefaultWebhookProfile`, `DefaultWebhookConfigName` |
| CRD validation and admission policy under envtest | `internal/operator/envtest_test.go`                   | `crdSuite`: CEL rules, status subresource, the chart's ValidatingAdmissionPolicy (`renderAdmissionPolicy`); skips without `KUBEBUILDER_ASSETS` (`make envtest`) |
| Operator manager under envtest                 | `internal/operator/manager_test.go`                      | `managerSuite`: `operator.Setup` with `testauthority` on its own API server; the watches and predicates (no retry loop, CA bundle following `issuerRef`) |
| Policy evaluation                              | `internal/operator/policy/policy.go`                     | `Evaluate`, `Compile`, `BoundDuration`, `MaxDuration`, `Request`, `Violation`, `Reason*`, `Placeholder*`, `Type*`      |
| Field indexes                                  | `internal/operator/index/index.go`, `doc.go`             | `Register`, `CertificateIssuer`, `CertificateServices`, `CertificateIssuerValue`, `CertificateServicesValue`          |
| Operator metrics                               | `internal/operator/metrics/metrics.go`, `doc.go`         | `CertificateExpiration`, `CertificateRenewal`, `CertificateReady`, `IssuanceTotal`, `IssuanceDuration`, `ClusterIssuerCAExpiration`, `ObserveCertificate`, `ForgetCertificate`, `Result*`, `expirationSeries` (last issuer/profile per Certificate) |
| ClusterIssuer reconcile                        | `internal/operator/issuer/reconciler.go`                 | `Reconciler`, `Reconcile`, `SetupWithManager`, `IssuerRefChanged` (watch predicate), `evaluate`, `certificateNamespaces`, `publishCABundle`, `pruneCABundles`, `configMapConflict`, `Backdate`, `RootPEM`, `ControllerName` |
| Certificate reconcile, status, errors          | `internal/operator/certificate/reconciler.go`            | `Reconciler`, `Reconcile`, `SetupWithManager`, `CertificateChanged` (watch predicate), `reconcile`, `handleError`, `fail`, `setStored`, `permanentError`, `isPermanent`, `ControllerName`, `DefaultMaxConcurrentReconciles` |
| Issuer/profile resolution, names, validity, key, CSR, Sign | `internal/operator/certificate/issuance.go`  | `issuanceContext`, `resolve`, `assembleNames`, `evaluatePolicy`, `podServiceAccount`, `issue`, `certificatePEM`, `privateKey`, `generateKey`, `keyMatches`, `namesDrift`, `sanStrings`, `formatSerial` |
| Secret read, conflict, write, in-place sync    | `internal/operator/certificate/secret.go`                | `stored`, `readSecret`, `conflictMessage` (ownership, then type), `parseStored`, `restoreStatus`, `writeSecret`, `syncSecret`, `repairTrustData`, `sameChain`, `caBundlePEM`, `secretLabels`, `secretAnnotations`, `templateEntries`, `validateSecretTemplate` |
| Issuance decision, renewal time, jitter        | `internal/operator/certificate/renewal.go`               | `needsIssuance`, `specDrift`, `renewalTime`, `jitter`, `publicKeysEqual`                                             |
| Pod reconcile, Certificate per Pod             | `internal/operator/pod/reconciler.go`                    | `Reconciler`, `Reconcile`, `SetupWithManager`, `Injected`, `desiredSpec`, `invalidPodError`, `ControllerName` |
| Pod admission mutation                         | `internal/operator/webhook/mutator.go`                   | `PodMutator`, `NewPodMutator`, `Handle`, `Mutate`, `GenerateSecretName`, `Path`                                       |
| Webhook serving certificate, caBundle          | `internal/operator/webhook/serving.go`                   | `ServingCertificate`, `Issue`, `EnsureCABundle`, `Start`, `NeedLeaderElection`, `CertFileName`, `KeyFileName`         |
| CSR signer flags, Authority loading            | `internal/controller/controller.go`                      | `ApproveMode` (`ApproveOff`, `ApproveAudit`, `ApproveEnforce`), `ParseApproveMode`, `LoadAuthority`                 |
| CSR reconcile, approval, signing, `Failed`     | `internal/controller/certificatesigningrequest.go`       | `CertificateSigningRequestSigningReconciler`, `Reconcile`, `approve`, `sign`, `fail`, `findIssuer`, `SetupWithManager`, `approvalConditions`, event and condition reason constants |
| CSR name evaluation (approver)                 | `internal/controller/approver.go`                        | `evaluateNames`, `parseServiceAccount`, `allowedIP`, `isSPIFFEID` (canonical form only), `trustDomainRegexp`, `podServiceAccountField` |
| Signer name ↔ issuer/profile                   | `internal/controller/certificatesigningrequest.go`, `internal/certinit/certreq.go` | `findIssuer` (`<label>/<profile>` → `Authority.GetIssuerByProfile`), `requestCertificate` (same split), `profileUsages` |
| xpki error classification                      | `internal/signerr/signerr.go`, `doc.go`                  | `IsPermanent`, `permanentMessages`                                                                                   |
| Pod and Service name derivation                | `internal/k8snames/names.go`                             | `Options`, `Names`, `ForPod`, `ServiceNames`, `ServiceNamesOf`, `ClusterIPs`, `SelectingServices`, `PodIPs`, `PodDNSName`, `SPIFFEID`, `IPToLabel`, `SplitList`, `DefaultClusterDomain`, `DefaultServiceAccount` |
| Test Authority                                 | `internal/testauthority/testauthority.go`, `doc.go`      | `New`, `FromEntities`, `CA` (`Authority`, `Root`, `Issuer`, `Dir`), `RootPEM`, `IssuerLabel`, `Profile*`              |
| Init request parameters, Kubernetes clients    | `internal/certinit/certinit.go`                          | `Request`, `Request.Create`, `CertClient`, `MinPods`, `MinServices`, `MinCertificates` (with `Watch`), `NewClient`   |
| Key and CSR generation, CSR submit, watch, wait | `internal/certinit/certreq.go`                          | `requestCertificate`, `waitForCertificate`, `watchCertificate`, `certificateOf`, `requestName`, `usages`, `pollInterval` |
| Output files of the init container             | `internal/certinit/certreq.go`                           | `tls.key` (`keyFileMode` 0644, KUBECA-003), `tls.csr`, `tls.crt` under `Request.CertDir`                             |
| go-logr adapter                                | `internal/logr/logr.go`                                  | `New`, `prov`, `xlogLevel`                                                                                           |
| Build version                                  | `internal/version/current.go`, `versioninfo.go`          | `Current`, `Info`, `Info.PopulateFromBuild`, `buildVersion`, linker variable `build`                                 |
| CA configuration and profiles                  | `examples/kubeca/etc/ca-config.kubeca.yaml`              | `authority.issuers[].label` (= signer domain and `ClusterIssuer.spec.issuerLabel`), `profiles.<name>`; `webhook` profile; `extraProfiles` loop; rendered through `tpl` |
| KMS / HSM token configuration                  | `examples/kubeca/etc/aws-kms-us-west-2.yaml`, `aws-dev-kms-local.yaml`, `aws-dev-kms-minikube.yaml` | `manufacturer`, `model`, `attributes` (`Region`, `Endpoint`)                                   |
| Controller deployment, computed flags, mounts  | `examples/kubeca/templates/deployment.yml`, `configmap-etc.yaml`, `configmap.yaml`, `_helpers.tpl` | `values.command` plus flags from `clusterDomain`, `metricsPort`, `healthProbePort`, `csrSigner`, `operator`; `/kubeca/etc`, `/kubeca/certs` (`kubeca.certsSecretName`), `/kubeca/webhook` (emptyDir); ports `metrics`, `health`, `webhook`; readiness probe `/readyz` |
| Pod-controlled Certificate admission policy    | `examples/kubeca/templates/admission-policy.yaml`        | `ValidatingAdmissionPolicy` and binding `<fullname>-pod-certificates` (`operator.podCertificatePolicy`, Kubernetes 1.30+): only the operator's ServiceAccount creates a Certificate controlled by a Pod or changes its spec or owners |
| Controller RBAC                                | `examples/kubeca/templates/role-csr-signer.yaml`, `role-operator.yaml`, `role-leader-election.yaml`, `rolebinding.yaml`, `serviceaccount.yaml` | `kubeca:csr-signer` (CSRs, status, approval, `sign`/`approve` on `kubeca.svc/*`, pods, services, events), `kubeca:csr-creator` (opt-in), `kubeca:operator` (CRDs and status, secrets, configmaps, namespaces, pods, services, events, mutatingwebhookconfigurations), `<fullname>-leader-election` |
| Webhook Service, configuration, PDB            | `examples/kubeca/templates/webhook.yaml`                 | `<fullname>-webhook` Service (443 → `webhook`), `MutatingWebhookConfiguration` `kubeca.webhookConfigName` (`<fullname>-pod-injector`, objectSelector `inject=true`, `/mutate-pod`), PDB when `replicaCount.default > 1` |
| Workload RBAC (init container)                 | `examples/initcontainer/rbac.yaml`, README               | `kubeca:csr-creator` ClusterRole (create/get/list/watch CSRs) and the namespaced `kubeca:pod-names` Role (get/list pods and services) |
| Certificate monitor (test tool)                | `cmd/certmonitor/main.go`                                | `main`, `printCertificate`; flags `-cert`, `-key`, `-root`, `-interval` |
| Images                                         | `Dockerfile.kubeca`, `Dockerfile.kubecertinit`, `Dockerfile.certmonitor` (local only) | distroless `base-debian13:nonroot`, `/app/<binary>` + `change_log.txt`                                               |
| Build, generation, version string, CI          | `Makefile` (`LDFLAGS`, `CONTROLLER_GEN_VERSION`, `SETUP_ENVTEST_VERSION`, `ENVTEST_K8S_VERSION`, `KUBEBUILDER_ASSETS`), `.project/gomod-project.mk`, `.VERSION`, `.github/workflows/build.yml`, `settag.yml` | `make build/test/lint/covtest/generate/manifests/envtest/version/change_log/docker`; version `v<.VERSION>.<commit count>[-dirty]` |
| Key ceremony                                   | `scripts/gen_root.sh`, `scripts/gen_ca.sh`, `etc/ca-config.bootstrap.yaml`, `etc/csr_profile/` | `make kubeca-ceremony-local`, `kubeca-root-aws`, `kubeca-g1-aws`; `Documentation/key-ceremony.md`     |
| Local end-to-end test (minikube)               | `scripts/minikube_{images,deploy,test,clean}.sh`, `examples/kubeca/minikube.yaml` (adds `e2e-5m` and the e2e `ClusterIssuer` values), `examples/shop/{namespace.yaml,e2e/workload.yaml}`, `examples/initcontainer/dummy-deployment.yaml` | `make minikube-all`; operator issuance and renewal (`e2e-5m`), injected Pod, admission policy (type-checked, forged Certificate denied), approved CSR, files in the Pod, chain, JSON log format |

## Package cmd/kubeca

`main` registers the provider aliases, parses flags, prints the version
and exits with `-version`, sets the xlog formatter (JSON or Stackdriver,
with caller), sets the controller-runtime global logger to the xlog
adapter, turns leader election on when `-enable-operator` is set and
`-enable-leader-election` was not given explicitly (`flag.Visit`), logs
the version and calls `run`. `run` (`run.go`) validates the flag
combinations (`-approve` value, `-enable-webhook` needs the operator,
`-disable-csr-signer` needs the operator), builds the scheme
(`certificates/v1`, `core/v1`, plus `operator.AddToScheme` in operator
mode), the manager options (metrics, health probes, leader election,
logger, `operator.CacheOptions()` or a cache that only strips
`managedFields`, the webhook server), creates the manager, adds the
`ping` health check and the readiness check (`webhook`: the webhook
server's `StartedChecker`, a TLS dial, with `-enable-webhook`; `ping`
otherwise), loads the Authority
(`controller.LoadAuthority`), registers the CSR reconciler unless
disabled and `operator.Setup` when enabled, and starts the manager with
the signal context. A panic is recovered and printed; errors exit with
status 1.

Invariants:

- Process-global state: the xpki provider registry (the blank-imported
  providers register `SoftHSM`, `AWSKMS`, `GCPKMS` in `init()`;
  `providerAliases` adds `PKCS11`; a registration error exits 1), the xlog
  formatter and global level (`-debug` sets `DEBUG`), the
  controller-runtime global logger (the same xlog adapter as the manager
  logger), and the Prometheus registry of controller-runtime
  (`internal/operator/metrics` registers in `init()` and keeps, under a
  mutex, the issuer/profile labels last observed per Certificate).
- Flag defaults point at `/kubeca/etc/ca-config.yaml` and
  `/kubeca/etc/aws-kms-us-west-2.json`; the chart passes both explicitly
  (`.yaml`) and appends the operator and approver flags after
  `values.command`.
- The Authority is loaded once; a changed CA configuration or issuer
  certificate needs a restart (ROADMAP, hot reload).

## Package cmd/certmonitor (test tool)

`main` requires `-cert` and `-key` (exit 1 otherwise, or on a bad
`-interval`), builds a client TLS configuration with
`tlsconfig.NewClientTLSWithReloader` (porto), prints the loaded
certificate (`printCertificate`: subject, DNS names, IPs, URIs, validity,
serial, issuer's full name; a Pod certificate has no common name), prints
it again from the reloader's `OnReload` handler, and waits for SIGINT or
SIGTERM. The reloader polls the files every `-interval` and reloads when
the certificate or key modification time moves (`os.Stat` follows the
symlinks a Secret volume swaps on update) or after an hour; an expired
certificate at start is an error. Output is plain `fmt` lines on stdout,
not xlog: a demo tool read with `kubectl logs`. Each event is a block
whose first line is `<RFC 3339 time>: certificate loaded` or
`... certificate reloaded`, then indented fields, the decimal
`serial number` among them; `scripts/minikube_test.sh` matches those
lines (unanchored) and compares the serial with the Secret's hex `serial`
annotation. `-root` is optional: the monitor never connects, so the init-container
Pod, whose files have no `ca.crt`, runs without it. Image
`Dockerfile.certmonitor` (distroless: no shell, `ls` or `cat`, so the
minikube test reads logs and Secrets instead of `kubectl exec`), built and
loaded by `scripts/minikube_images.sh`; CI neither builds nor publishes
it. Every workload of `examples/shop` and
`examples/initcontainer/dummy-deployment.yaml` runs it.

## Package cmd/kubecertinit (deprecated)

`main` parses flags into `certinit.Request`, prints the version and exits
with `-version`, sets the formatter, logs the version, builds a client with
`certinit.NewClient(-kubeconfig, -namespace)` (empty kubeconfig means
in-cluster) and runs `Request.Create` with a context bounded by `-timeout`
(10 minutes by default, `0` never ends it). Exit status 2 on any error.
The package comment carries the `Deprecated` marker; see
[design/initcontainer.md](design/initcontainer.md).

## Package api/v1alpha1

### Files

| File                       | Role                                                                                                       |
| -------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `doc.go`                   | Package comment, `+groupName`, the `go:generate controller-gen object` directive                           |
| `groupversion_info.go`     | `GroupVersion`, `SchemeBuilder` (apimachinery `runtime.NewSchemeBuilder` with `addKnownTypes` and `metav1.AddToGroupVersion`), `AddToScheme` |
| `constants.go`             | Every label, annotation, condition type, reason, event reason, Secret key and default, spelled out once      |
| `names.go`                 | `PodSecretName` and `PodCertificateName`: the Secret and Certificate names of a labeled Pod, derived from its name and `secret-name` annotation |
| `certificate_types.go`     | `Certificate` with the kubebuilder markers (status subresource, short names `cert`/`certs`, printer columns) and the spec helpers |
| `clusterissuer_types.go`   | `ClusterIssuer` (cluster-scoped, short name `cissuer`, printer columns) and the spec helpers                 |
| `zz_generated.deepcopy.go` | Generated by `make generate`; never edited                                                                   |

Invariants:

- Imports only `k8s.io/apimachinery` (no controller-runtime, no
  `k8s.io/api`, nothing from `internal/`); the `kubernetes.io/tls` Secret
  keys are literals, pinned to the corev1 constants by `TestSecretKeys`
  in `internal/operator/certificate`.
- Validation lives in the markers: at least one name (`dnsNames`,
  `ipAddresses`, `uris`, `emailAddresses` or `kubernetesNames.services`),
  `renewBefore < duration`, `duration ≥ 1m`, `renewBefore ≥ 30s`,
  `secretName` and `issuerLabel` immutable (`self == oldSelf`),
  `privateKey.size` per algorithm, `defaultProfile` listed in `profiles`
  when both are set, DNS-1123 patterns on `secretName`, `configMapName`,
  `trustDomain` and Service names. Defaults: `privateKey.algorithm`
  ECDSA, `rotationPolicy` Always.
- Printer columns `Not After`, `Renewal` and `CA Not After` are `string`
  (RFC 3339), not `date`: kubectl renders a future time of a `date` column
  as `<invalid>`. `Age` stays a `date`.
- `IssuerPolicy.Allowed*` are `*[]string` so an explicit empty list (deny
  the name type) survives `omitempty`.
- A new field needs the markers, `make generate manifests`, the API
  document and the examples in the same change.

## Package internal/operator

`setup.go`: `Scheme`/`AddToScheme` (core/v1, admissionregistration/v1,
v1alpha1), `CacheOptions` (Secrets and ConfigMaps restricted to
`kubeca.effectivesecurity/managed=true`, Pods to `inject=true`,
`managedFields` stripped for every object; Certificates, ClusterIssuers,
Namespaces and Services cached fully), `WebhookServer` (port and cert
dir), `Setup` (indexes, the three controllers with the real clock, and the
webhook: `ServingCertificate.Issue` runs synchronously so the server finds
its files, the renewer is added as a runnable without leader election,
`PodMutator` is registered at `webhook.Path`). `envtest_test.go`
(`crdSuite`) starts an API server with the CRDs of `config/crd/bases`,
checks the CEL rules and the status subresource, and applies the chart's
admission policy (rendered from the template by `renderAdmissionPolicy`,
which fails on a template action it does not know) to check, with users
added by `envtest.Environment.AddUser`, who may create and change a
Pod-controlled Certificate. `manager_test.go` (`managerSuite`) runs
`operator.Setup` with `testauthority` on a second API server and checks
that a rejected Certificate is attempted once until a relevant change.
Both skip when `KUBEBUILDER_ASSETS` is empty.

Invariants: the sub-packages never import each other; a controller that
needs an object outside the cache selectors uses `mgr.GetAPIReader()`.

### Package internal/operator/policy

`Evaluate(policy, Request) *Violation`: nil policy allows everything; the
namespace selector (compiled per call, `InvalidPolicy` when invalid) must
match the namespace labels; each of `allowedDNSNames`, `allowedURIs`,
`allowedEmailAddresses` is a list of RE2 expressions after substituting
`${NAMESPACE}`, `${NAME}`, `${SERVICE_ACCOUNT}` and `${CLUSTER_DOMAIN}`
(`Request.ClusterDomain`, the Certificate controller's `ClusterDomain`,
so the chart's default policy follows `clusterDomain`) regex-quoted; a nil
list allows the type, an empty list denies it; `Request.CommonName` is
checked against `allowedDNSNames` before the SAN (xpki signs the trusted
subject as given); IP addresses need `allowIPAddresses`. The first
offending name is reported (`NameNotAllowed`, `NamespaceNotAllowed`,
`InvalidPolicy`). `Compile`
checks the selector and every expression once (the ClusterIssuer
controller), in a fixed field order so the first error, and the
ClusterIssuer condition message, is the same on every call.
`BoundDuration(requested, profileExpiry, maxDuration)` is the
lifetime bound. Pure; table tests.

### Package internal/operator/index

`Register` adds two field indexes on Certificates: `spec.issuerRef.name`
and every entry of `spec.kubernetesNames.services`. Tests register the
same indexes on the fake client with `WithIndex`.

### Package internal/operator/metrics

Registers the six operator metrics with controller-runtime's registry in
`init()`. `ObserveCertificate` sets the three gauges of a Certificate and
remembers the issuer/profile labels of its expiration series
(`expirationSeries`, mutex-guarded): a Certificate observed again under
another issuer or profile loses the previous series, and a zero
`notAfter`/renewal (nothing stored) deletes that series. `ForgetCertificate`
deletes them all (partial match on namespace and name). Both are called
by the Certificate controller's concurrent workers;
`TestObserveCertificateConcurrent` races them under `RACE=true`.

### Package internal/operator/issuer

`Reconcile`: get the ClusterIssuer (NotFound forgets the CA gauge);
`evaluate` resolves `spec.issuerLabel` with `Authority.GetIssuerByLabel`
(`IssuerNotFound` clears the status fields), checks every exposed profile
(`spec.profiles`, or all the issuer serves, sorted by name for
`status.profiles` either way) and the `defaultProfile`
(`ProfileNotFound`), compiles the policy (`InvalidPolicy`), fills
`issuerKeyID`, `caCertificate` (issuer PEM), `rootCertificate` (`RootPEM`:
the chain's root or the Authority's root bundle, trailing newline),
`caNotAfter` and `profiles` (name, expiry, `Backdate` with the 5 m
default, usages), sets the CA gauge and the `Ready` condition: `CAExpired`
(False) when the CA expired, `CAExpiring` (True) when `caNotAfter < now +
bound` with `bound` the longest certificate the issuer can sign (the
longest exposed expiry, or the policy `maxDuration` when shorter, as
`policy.BoundDuration` bounds an issuance), else `Loaded`. The requeue is the next transition clamped to
[1 m, 1 h]. A condition transition is one event (`Ready` for `Loaded`,
the reason otherwise) and one `INFO` line. The status is patched only when
it changed. `certificateNamespaces` lists the issuer's Certificates
through the index. With `spec.caBundle` and `Ready`, `publishCABundle`
has `writeCABundle` create or update the ConfigMap in each of those
namespaces (key `ca.crt`, label `managed=true`,
annotation `issuer`, controller reference to the ClusterIssuer;
cluster-scoped owners of namespaced objects are allowed). The cache holds
managed ConfigMaps only, so a miss is confirmed with `APIReader`.
`configMapConflict` leaves alone, with a `ConfigMapConflict` Warning event
and no error or retry, a ConfigMap of that name that is controlled by
anything but a ClusterIssuer of this name (another ClusterIssuer with the
same `configMapName` included: `SetControllerReference` would fail on
every reconcile), or has no controller and no `managed` label; a stale
controller reference of a deleted ClusterIssuer of this name is replaced.
`pruneCABundles` runs on every reconcile, Ready or not: it deletes the
managed ConfigMaps whose controller reference carries this issuer's UID
and that are not wanted any more (a namespace without one of its
Certificates, another name than `configMapName`, or no `spec.caBundle`),
one `INFO` line each (`status=ca_bundle_deleted`); RBAC `configmaps`
includes `delete`. Watches: ClusterIssuers; Certificates through
`IssuerRefChanged` (create, delete, and updates that change
`spec.issuerRef.name`; controller-runtime's map handler enqueues the
issuers of the old and the new object).
Log keys: `condition` carries a condition reason code, `reason` free text
(the same convention in `internal/operator/certificate`).

### Package internal/operator/certificate

`Reconcile`: get (NotFound or deleting forgets the gauges), run
`reconcile`, patch the status when it changed (`Status().Patch` with
`MergeFrom`; a patch failure is combined with the pipeline error), record
the gauges with the profile `reconcile` returns (the resolved one, the
issuer's `defaultProfile` included; the Secret's `profile` annotation,
`storedProfile`, when the issuer cannot be resolved). `reconcile` (with
`issueOrKeep` once the issuer is resolved):

1. `resolve`: `validateSecretTemplate` first checks the template's
   labels and annotations (reserved prefix skipped) with apimachinery's
   `ValidateLabels`/`ValidateAnnotations`, the API server's own rules, and
   reports them sorted as `PolicyViolation` (the CRD accepts any string,
   and a Secret write rejected after signing would be retried, signing
   again each time); the ClusterIssuer must exist and be `Ready`
   (`IssuerNotReady`, requeue 1 m; the issuer controller also enqueues
   the Certificates of an issuer whose status changes; the Secret is read
   first, and a still valid stored certificate keeps `Ready=True` with
   only `Issuing=False/Failed` recording the message); the xpki issuer by
   label; the profile (`spec.profile` or `defaultProfile`) must be exposed
   by the ClusterIssuer and served by the issuer (`PolicyViolation`);
   `assembleNames` concatenates the spec names and the Service names of
   `kubernetesNames` (a missing Service is `PolicyViolation` with
   `ServiceNotFound`), validates with `csr.ParseSAN` and checks the
   profile's `allowed_fields` per name type; `evaluatePolicy` reads the
   Namespace only when the policy has a selector; the lifetime is
   `policy.BoundDuration` and must leave at least 2 minutes after the
   profile `backdate` (else `PolicyViolation`); `renewBefore` is the spec
   value or a third of the lifetime, clamped so the renewal is never
   scheduled within a minute of the issuance; the key algorithm and size
   come from `KeyAlgorithmOrDefault`.
2. `readSecret`: the cached Get (managed Secrets only), then the uncached
   `APIReader` on a miss (`stored.cached` records which). Before a
   decision to sign, `issueOrKeep` has `confirmSecret` re-read a cached
   Secret through the `APIReader` and, when its resourceVersion differs,
   runs `restoreStatus` and `needsIssuance` again on it: the cache can lag
   the controller's own last write (a retry right after a failed status
   patch) and would otherwise sign again. `conflictMessage` accepts a Secret controlled
   by this Certificate (UID), or by a Certificate of the same name that no
   longer exists (stale owner, adopted), or without a controller and
   labeled `managed=true` or `adopt=true`; anything else is
   `SecretConflict` (requeue 5 m: the foreign Secret is not in the cache,
   so its deletion is not observed). `parseStored` parses `tls.crt`
   (`certutil.ParseChainFromPEM`, the first certificate is the leaf) and
   `tls.key` (`certutil.ParsePrivateKeyPEM`) and records the first
   problem. `restoreStatus` then takes `status.revision` and
   `status.lastRenewRequest` from the Secret's `revision` and
   `renew-requested` annotations when the Secret's revision is ahead of
   the status: the Secret is written before the status patch, and a
   failed patch must not count the issuance again or honour the same
   renewal request twice. A Secret we may own but whose type is not `kubernetes.io/tls`
   is a `SecretConflict` as well (the type is immutable): a matching
   Opaque Secret labeled `adopt=true` is never adopted.
3. `needsIssuance`, in this order: no or invalid Secret (`Initial` when
   `status.revision` is 0, else `SecretMissing`); key and certificate
   public keys differ (`SecretMissing`); `renew-requested` annotation
   differs from `status.lastRenewRequest`, a removed annotation included,
   which renews once and clears the status (`Requested`); the leaf's AKI
   differs from the ClusterIssuer's `issuerKeyID` (`CAChanged`);
   `specDrift` (the Secret's `issuer`, `profile` and `duration`
   annotations, an unparsable `duration` counting as drift, the common name, `namesDrift`, `keyMatches`, the
   profile's key usages and extended key usages) (`SpecChanged`); the leaf expired (`Renewal`); the
   renewal time passed (`Renewal`). Nothing to do: `syncSecret` applies
   `secretTemplate` changes and the owner in place and `repairTrustData`
   restores what an issuance would write today and does not depend on it
   (the issuer chain after the stored leaf in `tls.crt`, compared by DER;
   `ca.crt`, the ClusterIssuer's `status.rootCertificate`), logging one
   `WARNING` (`status=secret_repaired`); `setStored` copies the leaf
   into the status with `Ready=True/Issued`, and the result is
   `RequeueAfter` the renewal time (at least 10 s).
4. `issue`: `privateKey` reuses the stored key only with
   `rotationPolicy: Never` and a matching algorithm and size, else
   `generateKey` (ECDSA P-256/384/521 or RSA 2048/3072/4096; an
   unsupported size is a `PolicyViolation`); the CSR carries the common
   name and all names (`x509.CreateCertificateRequest`); the clock is read
   right before `Sign`; `SignRequest{Request, Profile, Subject{CommonName},
   NotBefore = now.Truncate(1m) − backdate, NotAfter = NotBefore +
   duration}` and never `SAN`; `namesDrift` between the leaf and the
   request is a permanent `IssuanceFailed` (the profile dropped a name
   type); `tls.crt` is the leaf plus `Issuer.PEM()` (`certificatePEM`), `tls.key` is
   `certutil.EncodePrivateKeyToPEM` (`EC PRIVATE KEY` / `RSA PRIVATE KEY`,
   as `kubecertinit`).
5. `writeSecret`: Create (type `kubernetes.io/tls`) or Update (an
   existing Secret passed `readSecret`, so its type is right);
   labels `secretLabels` (existing + template without the reserved prefix,
   `templateEntries`
   + `managed=true`), annotations `secretAnnotations` (existing + template
   + `certificate`, `issuer`, `profile`) plus `serial`, `not-before`,
   `not-after`, `issued-at`, `duration`, `revision` and `renew-requested`
   (the request this issuance honoured; removed when there is none); `ca.crt` is the
   ClusterIssuer's `status.rootCertificate` (`caBundlePEM`); `own` drops a stale owner
   reference of a same-named Certificate and sets the controller
   reference with `blockOwnerDeletion: false` (no `finalizers` RBAC under
   `OwnerReferencesPermissionEnforcement`; the issuer and pod controllers
   do the same); `syncSecret` also owns an adopted Secret that needs no
   re-issuance.
6. Status: `revision++`, `failedAttempts` 0, `lastRenewRequest`, the leaf
   times, `serialNumber` (upper-case hex pairs with colons),
   `issuerLabel`, `issuerKeyID`, `renewalTime`, `Ready=True/Issued`,
   `Issuing=False/Issued`; event `Issued` (revision 1) or `Renewed`;
   `kubeca_issuance_total{result=success}` and the duration histogram;
   one `INFO` line (`status=issued`, `ns`, `name`, `issuer`, `profile`,
   `serial`, `not_after`, `renewal_time`, `trigger`, `revision`,
   `elapsed`).

Errors: a `*permanentError` (reason, message) or a `signerr.IsPermanent`
error ends in `fail` (`Ready=False/<reason>`, `Issuing=False/Failed`, a
`Warning` event with the reason, one `WARNING` line, `result=policy_violation`
or `error`) and returns without error; a transient error increments
`failedAttempts`, sets `lastFailureTime`, keeps `Issuing=True/<trigger>`,
sets `Ready=False/IssuanceFailed` only when no valid certificate is stored,
emits `IssuanceFailed` and is returned for the backoff. Neither retries
through the status patch: the Certificate watch passes updates of the
generation, the annotations and the owner references only
(`CertificateChanged`), so a permanent failure waits for a relevant change
(spec, `renew-requested`, the Secret, the ClusterIssuer, a named Service,
the Namespace labels) and a transient one for the rate limiter.

Renewal time (`renewal.go`): `notAfter − renewBefore − jitter`, where
`renewBefore` falls back to a third of the actual lifetime when it is not
shorter than it (the issuer may have clipped the certificate), the jitter
is `fnv64a(serial) mod (renewBefore / 10)` (deterministic across replicas),
and the result is never sooner than one minute after the issuance time
recorded in the Secret's `issued-at` annotation (`notBefore + backdate`
when the annotation is missing). It is recomputed on every reconcile, so a
`renewBefore` change applies without re-issuing.

Watches: Certificates (`CertificateChanged`: not their status); owned
Secrets (the cache holds managed Secrets only, which ours are);
ClusterIssuers mapped through the issuer index;
Services mapped through the services index within their namespace;
Namespaces whose labels changed (`LabelChangedPredicate`) mapped to
their Certificates. The policy placeholder `${SERVICE_ACCOUNT}`
(`podServiceAccount` in `issuance.go`) is the ServiceAccount of the Pod
that controls the Certificate, read from the cache (labeled Pods only,
RBAC `pods` get/list/watch) and used only when the Certificate is the one
the Pod controller writes for that Pod: the owner UID is the Pod's, and
the name, `secretName` and issuer are `v1alpha1.PodCertificateName`,
`v1alpha1.PodSecretName` and the Pod's `issuer` annotation; anything
else, a direct Certificate or a `service-account` annotation (no longer
an API) included, expands it to `""`. Owner references are written by the
Certificate's author: the chart's ValidatingAdmissionPolicy
(`templates/admission-policy.yaml`) admits a Pod controller from the
operator's ServiceAccount only; without it, a forged owner with the real
UID gets the Pod's identity written into the Pod's own Secret only.
`MaxConcurrentReconciles` 4 (`Issuer.Sign` is safe for concurrent use,
XPKI-055).

### Package internal/operator/pod

`Reconcile`: get the Pod (NotFound, deleting or not labeled: nothing); the
`issuer` annotation is required (`InvalidPod` event otherwise);
`desiredSpec` lists the namespace's Services, derives
`k8snames.ForPod(pod, services, {ClusterDomain, IncludeUnqualified: true})`,
adds every Pod address (`k8snames.PodIPs`), the SPIFFE ID when the ClusterIssuer (read from the
cache, NotFound tolerated) has a trust domain, and the `san` annotation,
validates with `csr.ParseSAN` (`InvalidPod`), and reads the `profile`,
`secret-name`, `duration` and `renew-before` annotations (`InvalidPod` on
a bad duration). A Pod with no name yet (no IP, no Service, no trust
domain, no `san`) gets an `InvalidPod` event naming the missing sources
(the injected Secret volume keeps such a Pod from ever getting an IP) and
is retried on its next update. The Certificate carries no annotation:
the Certificate controller derives the policy's `${SERVICE_ACCOUNT}` from
the owning Pod itself. The Certificate is
`v1alpha1.PodCertificateName(pod, secretAnnotation)`: the Pod name when
the annotation is absent or equals `<pod>-tls`, else `<pod>-<last dash
segment>`; its Secret is `v1alpha1.PodSecretName` (the annotation or
`<pod>-tls`). `writeCertificate` creates the Certificate with the Pod as
controller, or updates the spec of the one whose controller reference
carries this Pod's UID (an existing `secretName` is kept: immutable). Any
other Certificate of that name is refused (`refusedError`, an `InvalidPod`
event, never written or adopted): one without a controller (a Pod author
could otherwise take over another workload's Certificate and its Secret,
and have them garbage-collected with the Pod), one controlled by
something else, and one of a previous Pod of the same name (requeued
after `staleOwnerRetry`, 15 s, until the garbage collector deletes it;
the deletion also enqueues the Pod through `Owns`). A Certificate the CRD
validation rejects (`apierrors.IsInvalid`, for example a `duration`
annotation under 1 m) is `InvalidPod` too: no retry, a Pod edit
re-triggers the reconcile.
Events `CertificateCreated` / `CertificateUpdated` on the Pod and one
`INFO` line. Watches: labeled Pods (predicate `Injected`, on top of the
cache selector); owned Certificates; Services mapped to the labeled Pods
their selector matches; ClusterIssuers mapped to the labeled Pods
annotated with them.

### Package internal/operator/webhook

`PodMutator.Handle` allows non-CREATE operations without decoding, decodes
the Pod, allows unlabeled Pods unchanged,
computes the Secret name (`v1alpha1.PodSecretName`: the `secret-name`
annotation or `<name>-tls` for a named Pod; `GenerateSecretName` = `kubeca-` + 8 random `[a-z0-9]` from
`crypto/rand` for a `generateName` Pod), applies `Mutate` and returns
`PatchResponseFromRaw` (or "already injected"), with one `DEBUG` line per
admitted Pod. `Mutate` sets the
annotation, reuses a volume that already references the Secret or appends
`kubeca-tls` (suffixed `-1`, `-2`... when taken), and mounts it read-only
at the `mount-path` annotation (default `/etc/tls`) into the containers of
the `containers` annotation (default all) that have no mount at that path
or of that volume; it reports whether anything changed. Pure; tests check
the JSON patch.

`ServingCertificate.Issue` returns an error without `DNSNames`, generates
an ECDSA P-256 key, signs a CSR for
the webhook Service names with `IssuerLabel`/`Profile` (no explicit
validity: the profile's), writes `tls.key` (0600) then `tls.crt` (0644,
leaf plus chain) atomically into `CertDir` (0700), records the renewal
time (two thirds of the remaining lifetime) and the root bundle, and
calls `EnsureCABundle`, which reads the `MutatingWebhookConfiguration`
`ConfigName` with the uncached `Reader` and merge-patches every webhook's
`clientConfig.caBundle` when it differs. `Start` (a manager runnable with
`NeedLeaderElection` false, so every replica serves) loops: when the
renewal time has passed it re-issues with `issue` (certificate and files
only; a failure is retried after a minute) and then tries
`EnsureCABundle`, whose failure is only logged: the renewed certificate
keeps its schedule and the ticker retries the patch, instead of a new
certificate every minute. Otherwise it waits on a timer for the renewal
or a one-minute ticker for `EnsureCABundle`. `Issue` (start-up) is
`issue` plus `EnsureCABundle` and fails with either; whether a renewal is due is decided by the clock on
every wake-up. The controller-runtime webhook server watches the files
and reloads them.

Invariant (D-6 as taken): the serving certificate is never a
`Certificate` object or a Secret; a Secret volume cannot be mounted before
the Pod that would issue it runs.

## Package internal/controller

### Files

| File                            | Role                                                                                                   |
| ------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `controller.go`                 | `ApproveMode` and `ParseApproveMode`, `LoadAuthority` (`cryptoprov.Load`, `authority.LoadConfig`, `authority.NewAuthority`) |
| `certificatesigningrequest.go`  | `CertificateSigningRequestSigningReconciler` (`client.Client`, `APIReader`, `Scheme`, `Authority`, `EventRecorder`, `ApproveMode`, `AllowedNames`, `ClusterDomain`), `Reconcile`, `approve`, `sign`, `fail`, `findIssuer`, `approvalConditions`, event and condition reasons |
| `approver.go`                   | `evaluateNames` and its helpers (KUBECA-001)                                                           |
| `doc.go`                        | Package comment and usage                                                                              |

### Reconcile contract

For each `CertificateSigningRequest` event (cluster-scoped, one worker):

1. `Get` the CSR; NotFound returns without error.
2. Skip (no error) when: `DeletionTimestamp` set; `spec.signerName` empty;
   `status.certificate` set; a `Denied` or `Failed` condition with status
   `True` exists.
3. `findIssuer`: `strings.Cut` on `/`, exactly one slash;
   `Authority.GetIssuerByProfile(profile)` must have `Label() == label`.
   Unknown signer: skip with an `INFO` log.
4. Approval (`ApproveMode`, `off` when empty), only when no `Approved`
   condition exists (`approvalConditions` counts `Approved`, `Denied` and
   `Failed` only with status `True`, the only status the API server
   admits for them):
   - `enforce`: `evaluateNames`; `approve` appends `Approved`
     (reason `KubeCAApproved`) or `Denied` (reason `NamesNotAllowed`, the
     offending names in the message) through the `approval` subresource,
     emits `Approved` / `Denied` and returns; the update triggers the
     reconcile that signs.
   - `audit`: `evaluateNames`; a violation is a `WARNING` line and a
     `Warning` event `ApprovalAudit`; signing continues.
   - `off`: signing continues.
   With `enforce`, a CSR without `Approved` is never signed; one approved
   by another principal is signed without evaluation.
5. `sign`: `issuer.Sign(csr.SignRequest{Request, Profile})`. The names and
   subject come from the CSR under the profile's `allowed_fields` and
   regexes; `spec.usages` is ignored. A `signerr.IsPermanent` error emits
   `SigningFailed` and `fail` patches the `Failed` condition (reason
   `SigningFailed`, the error as message) through the status subresource
   and returns no error (KUBECA-013); any other error emits
   `SigningFailed` and is returned for the backoff.
6. Patch `status.certificate` (`client.MergeFrom`) with the leaf PEM
   followed by `issuer.PEM()` (the issuing certificate plus the
   `ca_bundle` intermediates, not the root), trimmed. Emit `Signed`.
   Record `metricskey.PerfCASignRequest`. Log one `NOTICE` line
   (`status=signed`, `name`, `issuer`, `profile`, `serial`, `not_after`,
   `elapsed`) and the certificate text at `DEBUG`.

`evaluateNames` (`approver.go`): the requester must be
`system:serviceaccount:<ns>:<sa>` and the CSR must parse (`csr.ParsePEM`),
else the violation says so. The Pods of the ServiceAccount are listed with
the uncached `APIReader` and the field selector `spec.serviceAccountName`
(the fake client needs a `WithIndex` on that field); the namespace's
Services with the cached client. Allowed: DNS names and emails
case-insensitively from `AllowedNames`, every Pod's IP and
`k8snames.ForPod` names (`IncludeUnqualified`); IPs by value; URIs
exactly as listed in `AllowedNames` (a URI path is case-sensitive), or
`spiffe://<trust domain>/ns/<ns>/sa/<sa>` in canonical form only (any
trust domain matching `[a-z0-9._-]+`; `u.String()` must equal
`k8snames.SPIFFEID`, which rules out user info, ports, queries, fragments
and percent-encoding). The common name, DNS names, IPs,
URIs and emails of the CSR are checked; the message lists every offender
(`<username> may not have: ...`). API errors are returned (retry).

Invariants:

- RBAC markers: CSRs get/list/watch, `certificatesigningrequests/status`
  update/patch, `certificatesigningrequests/approval` update, `signers`
  sign/approve on `kubeca.svc/*`, pods and services get/list/watch,
  events create/patch.
- The reconciler never widens the manager cache for Pods: the approver
  lists them uncached.

Tests: `certificatesigningrequest_test.go` (black box) with the fake
client, `WithStatusSubresource` on CSRs, `WithIndex` on
`spec.serviceAccountName`, `record.NewFakeRecorder` and
`internal/testauthority`: `TestSignOff`, `TestSkips`, `TestSignFailed`
(KUBECA-013, profile rejection and parse error), `TestSignTransientError`
(interceptor on the status patch), `TestApproveEnforce` (two reconciles; an allowed URI in its exact form),
`TestApproveDenied` (foreign names, common name, non-canonical SPIFFE
IDs, an allowed URI in another case, non-ServiceAccount, bad request),
`TestApproveEnforceExternalApproval` (also `Approved` with status
`Unknown` or `False`: evaluated and denied), `TestApproveAudit`,
`TestApproveListError`, `TestParseApproveMode`, `TestLoadAuthority`. The
fake client's `approval` subresource update writes the whole object.

## Package internal/certinit (deprecated flow)

### Files

| File          | Role                                                                                                                        |
| ------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `certinit.go` | `Request` (flag mirror plus `san`, `labelsMap`), `CertClient` and the three `Min*` interfaces, `NewClient`, `Request.Create` |
| `certreq.go`  | `usages` (profile → `capi.KeyUsage` list), `profileUsages`, `requestCertificate` (key, CSR, files, submit), `waitForCertificate`, `watchCertificate`, `certificateOf`, `requestName`, file and poll constants |
| `doc.go`      | Package comment and usage; says in prose that the flow is deprecated since v0.9 (no `Deprecated` marker, which would make staticcheck flag the command importing it) |

### Flow (`Request.Create`)

1. Require `Namespace`, `PodName`, `SignerName`.
2. Parse `-labels` (`k=v,...` through `k8snames.SplitList`; entries
   without `=`, with an empty key or with `=` in the value are dropped).
3. With `-query-k8s`: `Pods.Get(ctx, PodName)`, `Services.List` and
   `k8snames.ForPod(pod, services, {ClusterDomain, IncludeUnqualified}).All()`:
   `<ip-with-dashes>.<ns>.pod.<domain>`; `<hostname>.<subdomain>.<ns>.svc.<domain>`
   when both are set (plus the unqualified form); for every Service whose
   selector matches the Pod labels: `<svc>.<ns>.svc.<domain>` (plus
   unqualified), the `ExternalName` or the cluster addresses
   (`k8snames.ClusterIPs`: `spec.clusterIPs`, both families, or
   `spec.clusterIP`; a headless `None` and an empty address are skipped),
   and every `ExternalIP`.
4. For each `-service-names` entry: `k8snames.ServiceNames`.
5. Append the comma-separated `-san` values (classified, validated and
   deduplicated by xpki).
6. `requestCertificate`: signer must be `<label>/<profile>`; usages from
   `Request.Usages` when set, else the built-in table (`peer`, `server`,
   `client`; any other profile needs `-usages`); ECDSA P-256 key through
   `csr.NewProvider(inmemcrypto)`; write `tls.key` (`keyFileMode` 0644,
   KUBECA-003) and `tls.csr`; build the CSR object; name
   `<pod>-<ns>-<5 chars of [0-9a-z]>` from `crypto/rand` (panics if the
   reader fails); `Get` then `Create` when missing.
7. `waitForCertificate`: `Get` once (`certificateOf` returns the
   certificate, or the error of a `Denied` or `Failed` condition), then
   `watchCertificate` with a field-selected `Watch` from the CSR's
   resource version: `Modified`/`Added` events are checked with
   `certificateOf`, `Deleted` is an error, a closed channel ends the watch
   and the CSR is read and watched again after `watchRetryDelay` (1 s); a
   `Watch` error or an `Error` event (an API status, such as 410 for a
   resource version that is too old) falls back to one poll after
   `pollInterval` (5 s); a
   deleted CSR (`apierrors.IsNotFound`) or a done context (`-timeout`) is
   an error. Then write `tls.crt`.

Invariants:

- Only `Pods.Get`, `Services.List` and
  `CertificateSigningRequests.Get/Create/Watch` are used; `NewClient`
  wires them from `kubernetes.NewForConfig`. Every call takes the
  caller's context.
- xpki v1.0 rejects an invalid or empty name before the CSR is created, so
  a malformed `-san` fails fast; duplicates are dropped.
- Files are written with `os.WriteFile`; an existing `CertDir` is required.

Tests: `certinit_test.go` (black box) mocks the three interfaces with
`testify/mock` (the certificates mock has `Watch`). `TestCreate` captures
the created CSR and asserts the exact SAN lists, the usages, trimmed
labels, no `spec.extra`, the name pattern and the output files;
`TestCreatePodIPv6`, `TestCreatePodWithoutIP`, `TestCreateUsages`,
`TestCreateDeniedCSR`, `TestCreateFailedCSR`, `TestCreateDeletedCSR`,
`TestCreateContextDone` (watch unavailable, context ends), `TestCreateWatch`
(a watch that ends, an error event, then the certificate through
`watch.NewFake`; at least 1 s + 5 s), `TestCreateWatchDenied` (`Denied`, `Failed`, `Deleted`
events). `issuingCertificates` builds the NotFound → Create → issued mock
sequence. Files go under `t.TempDir()`.

## Package internal/k8snames

Pure name derivation shared by three callers. `Options{ClusterDomain,
IncludeUnqualified}` (`cluster.local` default); `Names{DNS, IPs}` with
`All()`; `ForPod(pod, services, opts)` returns, in order, the Pod DNS name
(`PodDNSName` for every address of `PodIPs`: `status.podIPs`, or `status.podIP` when the list is empty), the hostname/subdomain name (plus
unqualified), and for every `SelectingServices` entry (a Service whose
selector is nil or empty selects nothing, as in Kubernetes) `ServiceNamesOf`
(`ServiceNames` plus `ExternalName` as a DNS name or `ClusterIPs`:
`spec.clusterIPs`, both families of a dual-stack Service, or
`spec.clusterIP`, never `None` or empty, plus `ExternalIPs`).
`SPIFFEID(trustDomain, ns, sa)` (`DefaultServiceAccount` when the
ServiceAccount is empty; `""` without a trust domain). `IPToLabel` turns dots and colons into dashes. `SplitList` yields
trimmed, non-empty items of a comma-separated list. No deduplication (the
callers pass the names to `csr.ParseSAN`). Tests: `names_test.go`, table
and fixture based, parallel.

## Package internal/signerr

`IsPermanent(err)` matches the error text against the messages
`authority.Issuer.Sign` and `csr.ParseSAN` return for a request rejected
on its content (parse failure, unsupported profile, names outside the
allowed lists, invalid SAN, extensions, CA constraints, validity window,
missing expiry, profile without usages); everything else, including a
`NotBefore ... is earlier than allowed` window race, is transient. The
substrings are listed in `permanentMessages`; an xpki message change needs
an update here (ROADMAP: typed errors from xpki). Tests: table.

## Package internal/testauthority

`New(t)` builds a testca root (10 years) and issuing CA (5 years) with
in-memory keys, writes `issuer.pem`, `issuer.key`, `root.pem` under
`t.TempDir()`, rewrites `testdata/ca-config.yaml` (the chart's profiles
without the Helm templating, `ISSUER_*_FILE`/`ROOT_BUNDLE_FILE`
placeholders replaced with those files; located relative to the source
file with `runtime.Caller`) and loads it with `authority.LoadConfig` into
an `authority.NewAuthority` over `cryptoprov.New(inmemcrypto.NewProvider())`.
`FromEntities` takes the CAs (a test controls the CA validity). `CA`
exposes the `Authority`, `Root`, `Issuer` and `Dir`; `RootPEM` the root.
Constants: `IssuerLabel` (`kubeca.svc`), `ProfilePeer`, `ProfileServer`,
`ProfileClient`, `ProfileWebhook`. Imported by tests only; the example
file stays valid because the tests load it.

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
| `Chart.yaml`                     | `kubeca` 0.2.0                                                                                                        |
| `crds/`                          | The two CRDs, copied from `config/crd/bases` by `make manifests`; Helm installs them on install only                 |
| `values.yaml`                    | image, `imagePullSecrets`, `command` (binary and config flags), `clusterDomain`, `metricsPort`, `healthProbePort`, `csrSigner.{enabled,approve,allowedNames,createCSRCreatorRole}`, `operator.{enabled,podCertificatePolicy,webhook.{enabled,port,signer,failurePolicy}}`, `extraProfiles`, `clusterIssuers` (list of `{name, spec}` rendered by `templates/clusterissuer.yaml`; default one `kubeca` issuer), `certs.secretName`, `replicaCount.default`, `nodeSelector/tolerations/affinity.default`, `serviceAccount`, `config.common` (env), `issuers.kubeca.{cert,key,ca_bundle,root_bundle}` paths under `/kubeca/certs` |
| `local.yaml`, `aws-dev.yaml`, `minikube.yaml` | Value overlays: local-kms endpoint with dummy AWS credentials; IRSA role annotations; the minikube test (adds the `e2e-5m` profile through `extraProfiles`) |
| `etc/ca-config.kubeca.yaml`      | xpki CA config: issuer `kubeca.svc` (files from the certs Secret, no AIA), profiles `peer`, `server`, `client` (8760h), `peer-24h`, `server-24h`, `client-24h` (24h, backdate 5m), `webhook` (168h, `allowed_dns` pinned to `<fullname>-webhook.<ns>.svc`), then `extraProfiles` |
| `etc/aws-kms-us-west-2.yaml`, `etc/aws-dev-kms-local.yaml`, `etc/aws-dev-kms-minikube.yaml` | `AWSKMS` token configs                                                                    |
| `templates/configmap-etc.yaml`   | Every `etc/*` file, rendered with `tpl`, as `<name with dots and underscores replaced by dashes>` keys                 |
| `templates/configmap.yaml`       | One ConfigMap per `config.<name>` map (env for `common`)                                                               |
| `templates/deployment.yml`       | `replicaCount.default` replicas, `command` from values plus the computed flags (`-cluster-domain`, `-metrics-addr`, `-health-probe-addr`, `-enable-leader-election` always (two CSR-signer-only replicas would both sign), `-approve`/`-approve-allowed-names` or `-disable-csr-signer`, `-enable-operator`, the `-webhook-*` flags), ports `metrics` (`metricsPort`), `health` (`healthProbePort`) and `webhook`, readiness probe `GET /readyz` on `health` (the webhook server accepts TLS), mounts `/kubeca/etc` (ConfigMap), `/kubeca/certs` (Secret `kubeca.certsSecretName`, external) and `/kubeca/webhook` (emptyDir), optional pull secrets, node selector, tolerations, affinity |
| `templates/serviceaccount.yaml`  | ServiceAccount with annotations (IRSA)                                                                                |
| `templates/role-csr-signer.yaml` | `kubeca:csr-signer` ClusterRole (with the approver rules) and the opt-in `kubeca:csr-creator`                         |
| `templates/role-operator.yaml`   | `kubeca:operator` ClusterRole                                                                                         |
| `templates/rolebinding.yaml`     | ClusterRoleBindings `<sa>:csr-signer` and `<sa>:operator` (no `namespace`)                                            |
| `templates/role-leader-election.yaml` | Role and RoleBinding on `leases` and events in the release namespace                                             |
| `templates/webhook.yaml`         | Webhook Service, `MutatingWebhookConfiguration` (`caBundle` left to the operator), PodDisruptionBudget                |
| `templates/admission-policy.yaml` | `ValidatingAdmissionPolicy` + binding `<fullname>-pod-certificates` when `operator.podCertificatePolicy` and the cluster serves `admissionregistration.k8s.io/v1` `ValidatingAdmissionPolicy` (1.30+; `helm template` needs `--api-versions`): CREATE/UPDATE of a Certificate with a Pod controller is denied unless the user is the operator's ServiceAccount or the UPDATE keeps the spec and the owner references; an UPDATE of a Certificate whose old object had a Pod controller must keep the spec (dropping the controller alone is allowed, the garbage collector's orphaning included). Rendered and applied by `internal/operator/envtest_test.go` |
| `templates/clusterissuer.yaml`   | One `ClusterIssuer` per `values.clusterIssuers` entry (operator mode); deleted with the release                        |
| `templates/_helpers.tpl`         | names, labels, `kubeca.serviceAccountName`, `kubeca.certsSecretName`, `kubeca.webhookConfigName`                      |

Invariants: the issuer label in `ca-config` must equal the domain part of
the `signers` `resourceNames` in the RBAC (`kubeca.svc/*`), the
`-webhook-signer` label and `ClusterIssuer.spec.issuerLabel`. The
`-webhook-service` and `-webhook-config` flags must name the chart's
Service and configuration (the deployment template computes both). The
certs Secret keys must match `values.issuers.kubeca.*` paths. The chart
roles are hand-written and compared against `config/rbac/role.yaml` by
review. Render with
`helm template kubeca examples/kubeca -f examples/kubeca/local.yaml`.

## Build, generation, images and CI

- `make generate` runs `go generate ./...` (the `controller-gen object`
  directive of `api/v1alpha1/doc.go`) and the `interface{} -> any`
  rewrite; `make manifests` runs `controller-gen crd rbac:roleName=kubeca-operator
  webhook` over `api/`, `internal/` and `cmd/` into `config/` and copies
  the CRDs into `examples/kubeca/crds`; both need `bin/controller-gen`
  (`make tools`, `CONTROLLER_GEN_VERSION` v0.20.1).
- `make envtest` downloads the control-plane binaries (`setup-envtest`,
  `SETUP_ENVTEST_VERSION` release-0.25, `ENVTEST_K8S_VERSION` 1.37.x) into
  `bin/envtest`; `KUBEBUILDER_ASSETS` is exported from `Makefile`
  (`setup-envtest use -i -p path`, empty when not installed) so
  `make test`/`covtest` run the envtest test when the binaries exist.
- `make build` produces `bin/kubeca` and `bin/kubecertinit` with
  `LDFLAGS` setting the version; `make version` prints the version string;
  `make change_log` writes `change_log.txt`; `make docker` builds
  `effectivesecurity/kubeca:main` and `effectivesecurity/kubecertinit:main`
  from distroless `nonroot` images that copy the binary and the change log
  into `/app`.
- Version string: `v<.VERSION>.<git rev-list --count>[-<hostname>]` from
  `.project/gomod-project.mk` (`GIT_VERSION`); `.VERSION` is `v0.9`.
- CI (`.github/workflows/build.yml`): on PRs and pushes to `main`, skip
  when only docs changed, then `make vars tools folders generate manifests
  envtest version change_log`, `git diff --exit-code -- api config
  examples/kubeca/crds` (generated files must be committed), `make
  fmt-check vet lint` and `make build covtest`; on `main` pushes, build and push
  both images (tags: branch, sha, semver) and create the `v<.VERSION>.<n>`
  tag when `.VERSION` changed. `settag.yml` creates a tag on demand.
  `MIN_TESTCOV=80` is declared but not enforced (ROADMAP). Dependabot
  groups `aws`, `es`, `go`, `google`, `k8s.io` (`*k8s.io/*`), actions and
  docker weekly.

## Tests

| Package                          | Tests                                                                                                                                       | Fixtures                                                                            |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `internal/operator`              | `envtest_test.go` (`TestCRDs`: CRD CEL rules, status subresource, `TestPodCertificatePolicy`), `manager_test.go` (`TestManager`: `TestPermanentFailureIsNotRetried`, `TestCABundleFollowsIssuerRef`) | envtest with `config/crd/bases` (two API servers), `testauthority`, users from `AddUser` in `system:masters`; skip without `KUBEBUILDER_ASSETS` |
| `internal/operator/policy`       | `TestEvaluate` (table, incl. `${CLUSTER_DOMAIN}`), `TestCompile`, `TestBoundDuration`                                                                                  | none; parallel                                                                      |
| `internal/operator/issuer`       | `TestReconcileLoaded`, `TestReconcileAllProfiles`, `TestReconcileNotReady`, `TestReconcileCAExpiring` (also a `maxDuration` above the profile expiry), `TestReconcileCABundle` (foreign, another ClusterIssuer's and stale-owner ConfigMaps; pruning after a deleted Certificate, a renamed and a removed `caBundle`), `TestReconcileMissing`, `TestBackdateAndRootPEM` | fake client with status subresource and the issuer index, fake recorder, fake clock, `testauthority` (`FromEntities` for the expiring CA) |
| `internal/operator/certificate`  | black box: `TestIssueAndRenew`, `TestRotationPolicyNever`, `TestDefaults`, `TestMaxDurationBounds`, `TestKubernetesNames` (dual-stack ClusterIPs), `TestPolicyViolation` (incl. common name), `TestInvalidSecretTemplate` (new and issued Certificate: `PolicyViolation`, nothing signed or rewritten), `TestServiceAccountPlaceholder` (owning Pod; forged owner with the Pod's UID and another Secret or issuer; annotation), `TestAdoptValidSecret`, `TestAdoptOpaqueSecret`, `TestRepairTrustData`, `TestStatusPatchFailure`, `TestStaleSecretCache` (the reconciler's client serves a stale Secret, the `APIReader` the current one), `TestSecretKeys`, `TestIssuerNotReady`, `TestSecretConflict`, `TestIssuanceFailedPermanent`, `TestTransientError`, `TestRenewalFailureKeepsReady`, `TestDeleted`, `TestConcurrentReconciles`; white box: `TestNeedsIssuance`, `TestRenewalTime`, `TestFormatSerial`, `TestConflictMessage`, `TestGenerateKey`, `TestNamesDrift` | fake client (status subresource, both indexes, interceptors), fake recorder, fake clock started at the real time + 30 s, `testauthority` |
| `internal/operator/pod`          | `TestReconcileCreatesCertificate`, `TestReconcileAnnotations`, `TestReconcileInvalid`, `TestReconcileSkips`, `TestReconcileAlreadyOwned`, `TestReconcileRefusesForeignCertificate` (no controller, a previous Pod of the same name), `TestInjected` | fake client, fake recorder                                                      |
| `internal/operator/metrics`      | `TestObserveCertificate` (series replaced on issuer/profile change, dropped when nothing is stored, `ForgetCertificate`), `TestObserveCertificateConcurrent` (distinct and shared Certificates from 16 goroutines) | `testutil.CollectAndCompare` on the global vectors (serial tests)                 |
| `api/v1alpha1`                   | `TestPodNames`, `TestPodNamesLength` (253-character Pod names)                                                                              | none                                                                               |
| `internal/operator/webhook`      | `TestMutate`, `TestGenerateSecretName`, `TestHandle` (admission requests → JSON patch), `TestServingCertificate` (files, caBundle patch and restore, renewal with the fake clock, errors), `TestServingCertificateCABundleFailure` (a renewal whose patches fail is not re-issued every minute) | `testauthority`, fake client, fake clock, `t.TempDir()`      |
| `internal/controller`            | see the package section                                                                                                                     | fake client, `testauthority`                                                        |
| `internal/certinit`              | see the package section                                                                                                                     | testify mocks, `watch.NewFake`, `t.TempDir()`, in-memory keys                      |
| `internal/k8snames`              | `TestSplitList`, `TestServiceNames`, `TestPodDNSName`, `TestPodIPs`, `TestSPIFFEID`, `TestForPod`, `TestSelectingServices` (empty selector ignored), `TestClusterIPs` | none; parallel                                                                      |
| `internal/signerr`               | `TestIsPermanent`                                                                                                                           | none                                                                                |
| `internal/testauthority`         | `TestNew`                                                                                                                                   | the example CA configuration                                                        |
| `internal/logr`                  | `TestLogr`                                                                                                                                  | global xlog formatter (serial)                                                      |
| `internal/version`               | `TestBuildVersion`, `TestCurrent`, `TestInfo_ParseBuild`, `TestInfo_GreaterOrEqual`                                                         | none                                                                                |

Conventions: xpki validates `NotBefore` against the real clock, and
building an Authority from `testca` entities verifies their chain against
it, so the validity of test CAs is derived from `time.Now()`, never from a
fixed date (`TestReconcileCAExpiring` failed once its fixed issuing CA
was two days old), and the fake clocks of issuance tests start at
`time.Now()` (plus 30 s in the
Certificate tests so a minute boundary during the test never puts the
issuer's window after ours); status times round-trip through JSON with
second precision, so tests compare with `UTC()` and tolerate a second;
the fake client assigns no UIDs (test objects set them) and writes the
`approval` subresource as a whole-object update. `make test RACE=true`
passes. No unit test needs a cluster, a KMS or Docker; the envtest test
needs `make envtest`.

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
- `scripts/minikube_images.sh` (docker build + `minikube image load` of
  `kubeca`, `kubecertinit` and `certmonitor`),
  `minikube_deploy.sh` (namespace, certs Secret, `kubectl apply` of the
  CRDs, `helm upgrade --install` with `examples/kubeca/minikube.yaml`,
  restart, wait for the controller and for the `caBundle` on the
  `MutatingWebhookConfiguration`), `minikube_test.sh` (operator: ClusterIssuer
  `Ready`, the previous run's Certificates and Secret deleted before the
  workload is applied so the `Ready` wait sees a fresh object,
  `e2e-api-tls` issued with `e2e-5m` and 5 m / 2 m, chain and `ca.crt`
  and the `kubeca-ca` ConfigMap against the root, the Deployment's
  certmonitor logging that certificate (`wait_monitor`: the last serial it
  printed equals the Secret's `serial` annotation), renewal to revision 2
  with a new serial and key within five minutes and the running Pod's
  certmonitor logging the renewed one, the
  injected Pod `e2e-worker` re-created on every run with its owned
  Certificate, the admission policy type-checked by kube-controller-manager
  and denying a Pod-controlled Certificate created by another user
  (`kubectl --as`); then the init container: the `web` Pod of the
  Deployment's current ReplicaSet (`current_pod`, as for `e2e-api`: an
  apply that changes the template plus a restart makes two rollouts whose
  Pods can share a creation second) and its CSR by name
  (`<pod>-<namespace>-`), the CSR
  must be `Approved`, the Pod's certmonitor loaded the init container's
  certificate, the chain of the CSR's certificate, log format; no
  `kubectl exec`: the certmonitor image is distroless), `minikube_clean.sh`
  (workloads, release, namespaces, CRDs);
  `make minikube-all`. The Pod reaches kms2 through
  `host.minikube.internal`.
- See [key-ceremony.md](key-ceremony.md) and the README.
