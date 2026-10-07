# kubeca v0.9 release notes

v0.9 ships the KubeCA operator designed in v0.8
([design/operator.md](design/operator.md),
[design/operator-api.md](design/operator-api.md)): the
`kubeca.effectivesecurity/v1alpha1` API with the `ClusterIssuer` and
`Certificate` kinds, a Certificate controller that issues short-lived
certificates into `kubernetes.io/tls` Secrets and renews them, a Pod
controller and a mutating webhook for per-Pod certificates, all in the
`kubeca` binary and chart. It also closes the findings KUBECA-001, 006,
012, 013, 014, 015, 016 and 017 of [FINDINGS.md](../FINDINGS.md) and
deprecates the init-container flow (`kubecertinit`), which keeps working.

Validation: unit tests of every controller with controller-runtime's fake
client, an in-memory Authority (`internal/testauthority`, built from the
example profiles) and the race detector (`make test RACE=true`); the CRDs
under envtest (`internal/operator/envtest_test.go`), together with the
chart's admission policy applied to that API server and checked with
separate users; the operator manager under envtest
(`internal/operator/manager_test.go`: a rejected Certificate is attempted
once); `helm lint` and `helm template`; and the minikube end-to-end test of
`scripts/minikube_test.sh` against the local-kms emulators (operator
issuance with the 5-minute `e2e-5m` profile, renewal with key rotation
about three minutes later, the injected Pod, the admission policy denying
a forged Pod-controlled Certificate, the approved CSR).
No run against a real KMS or a managed cluster; validate on a dev cluster
before rolling out.

## The operator

- **API** (`api/v1alpha1`, CRDs in `examples/kubeca/crds`): `ClusterIssuer`
  (cluster-scoped; binds an xpki issuer label to exposed profiles, a
  default profile, a SPIFFE trust domain, a policy and an optional CA
  bundle ConfigMap) and `Certificate` (namespaced; names, profile,
  duration, renewBefore, private key, secret template). CEL rules reject a
  Certificate without a name, a `renewBefore` not shorter than `duration`,
  a `duration` under 1 m or a `renewBefore` under 30 s, a key size that
  does not match the algorithm, a changed `secretName` or `issuerLabel`,
  and a `defaultProfile` outside `profiles`. `kubectl get certs` prints
  READY, SECRET, ISSUER, PROFILE, NOT AFTER, RENEWAL and AGE;
  `kubectl get cissuer` READY, LABEL, CA NOT AFTER and AGE (the
  timestamps are RFC 3339 strings: kubectl prints a future time of a
  `date` column as `<invalid>`).
- **ClusterIssuer controller** (`internal/operator/issuer`): resolves the
  issuer in the Authority, checks the exposed and default profiles and
  compiles the policy (`Ready=False` with `IssuerNotFound`,
  `ProfileNotFound` or `InvalidPolicy`), publishes the issuing certificate,
  the root bundle, the subject key id, the CA expiry and the profiles in
  the status, flags `CAExpiring` (`Ready` stays `True`; issued certificates
  are clipped to the CA expiry) and `CAExpired`, and maintains the
  `ca.crt` ConfigMap of `spec.caBundle` in every namespace that holds a
  Certificate of the issuer.
- **Certificate controller** (`internal/operator/certificate`): the
  issuance pipeline of the design. It generates the key (ECDSA P-256 by
  default; RSA on request; a new key on every issuance unless
  `rotationPolicy: Never`), builds a CSR carrying the names so the xpki
  profile regexes and `allowed_fields` apply, signs with an explicit
  validity window (`NotBefore = now − backdate`, `NotAfter = NotBefore +
  duration`, bounded by the profile expiry and the policy `maxDuration`),
  writes the Secret (`tls.crt` leaf plus issuer chain, `tls.key`, `ca.crt`
  root bundle, provenance annotations including `issued-at`, the
  `managed=true` label, a controller owner reference) and requeues itself
  at `renewalTime` (`notAfter − renewBefore − jitter`, never sooner than a
  minute after the issuance; recomputed on every reconcile from the stored
  certificate, so a `renewBefore` change applies without re-issuing). A
  `duration` that leaves less than 2 minutes of usable lifetime after the
  profile `backdate` is a `PolicyViolation` (the minikube run found a
  certificate re-issued in a loop otherwise). It re-issues when the Secret is
  missing or invalid, the key does not match, a renewal was requested
  (`kubeca.effectivesecurity/renew-requested`), the CA changed, the spec
  drifted or the renewal time passed; a `secretTemplate` change is applied
  in place. Policy violations, issuer problems, Secret conflicts and
  requests xpki rejects are recorded in the `Ready` condition and an
  event without retry; API and KMS errors are retried with backoff while
  a still-valid certificate keeps `Ready=True`.
- **Pod controller** (`internal/operator/pod`): creates a `Certificate`
  owned by every Pod labeled `kubeca.effectivesecurity/inject=true` with
  the Pod's DNS name, hostname/subdomain name, the names and IPs of the
  Services that select it, its IP, the SPIFFE ID of its ServiceAccount and
  the `san` annotation; `issuer`, `profile`, `secret-name`, `duration` and
  `renew-before` annotations parametrize it; the Certificate follows the
  Pod IP and the Services.
- **Webhook** (`internal/operator/webhook`, `-enable-webhook`): mutates
  labeled Pods on CREATE with the Secret name annotation (`<name>-tls`, or
  `kubeca-<8 random>` for `generateName` Pods), the Secret volume and the
  mounts (`mount-path`, `containers` annotations). Its serving certificate
  is issued in process from the Authority with the `webhook` profile,
  renewed at two thirds of its lifetime, and the `caBundle` of the
  `MutatingWebhookConfiguration` is patched at start, after each renewal
  and whenever it is found empty (every minute, which covers a `helm
  upgrade`).
- **Metrics**: `kubeca_certificate_expiration_timestamp_seconds`,
  `kubeca_certificate_renewal_timestamp_seconds`, `kubeca_certificate_ready`,
  `kubeca_issuance_total{issuer,profile,trigger,result}`,
  `kubeca_issuance_duration_seconds` and
  `kubeca_clusterissuer_ca_expiration_timestamp_seconds` on the existing
  `/metrics`.
- **Process**: one manager. Leader election is on by default with
  `-enable-operator`; the webhook serves on every replica. The informer
  caches hold only managed Secrets and ConfigMaps and labeled Pods, and
  strip `managedFields`.

## Fixes

### Operator (pull-request review)

- **KUBECA-014**: the policy placeholder `${SERVICE_ACCOUNT}` trusted a
  Pod owner reference with the Pod's UID and the expected name, both of
  which a Certificate author can write, so another ServiceAccount's
  identity could be issued into a Secret of the author's choice. The chart
  now ships a `ValidatingAdmissionPolicy` (`templates/admission-policy.yaml`,
  value `operator.podCertificatePolicy`, Kubernetes 1.30 or later) that
  denies creating a Certificate controlled by a Pod, or changing its spec
  or owner references, to everyone but the operator's ServiceAccount;
  annotating it (`renew-requested`) and dropping the Pod as controller
  stay allowed, the latter only in an update that keeps the spec. The controller also requires the Certificate's
  `secretName` and issuer to be the ones derived from the Pod, so without
  the policy a forged owner can only have the Pod's identity written into
  the Pod's own Secret.
- **KUBECA-015**: a permanent issuance failure (a request xpki rejects)
  recorded `failedAttempts` in the status, and that status update
  enqueued the Certificate again: an unchanged Certificate was signed and
  rejected in a tight loop (16 times in 50 ms under a real manager), and
  transient errors skipped the backoff the same way. The Certificate
  watch now passes only changes of the spec, the annotations and the
  owner references (`CertificateChanged`); dependency watches (Secret,
  ClusterIssuer, Service, Namespace) are unchanged.
- **KUBECA-016**: removing or replacing `ca.crt`, or the issuer chain
  after the leaf in `tls.crt`, left the damage in place while the
  Certificate stayed `Ready`. An up-to-date Secret now gets both back
  from the ClusterIssuer without a re-issuance (the leaf and the key
  stay), with one `WARNING` line (`status=secret_repaired`).
- **KUBECA-017**: an Opaque Secret labeled `adopt=true` whose certificate
  and key matched was adopted and marked `Ready`, and its next renewal
  failed (a Secret's type is immutable). A Secret that is not
  `kubernetes.io/tls` is now a `SecretConflict` before any decision.
- Removing the `renew-requested` annotation after a request renews once
  and clears `status.lastRenewRequest`; it used to leave the old value in
  the status, so repeating that value later did not renew.
- The Secret and Certificate names derived for a Pod whose name is close
  to the 253-character limit end with a hash instead of exceeding it.
- The webhook logs each admitted Pod at `DEBUG` (it was `INFO`).
- The Secret is written before the status patch. When that patch failed,
  the retry counted the issuance again and, for a renewal request,
  issued a second certificate because the request still differed from
  the stale status. The Secret now records the request it honoured
  (annotation `renew-requested`), and a reconcile takes `status.revision`
  and `status.lastRenewRequest` from the Secret when the Secret is ahead.
- A `caBundle` ConfigMap controlled by another ClusterIssuer with the same
  `configMapName` was taken for ours because both carry the managed label;
  the controller then failed on the owner reference and retried for ever.
  It is now a `ConfigMapConflict` event like any foreign ConfigMap.
- The webhook serving certificate returns an error, instead of panicking,
  when it is given no DNS name.
- CA bundle ConfigMaps are pruned: the ClusterIssuer deletes the ones it
  owns in a namespace without any of its Certificates, under a previous
  `caBundle.configMapName`, or all of them when `caBundle` is removed
  (they used to stay until the ClusterIssuer was deleted). Moving a
  Certificate to another issuer now reconciles both issuers, so the new
  one publishes its bundle at once (Certificate updates were all ignored).
  The operator ClusterRole gains `delete` on ConfigMaps.
- `CAExpiring` is computed against the longest certificate the issuer can
  sign: the longest profile expiry, or `maxDuration` when shorter. A
  `maxDuration` above the profile expiry used to raise the warning early.
- `status.profiles` is sorted by name as documented; an explicit
  `spec.profiles` list was copied in the user's order.
- The `kubeca_certificate_expiration_timestamp_seconds` series of a
  Certificate on the issuer's default profile carries that profile's name
  (it had `profile=""`).
- An unparsable `duration` annotation on a managed Secret is drift and
  re-issues; it was ignored.
- A ClusterIssuer policy with several invalid expressions reports the
  same first error on every reconcile (the fields were checked in map
  order, so the condition message could change and trigger reconciles).
- The Pod controller no longer takes over an existing Certificate with
  the Pod's Certificate name that the Pod does not control. It adopted
  one without a controller, so anyone who could create a labeled Pod
  could rewrite another workload's Certificate and its Secret and have
  them garbage-collected with the Pod. Such a Certificate is now an
  `InvalidPod` event; one left by a previous Pod of the same name is
  retried until the garbage collector removes it.
- Before signing, a Secret read from the informer cache is read again
  from the API server: the cache can lag the controller's own last
  write, and the retry after a failed status patch could then sign again.
- The webhook serving certificate no longer re-issues every minute when
  only the caBundle patch fails after a renewal (an admission API or RBAC
  problem): the renewal keeps its schedule and the minute check retries
  the patch.
- The chart always passes `-enable-leader-election`: with
  `operator.enabled: false` and the default two replicas, both replicas
  ran the CSR signer and signed the same CSRs.
- The admission policy also checks the Certificate before the update: a
  user could drop the Pod as controller and rewrite the spec in the same
  update, which the policy evaluated as a plain Certificate. Dropping the
  controller now has to keep the spec (the garbage collector's orphaning
  does); a later update of the then plain Certificate is allowed, and
  `${SERVICE_ACCOUNT}` no longer expands for it.
- A `secretTemplate` label or annotation the API server rejects on the
  Secret is a `PolicyViolation` before signing. The CRD accepts any
  string, and the Secret write that failed after each signature was
  retried as a transient error, signing again every time.
- The policy placeholder `${CLUSTER_DOMAIN}` expands to the operator's
  `-cluster-domain`, and the chart's default ClusterIssuer uses it: with
  `clusterDomain` set to anything but `cluster.local`, the names the
  operator derived were denied by its own default policy.
- `TestReconcileCAExpiring` built its issuing CA from a fixed date and
  started failing once that CA had expired in real time; test CA validity
  now follows `time.Now()`.

### CSR signer (`kubeca`)

- **KUBECA-001**: the in-process approver. `-approve=enforce` approves a
  CSR when the requester is a ServiceAccount and every name (DNS, IP, URI,
  email and the subject common name) is one its Pods and Services may
  carry (the Pod IP and DNS name, hostname/subdomain, the selecting
  Services' names and IPs, `spiffe://<any trust domain>/ns/<ns>/sa/<sa>`
  in its canonical form, and `-approve-allowed-names`,
  `localhost,127.0.0.1` by default), and
  denies it otherwise (`Denied`, reason `NamesNotAllowed`, the offending
  names in the message). `audit` emits a `Warning` event `ApprovalAudit`
  for a CSR that `enforce` would deny and signs it; `off`, the binary
  default, keeps the implicit approval. A CSR approved by someone else
  (`kubectl certificate approve`) is signed without evaluation; only a
  condition with status `True` is a decision, the only status the API
  server admits for `Approved`, `Denied` and `Failed`. DNS names
  and emails compare case-insensitively; a URI of
  `-approve-allowed-names` must match exactly (a URI path is
  case-sensitive).
- **KUBECA-013**: a request xpki rejects on its content (a name outside
  the profile regexes, an extension not allowed, an invalid SAN, a parse
  error) gets the `Failed` condition (reason `SigningFailed`, the error as
  message) and is not retried; provider and API errors are still retried
  with backoff. `kubecertinit` exits 2 on `Failed`.
- The manager is built in `cmd/kubeca` (`run.go`);
  `controller.LoadAuthority` replaces `StartCertificateSigningRequestController`.
  Flags: `-disable-csr-signer`, `-approve`, `-approve-allowed-names`,
  `-cluster-domain`, `-enable-operator`, `-enable-webhook`,
  `-webhook-port`, `-webhook-cert-dir`, `-webhook-service`,
  `-webhook-namespace`, `-webhook-signer`, `-webhook-config`,
  `-health-probe-addr` (`/healthz`, and `/readyz`, which waits for the
  webhook server to accept TLS connections; default `:8081`).

### Init container (`kubecertinit`, deprecated)

- **KUBECA-006**: the wait for the certificate watches the CSR (a
  field-selected watch from the CSR's resource version, reopened when it
  ends) instead of polling every 5 s; polling remains the fallback when
  the watch cannot be opened or reports an error event. `-timeout` defaults to 10 minutes: the init
  container exits 2 and the kubelet restarts it with backoff instead of a
  Pod stuck in `Init` for ever (`-timeout=0` restores the old behaviour).
- The name derivation moved to `internal/k8snames`, shared with the
  approver and the Pod controller; no behaviour change.
- `cmd/kubecertinit` is marked `Deprecated` in its package comment;
  `internal/certinit` says in prose that the flow is deprecated since v0.9
  and kept for the migration (a `Deprecated:` marker there would make
  staticcheck flag the command that imports it).

### Chart (`examples/kubeca` 0.2.0)

- **KUBECA-012**: `autoscaling` is gone; the certs Secret is `certs.secretName`
  (default `<fullname>-certs-secret-tf`, documented in `values.yaml`, still
  created outside the chart); the `kubeca:csr-approver` ClusterRole and
  its binding are gone, their rules merged into `kubeca:csr-signer`
  (approval, `approve` on the signers, Pods and Services); the
  `kubeca:csr-creator` ClusterRole workloads bind to can be rendered by
  the chart (`csrSigner.createCSRCreatorRole`, default `false`:
  `examples/initcontainer/rbac.yaml` creates the same ClusterRole and Helm
  refuses to adopt an object it did not create).
- New: `crds/`, the `kubeca:operator` ClusterRole, the webhook Service and
  `MutatingWebhookConfiguration` (`<fullname>-pod-injector`), a
  `PodDisruptionBudget` when `replicaCount.default > 1` (now `2` by
  default, since the webhook's `failurePolicy: Fail` blocks labeled Pods
  while no replica serves), the `webhook`
  profile and `extraProfiles` in `etc/ca-config.kubeca.yaml`, and the
  values `clusterDomain`, `metricsPort`, `csrSigner.*`, `operator.*`,
  `certs.secretName`, `extraProfiles`, `clusterIssuers`. The Deployment
  appends the flags computed from those values after `values.command`.
- `image.tag` defaults to `main` (the image CI pushes on every push to
  `main`); the previous `sha-225d04f` image does not know the new flags.
  Pin a `sha-<commit>` or `v0.9.<n>` tag in production.
- The default ClusterIssuer policy accepts IPv6 Pod DNS names
  (`^[0-9a-f-]+\.${NAMESPACE}\.pod\.${CLUSTER_DOMAIN}$`) and follows
  `clusterDomain` (`${CLUSTER_DOMAIN}`).
- The Deployment has a readiness probe (`GET /readyz` on the `health`
  port, `healthProbePort`, default 8081): the webhook Service only routes
  admission requests to replicas whose webhook server is up, and a
  rollout keeps an old replica until then.
- `templates/admission-policy.yaml` (KUBECA-014) with
  `operator.podCertificatePolicy` (default `true`); Helm renders it when
  the cluster serves `ValidatingAdmissionPolicy` (`helm template` needs
  `--api-versions admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy`).

### Code and build

- `internal/controller` and `internal/certinit` use
  `github.com/cockroachdb/errors`; `github.com/pkg/errors` is no longer
  imported.
- Tests: controller tests for the CSR signer and the approver, tests of
  every operator package, `internal/k8snames`, `internal/signerr`,
  `internal/testauthority`, and the envtest CRD test;
  `TestObserveCertificateConcurrent` races the metrics bookkeeping the
  Certificate workers share.
- Every package has its package comment in a handwritten `doc.go`
  (`internal/operator/index`, `internal/operator/metrics`,
  `internal/signerr` and `internal/testauthority` had it in their main
  file).
- Review fixes before release: owner references are set without
  `blockOwnerDeletion` (no `finalizers` RBAC needed under the
  `OwnerReferencesPermissionEnforcement` admission plugin); a changed
  `duration` or `maxDuration` re-issues (Secret annotation `duration`);
  a set `secretName` can no longer be removed (CEL); namespace label changes
  re-evaluate the policy (Namespace watch); an adopted Secret that needs
  no re-issuance still gets the owner reference; a labeled Pod with no
  name source gets an `InvalidPod` event instead of waiting for an IP it
  cannot get.
- Pull-request review fixes (#144): the policy placeholder
  `${SERVICE_ACCOUNT}` is the ServiceAccount of the Pod that controls the
  Certificate (how that control is established: KUBECA-014 above), never
  an annotation a Certificate author could set (the `service-account`
  annotation is gone); `spec.commonName` must
  match the policy's `allowedDNSNames` (xpki signs the trusted subject as
  given and the shipped profiles set no `allowed_names`); the CSR approver
  accepts the SPIFFE ID of the requester only in its canonical form (no
  user info, port, query, fragment or percent-encoding); a Service with an
  empty selector selects no Pod (it used to match every Pod of the
  namespace); dual-stack Services contribute both `spec.clusterIPs`
  (`includeClusterIP`, the Pod flow, the approver, `kubecertinit`); the
  `kubeca_certificate_expiration_timestamp_seconds` series of a
  Certificate that changed issuer or profile is dropped instead of
  lingering with the old `notAfter`; `api/v1alpha1` no longer imports
  `k8s.io/api`; the chart defaults to two replicas; the minikube test
  deletes the previous run's Certificates before applying the workload
  and checks the newest `web` Pod and CSR (it used to pick them by name,
  which could be the previous run's terminating Pod, and skipped the
  approval check silently).
- `cmd/certmonitor`, a test tool: it watches a key pair (porto's
  `tlsconfig` reloader) and prints the certificate at start and on every
  renewal (`-root` optional: it never connects). The workloads of
  `examples/shop` and the init-container dummy deployment run it instead
  of busybox; `examples/shop/pod.yaml` with a 15-minute certificate
  renewed every 3 to 5 minutes. The minikube test reads the monitors'
  logs and the Secrets instead of `kubectl exec` (the image is
  distroless) and also checks that the running Pod logs the renewed
  certificate;
  `Dockerfile.certmonitor` is built and loaded into minikube by
  `make minikube-images` (`make build_certmonitor`) and is not published
  by CI.
- Tooling: `controller-gen` and `setup-envtest` pinned in `Makefile`;
  `make generate` (deepcopy), `make manifests` (CRDs, RBAC, webhook into
  `config/`, CRDs into the chart), `make envtest`; `goveralls` removed
  from `make tools`.
- CI (`.github/workflows/build.yml`) now runs `make manifests envtest`,
  fails when the generated `api/`, `config/` or chart CRDs are not
  committed, and runs `make fmt-check vet lint` before the tests.
- The CSR approver and the Pod controller use every Pod address
  (`status.podIPs`), so a dual-stack Pod's second address is allowed.

## What deployments must do

1. Install the CRDs. Helm applies `crds/` on install but never on upgrade:
   run `kubectl apply -f examples/kubeca/crds/` before `helm upgrade`
   (`scripts/minikube_deploy.sh` does exactly that).
2. Review the chart values. The operator and the webhook are enabled by
   default (`operator.enabled`, `operator.webhook.enabled`) and the CSR
   signer runs with `csrSigner.approve: enforce`. On a cluster with CSR
   clients whose names the approver cannot derive, set `csrSigner.approve:
   audit`, watch the `ApprovalAudit` events, then switch to `enforce`.
   `csrSigner.allowedNames` lists the names every requester may use.
3. RBAC: `helm upgrade` creates `kubeca:operator` and extends
   `kubeca:csr-signer`; the `kubeca:csr-approver` ClusterRole and the
   `<serviceaccount>:csr-approver` ClusterRoleBinding are deleted. Clusters
   that granted them outside the chart can drop them.
4. The chart now runs two replicas (`replicaCount.default: 2`): the
   `MutatingWebhookConfiguration` uses `failurePolicy: Fail`, so labeled
   Pods are rejected while no replica serves; the PDB keeps one up during
   a rollout. Set `1` only with `operator.webhook.failurePolicy: Ignore`
   or without the webhook.
5. Review `values.clusterIssuers`: the chart creates the `ClusterIssuer`
   `kubeca` for the `kubeca.svc` issuer with the short-lived profiles
   (`peer-24h`, `server-24h`, `client-24h` are in the chart's CA
   configuration), a `cluster.local` SPIFFE trust domain and a policy that
   selects namespaces labeled `kubeca.effectivesecurity/enabled=true`.
   Its DNS expressions use `${CLUSTER_DOMAIN}`; copy that into your own
   `clusterIssuers` instead of a literal `cluster\.local`.
   Then deploy `Certificate` objects or the inject label per workload
   (`examples/shop`, README "Migrating from the init container").
   Applications must reload `tls.crt`/`tls.key` when the files change.
6. Init containers without `-timeout` now exit after 10 minutes of waiting;
   pass `-timeout=0` to keep waiting for ever, or fix the cause (`kubectl
   describe csr` shows the `Denied` or `Failed` reason).
7. `extraProfiles` adds profiles without editing the chart; the `webhook`
   profile pins `allowed_dns` to the webhook Service name and must exist
   when the webhook is enabled (it does in the shipped configuration).
8. On Kubernetes 1.30 or later the chart installs the
   `<fullname>-pod-certificates` `ValidatingAdmissionPolicy`: nobody but the
   operator can create a Certificate controlled by a Pod or change its
   spec or owner (dropping the Pod as controller is allowed in an update
   that keeps the spec). Tools that copied such Certificates (backup restores
   that keep owner references, for example) must drop the owner
   reference. On older clusters the policy is not rendered; policies that
   use `${SERVICE_ACCOUNT}` then rely on the controller's binding of the
   Certificate to the Pod's own Secret and issuer.

## Behaviour changes to be aware of

| Area                    | Change                                                                                                         | Who notices                                              |
| ----------------------- | -------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| CSR approval            | With the chart default `enforce`, a CSR with names the requester may not have is `Denied`                      | CSR clients using names outside their Pods and Services  |
| `Failed` condition      | A request xpki rejects is marked `Failed` once instead of retried for hours                                    | `kubectl get csr`, init containers (exit 2 at once)      |
| `kubecertinit -timeout` | Default 10 m                                                                                                   | Pods that waited for ever in `Init`                      |
| Chart objects           | New CRDs, ClusterRole, Service, MutatingWebhookConfiguration; `csr-approver` role and binding removed           | `helm upgrade`, cluster admins                           |
| Leader election         | On by default with `-enable-operator` (the chart grants the Lease role already)                                | Nobody; single replicas elect themselves                  |
| Logs                    | New `INFO` lines per issuance (`status=issued`) and per approval, `DEBUG` per webhook injection; keys `trigger`, `serial` | Log consumers                                          |
| Admission               | A Certificate controlled by a Pod can only be created or changed (spec, owners) by the operator                | Users and tools that write such Certificates            |
| Readiness               | `/readyz` gates the Pods; a replica is ready once its webhook server answers                                   | Rollouts, the PodDisruptionBudget                        |
| CA bundle ConfigMaps    | Deleted from a namespace once the issuer has no Certificate there, and when `caBundle` is renamed or removed   | Workloads that mount the bundle without a Certificate of their own in that namespace |

## Still open

KUBECA-003 (key file mode of the init container, decision pending) in
[FINDINGS.md](../FINDINGS.md); batch P7 of [PLAN.md](../PLAN.md) and the
items of [ROADMAP.md](../ROADMAP.md).
