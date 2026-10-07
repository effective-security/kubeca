# KubeCA Operator

Status: implemented in v0.9 (2026-10-06). API: [operator-api.md](operator-api.md).
Remaining work: [`PLAN.md`](../../PLAN.md) (batch P7). Examples:
[`examples/shop`](../../examples/shop) (application side) and the
`ClusterIssuer` of the chart (`examples/kubeca`, `values.clusterIssuers`).
Code: `api/v1alpha1`,
`internal/operator` and its sub-packages, wired by `cmd/kubeca`
(`-enable-operator`, `-enable-webhook`).

## Goals

- Issue **short-lived** certificates (target 24 h) to workloads and **renew
  them automatically** before expiry, without restarting Pods.
- Make the certificate a Kubernetes object (`Certificate`) with a status an
  operator can read, alert on and act on.
- Enforce policy per namespace and ServiceAccount, not only per CA profile.
- Keep the CA key in KMS/HSM and keep xpki as the signing engine with the
  v1.0 contract ([xpki-1.0-conformance.md](../xpki-1.0-conformance.md)).
- Keep the existing CSR flow working during migration.

Not in this release: keys that never leave the Pod (CSI driver or in-Pod
CSR mode), revocation (short lifetimes replace it), CA key rotation
without a restart, a namespaced `Issuer` kind (see "Future work").

## Overview

```text
                 Kubernetes API
                       │
             ┌─────────┴─────────┐
             │                   │
             ▼                   ▼
      Certificate CR       ClusterIssuer CR
      (namespaced)         (policy, profiles, CA)
             │                   │
             └─────────┬─────────┘
                       ▼
                KubeCA Operator  (kubeca binary, same manager as the CSR signer)
                       │
             reconciliation loops
                       │
     ┌──────────┬──────┴─────┬─────────────┐
     ▼          ▼            ▼             ▼
  Secret     xpki CA       KMS/HSM     Pods (watch, inject)
 (tls.*)   (profile,     (CA key)
           Sign)
     │
     ▼
    Pod (secret volume, app reloads files)
```

| Requirement                           | Mechanism                                                                                                                    |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Watch Pods and react                  | Pod controller on Pods labeled `kubeca.effectivesecurity/inject=true`; mutating webhook on Pod `CREATE` for the volume and mounts |
| Watch Secrets and renew them          | Certificate controller `Owns` its Secrets; `RequeueAfter` at the renewal time; drift detection on every reconcile            |
| Add `Certificate` API                 | CRDs `Certificate` (namespaced) and `ClusterIssuer` (cluster-scoped), group `kubeca.effectivesecurity`, `v1alpha1`           |
| Manage complete certificate lifecycle | Issue → store → renew → rotate key → re-issue on spec/CA change → garbage-collect with the owner                            |

## Components

All run in the existing `kubeca` process (D-3): one controller-runtime
manager, one xpki `authority.Authority`, one KMS session, one metrics
endpoint, one leader election (on by default in operator mode). Flags:
`-enable-operator`, `-enable-webhook`, `-disable-csr-signer`,
`-cluster-domain`, `-webhook-port`, `-webhook-cert-dir`,
`-webhook-service`, `-webhook-namespace`, `-webhook-signer`,
`-webhook-config`.

| Component                | Package                         | Watches                                                                          | Writes                                                                        |
| ------------------------ | ------------------------------- | -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| ClusterIssuer controller | `internal/operator/issuer`      | `ClusterIssuer`; Certificate create/delete and issuer changes (for the CA bundle ConfigMaps) | `ClusterIssuer.status` (Ready, CA cert, root, SKID, profiles), CA ConfigMaps  |
| Certificate controller   | `internal/operator/certificate` | `Certificate`, owned `Secret`s, `ClusterIssuer` and `Service` (mapped by index)  | `Secret` (`kubernetes.io/tls`), `Certificate.status`, Events                  |
| Pod controller           | `internal/operator/pod`         | Pods with the inject label; Services and ClusterIssuers (mapped to the Pods)     | `Certificate` owned by the Pod                                                |
| Pod mutating webhook     | `internal/operator/webhook`     | Pod `CREATE` with the inject label                                               | Secret-name annotation, volume and mounts on the Pod; the webhook `caBundle`  |
| Policy                   | `internal/operator/policy`      | pure functions                                                                   | nothing; shared by the Certificate controller                                 |
| Indexes, metrics         | `internal/operator/index`, `metrics` | field indexes on Certificates; Prometheus registry                          | nothing                                                                       |
| Names                    | `internal/k8snames`             | pure functions                                                                   | nothing; shared with the approver and `certinit`                              |
| Wiring                   | `internal/operator` (`Setup`)   | scheme, cache selectors, webhook server                                          |                                                                               |
| CSR signer (existing)    | `internal/controller`           | `CertificateSigningRequest`                                                      | approval, `Failed` condition, `status.certificate`                            |

The `authority.Authority` and `Issuer.Sign` are safe for concurrent use
(XPKI-055), so the Certificate controller runs with
`MaxConcurrentReconciles` 4.

## Issuance pipeline

```mermaid
sequenceDiagram
    participant U as user / Pod controller
    participant API as Kubernetes API
    participant CC as Certificate controller
    participant X as xpki Issuer
    participant K as KMS
    U->>API: create Certificate (issuerRef, profile, names, duration)
    API-->>CC: event
    CC->>API: get ClusterIssuer; Ready? policy(namespace, names, duration)?
    CC->>CC: generate key (ECDSA P-256 default), build CSR with the validated names
    CC->>X: Sign(SignRequest{Request, Profile, Subject, NotBefore, NotAfter})
    X->>K: sign
    X-->>CC: leaf PEM
    CC->>API: create/update Secret (tls.crt, tls.key, ca.crt; ownerRef Certificate)
    CC->>API: patch status (Ready=True, notAfter, renewalTime, serial, revision)
    CC->>API: event Issued / Renewed
    Note over CC: RequeueAfter = renewalTime − now
```

Step details:

1. **Resolve the issuer.** A `secretTemplate` label or annotation the
   API server would reject on the Secret is a `PolicyViolation` first, so
   a bad template never costs a signature. `spec.issuerRef.name` →
   `ClusterIssuer`; it must
   be `Ready` and expose `spec.profile` (or its `defaultProfile`), and the
   xpki issuer must serve that profile. Otherwise `IssuerNotReady` with a
   requeue in 1 min (the ClusterIssuer controller also enqueues every
   Certificate of an issuer when the issuer's status changes): `Ready`
   goes `False` only when the Secret holds no valid certificate; a still
   valid one keeps `Ready=True` and only `Issuing=False/Failed` carries
   the message, so a transiently missing issuer does not alert on a
   workload that is not affected until its renewal. A profile problem is
   a `PolicyViolation`.
2. **Assemble and evaluate the names.** The spec names plus the Service
   names of `kubernetesNames` (a missing Service is
   `PolicyViolation/ServiceNotFound`, retried when the Service appears)
   are validated with `csr.ParseSAN`, checked against the profile's
   `allowed_fields` per name type, and then against the policy
   (`internal/operator/policy`): namespace selector, allowed DNS/URI/email
   regexes with `${NAMESPACE}`, `${NAME}`, `${SERVICE_ACCOUNT}` and
   `${CLUSTER_DOMAIN}` (the operator's `-cluster-domain`) substituted
   (the common name is checked against the DNS regexes: xpki signs the
   trusted subject as given), `allowIPAddresses`.
   `${SERVICE_ACCOUNT}` is the ServiceAccount of the Pod that controls the
   Certificate, read from the cache and accepted only when the
   Certificate is the one the Pod controller writes for that Pod: the
   owner reference carries the Pod's UID, and the name, `secretName` and
   issuer are derived from the Pod. It is never taken from the
   Certificate's own fields, whose author could claim any ServiceAccount
   of the namespace. Owner references are written by the author as well,
   so the chart's `ValidatingAdmissionPolicy` lets only the operator's
   ServiceAccount create a Certificate controlled by a Pod or change its
   spec or owners (Kubernetes 1.30 or later); dropping the Pod as
   controller is allowed only in an update that keeps the spec. Without
   the policy, the
   binding to the Pod's own Secret means a forged owner yields nothing
   its author could not already read. A
   violation sets `Ready=False`,
   `reason=PolicyViolation`, emits a `Warning` event and returns
   **without error** (no retry until the spec, the issuer or the
   namespace changes). The xpki profile regexes still apply as a second
   gate at signing.
3. **Decide whether to issue** (`needsIssuance`, a pure function with
   table tests), in this order:
   - no Secret, or `tls.crt`/`tls.key` missing or unparsable, or a key that
     does not match the certificate (`Initial` for a Certificate that was
     never issued, `SecretMissing` otherwise);
   - the annotation `kubeca.effectivesecurity/renew-requested` differs
     from `status.lastRenewRequest` (`Requested`);
   - the certificate's authority key id differs from the ClusterIssuer's
     `status.issuerKeyID` (`CAChanged`);
   - the certificate does not match the spec: issuer or profile (the
     Secret's annotations), common name, names, key algorithm/size, the
     key usages the profile implies (`SpecChanged`);
   - the certificate expired, or `now ≥ renewalTime` (`Renewal`).
     The reason becomes the `Issuing` condition reason and the metric
     `trigger` label. A Secret that exists and is not ours is a
     `SecretConflict` before this step (see "Secret conflicts").
4. **Key.** Generate a new key for every issuance when
   `spec.privateKey.rotationPolicy=Always` (default), reuse the Secret's
   key with `Never` when it matches the algorithm and size. Algorithms:
   ECDSA (256/384/521) and RSA (2048/3072/4096).
5. **CSR.** The common name and every name go into the CSR
   (`x509.CreateCertificateRequest`). The request `SAN` of xpki's
   `SignRequest` is **not** used: xpki applies a request SAN after the
   profile regex checks, so names must travel in the CSR for
   `allowed_dns`/`allowed_uri`/`allowed_email` and `allowed_fields` to
   apply. The common name is also passed as the trusted request `Subject`.
6. **Validity** (XPKI-054). Read the profile from the issuer
   (`Issuer.Profile(name)`):

   ```text
   backdate  = profile.backdate (default 5m)
   lifetime  = min(spec.duration or profile.expiry, profile.expiry, issuer policy maxDuration)
   notBefore = now.Truncate(1m) − backdate        // the earliest the issuer accepts
   notAfter  = notBefore + lifetime
   ```

   Both times are set explicitly in the `SignRequest`; the clock is read
   right before `Sign` so the issuer's own minute never ends before ours
   (a window rejection is classified transient and recomputed). The usable
   time is `lifetime − backdate`; a lifetime that leaves less than 2
   minutes of it is a `PolicyViolation` (otherwise the certificate would
   be renewed in a loop). `status.notAfter` is read from the issued
   certificate (the issuer clips it to the CA's `NotAfter`).

7. **Sign.** `Issuer.Sign`. The issued certificate must carry exactly the
   requested names; a profile that dropped a name type is a permanent
   `IssuanceFailed`. Errors are classified by `internal/signerr`: xpki
   policy and parse errors are permanent (`IssuanceFailed`, no retry,
   event), provider/KMS errors are transient (returned, exponential
   backoff, `failedAttempts++`, `lastFailureTime`; `Ready` stays `True`
   while a still-valid certificate is stored).
8. **Store.** `Secret` of type `kubernetes.io/tls` named `spec.secretName`
   (default: the Certificate name) with `tls.crt` (leaf + issuer chain, the
   same bytes the CSR signer writes), `tls.key` (PEM), `ca.crt` (the
   ClusterIssuer's `status.rootCertificate`), the label
   `kubeca.effectivesecurity/managed=true`, the annotations listed in the
   API document (`certificate`, `issuer`, `profile`, `serial`,
   `not-before`, `not-after`, `issued-at`, `revision`), the
   `secretTemplate` labels and annotations, and a controller owner
   reference to the Certificate (without `blockOwnerDeletion`, so the
   operator needs no `finalizers` permission; the same for the Pod- and
   ClusterIssuer-owned objects). An adopted Secret whose certificate
   already matches gets the reference without a re-issuance. The type is
   set on creation only; an existing Secret of another type is a permanent
   conflict.
9. **Status and signals.** Patch `status` (conditions `Ready`, `Issuing`;
   `notBefore`, `notAfter`, `renewalTime`, `serialNumber`, `issuerLabel`,
   `issuerKeyID`, `revision+1`, `failedAttempts=0`, `lastRenewRequest`),
   emit `Issued` or `Renewed`, update the metrics, log one `INFO` line
   (`ns`, `name`, `issuer`, `profile`, `serial`, `not_after`,
   `renewal_time`, `trigger`, `revision`).
10. **Schedule.** Return `RequeueAfter = renewalTime − now`. The informer
    resync and the Secret watch are the safety nets.

## Renewal and Secret watch

- **Renewal time.** `renewBefore` defaults to a third of `duration`
  (24 h → 8 h). `renewalTime = notAfter − renewBefore − jitter`; the jitter
  is deterministic per certificate (FNV hash of the serial modulo 10 % of
  `renewBefore`), so several replicas agree and a fleet issued at the
  same time does not renew at the same second. A `renewBefore` that is
  not shorter than the certificate's actual lifetime (the issuer may
  clip it to the CA expiry) falls back to a third of that lifetime, and
  the renewal is never scheduled sooner than one minute after the
  issuance recorded in the Secret's `issued-at` annotation. The renewal
  time is recomputed on every reconcile from the stored certificate, so a
  `renewBefore` change applies in place.
- **Secret deleted.** `Owns(&corev1.Secret{})` enqueues the Certificate;
  `needsIssuance` sees `SecretMissing` and re-issues at once with a new key.
- **Secret edited.** The same watch runs the drift check; a certificate
  that no longer matches the key or the spec is re-issued. The controller
  never "repairs" foreign edits silently: it re-issues and logs the trigger.
- **Spec changed.** Names, profile, duration (the requested lifetime
  recorded in the Secret's `duration` annotation, so a tightened
  `maxDuration` counts too and a CA-clipped certificate does not loop),
  key parameters trigger `SpecChanged`. `renewBefore` and
  `secretTemplate` changes do not re-issue (status and Secret metadata
  are updated in place). A namespace label change re-evaluates the policy
  of the namespace's Certificates (Namespace watch).
- **CA changed.** When the ClusterIssuer's CA certificate changes (restart
  with a new issuer certificate), the ClusterIssuer controller's status
  update enqueues every Certificate of that issuer; the AKI check re-issues
  them, spread by the jitter.
- **Manual renewal.** Annotate the Certificate with
  `kubeca.effectivesecurity/renew-requested=<any new value>`. Removing the
  annotation afterwards renews once more and clears
  `status.lastRenewRequest`, so a later request may reuse a value.
- **Outage budget.** A certificate issued at T is valid until T + 24 h and
  renewed at T + 16 h (± jitter). The operator or KMS can be down for up to
  8 h before any TLS failure. Alert on
  `kubeca_certificate_expiration_timestamp_seconds − time() < renewBefore / 2`.
- **Key rotation.** With `rotationPolicy=Always` every renewal uses a new
  key; a leaked key is valid for at most one lifetime.

### Secret conflicts

The cache only holds managed Secrets, so a miss is confirmed with an
uncached read before anything is created. A Secret is ours when it is
controlled by this Certificate, or by a Certificate of the same name that
no longer exists (a re-created Certificate adopts it), or when it has no
controller and carries the `managed=true` or `adopt=true` label. Anything
else is `SecretConflict` (`Ready=False`, event, requeue every 5 min since
the foreign Secret's deletion is not observed). An adopted Secret must be
of type `kubernetes.io/tls`.

## Pod integration

Two ways to get a Secret into a Pod, both producing a `Certificate` owned
by the Pod (garbage-collected with it):

1. **Known Pod names (bare Pods, Pods created by your own controllers,
   Jobs with a fixed name).** Label the Pod
   `kubeca.effectivesecurity/inject: "true"`, annotate it with the
   issuer and profile, and mount the Secret `<pod-name>-tls` (or the name
   given in the `secret-name` annotation) as a volume. The Pod controller
   sees the Pod, derives the names (every Pod address of `status.podIPs`
   with its DNS name,
   hostname/subdomain, selecting Services and their IPs, SPIFFE URI
   `spiffe://<trustDomain>/ns/<ns>/sa/<sa>` when the issuer defines a trust
   domain, plus the `san` annotation), creates the Certificate named after
   the Pod, and the kubelet starts the containers as soon as the Secret
   exists (a missing Secret keeps the Pod in `ContainerCreating`, which
   replaces the init-container wait). A Pod without any name yet (no IP,
   no Service) is skipped until its IP arrives; when the Pod IP changes
   (restart on another node), the Certificate is updated and re-issued.
   StatefulSets cannot template `secretName` per ordinal: they use one
   shared workload `Certificate` whose DNS names include the wildcard
   `*.<headless-service>.<ns>.svc.cluster.local`
   (`examples/shop/statefulset.yaml`), or the webhook below.
2. **Generated names (Deployments, Jobs).** The mutating webhook on Pod
   `CREATE` with the inject label fixes the Secret name in the
   `secret-name` annotation (`<name>-tls` for a Pod with a name, so that
   both flows agree; `kubeca-<8 random chars>` for a `generateName` Pod,
   whose `metadata.name` is empty at admission), and injects the volume
   and the mounts (`mount-path`, default `/etc/tls`, into the containers
   listed in the `containers` annotation or all of them) unless they
   exist. The Pod controller then proceeds as above; the Certificate is
   `<pod-name>-<suffix of the generated Secret name>` so a Pod re-created
   with the same name never collides with a stale Certificate.

Application side: the Secret volume is updated in place by the kubelet
within its sync period (1 min by default) plus the cache propagation delay;
`subPath` mounts never update. Applications reload the files on change,
for example with porto's `tlsconfig.NewKeypairReloader(label, certPath,
keyPath, checkInterval)` and its `GetKeypairFunc`/`GetClientCertificateFunc`
on the `tls.Config`, or a `tls.Config.GetCertificate` that stats the files.
`ca.crt` in the same Secret gives clients the root for peer verification.

`kubecertinit` keeps working (deprecated); the Secret keys `tls.crt` and
`tls.key` have the same content as its files, so moving a workload is a
volume change.

## Policy and security

- **Trust boundary.** Creating a `Certificate` in a namespace is the
  request; RBAC on `certificates.kubeca.effectivesecurity` in that
  namespace is the authorization. Reading the Secret is the usual
  Kubernetes Secret access. No cluster-wide CSR `create` right is needed any
  more.
- **Policy evaluation** happens in the controller on every issuance and,
  for the Pod flow, when the Certificate is derived; the webhook only
  injects. A `ValidatingAdmissionPolicy` or validating webhook can be added
  later to reject bad specs at admission; conditions are the contract now.
- **ClusterIssuer policy** is the cluster administrator's lever:
  `namespaceSelector`, `maxDuration`, `allowedDNSNames`, `allowedURIs`,
  `allowedEmailAddresses`, `allowIPAddresses`. Defaults in the examples
  bind DNS names to `*.<namespace>.svc[.cluster.local]` and URIs to
  `spiffe://<domain>/ns/<namespace>/sa/*`. The xpki profile regexes remain
  the CA-side gate, which is why the names travel in the CSR. An invalid
  policy makes the issuer not `Ready` (`InvalidPolicy`) instead of
  denying every request.
- **Secrets.** Keys live in etcd like every TLS Secret; enable encryption
  at rest. The operator needs `create/update/patch/delete/get/list/watch`
  on Secrets; the cache is restricted to `managed=true` Secrets, and
  conflicts are detected with an uncached read (`APIReader`) before
  creating. The operator never reads unlabeled Secrets except for that
  check.
- **Operator identity.** The operator's ServiceAccount holds the KMS role.
  The webhook serving certificate is issued in process from the Authority
  (D-6): a `Certificate` object cannot bootstrap it, because the Secret it
  would produce cannot be mounted before the Pod that issues it runs.
- **Audit.** Every issuance is an Event on the Certificate (and on the Pod
  for the Pod flow), an `INFO` log line with the serial, and a counter.
  `status.revision` and the Secret annotations (`serial`, `not-after`,
  `issued-at`, `revision`) tie a Secret to the issuance.
- **CSR signer.** Runs the in-process approver (KUBECA-001, D-7) and sets
  `Failed` on rejected requests (KUBECA-013). Deployments can disable it
  with `-disable-csr-signer` once nothing uses the CSR API.

## Webhook serving certificate

`webhook.ServingCertificate` signs an ECDSA P-256 certificate for
`<service>.<namespace>.svc[.<cluster domain>]` with the `-webhook-signer`
(`kubeca.svc/webhook`, a 168 h profile whose `allowed_dns` is pinned to
the webhook Service), writes `tls.key` (0600) and `tls.crt` (0644)
atomically into `-webhook-cert-dir` before the manager starts (so the
controller-runtime webhook server, which watches the files, finds them),
and patches `clientConfig.caBundle` of every webhook of the
`MutatingWebhookConfiguration` `-webhook-config` with the issuer's root
bundle. A runnable on every replica (no leader election) renews the
certificate at two thirds of its lifetime (retrying every minute when
the issuance fails; a renewal whose caBundle patch fails keeps its
schedule and leaves the patch to the check) and re-checks the `caBundle`
every minute, which repairs a
`helm upgrade` that re-rendered the configuration without it. The chart
ships the configuration with `failurePolicy: Fail` (D-6) and an
`objectSelector` on the inject label, so only labeled Pods depend on the
webhook; it runs two replicas with the PodDisruptionBudget (or set
`operator.webhook.failurePolicy: Ignore`). The readiness probe
(`/readyz` on `-health-probe-addr`) fails until the webhook server
accepts TLS connections, so the webhook Service routes admission
requests to replicas that can answer them and a rollout keeps an old
replica until the new one does.

## High availability and scale

- Leader election on by default in operator mode (`leases`; the chart
  grants the Role). Controllers run on the leader; the webhook server and
  its certificate renewer run on every replica, so two replicas keep
  admission available during a leader failover.
- Informer caches use `cache.Options.ByObject` label selectors for Secrets
  and ConfigMaps (`managed=true`) and Pods (`inject=true`); Certificates,
  ClusterIssuers, Namespaces and Services are cached fully. Every object
  is stored without `managedFields`.
- Work rate: one KMS `Sign` per issuance. 10 000 certificates at 24 h /
  renew at 16 h is well under one signature per second; AWS KMS asymmetric
  sign quotas are in the hundreds per second. Transient KMS throttling is a
  retried error.
- Reconcile cost is dominated by key generation (ECDSA P-256:
  sub-millisecond; RSA 4096: hundreds of milliseconds); keep RSA opt-in.
- The requeue heap holds one timer per Certificate; fine for 10^5 objects.

## Observability

Conditions and printer columns: [operator-api.md](operator-api.md).

Events: `Issued`, `Renewed`, `IssuanceFailed`, `PolicyViolation`,
`IssuerNotReady`, `SecretConflict` on Certificates; `CertificateCreated`,
`CertificateUpdated`, `InvalidPod` on Pods; `Ready`, `IssuerNotFound`,
`ProfileNotFound`, `InvalidPolicy`, `CAExpiring`, `CAExpired`,
`ConfigMapConflict` on ClusterIssuers.

Metrics (served with the existing `/metrics`):

| Metric                                                 | Type      | Labels                                                                            |
| ------------------------------------------------------ | --------- | --------------------------------------------------------------------------------- |
| `kubeca_certificate_expiration_timestamp_seconds`      | gauge     | `namespace`, `name`, `issuer`, `profile`                                          |
| `kubeca_certificate_renewal_timestamp_seconds`         | gauge     | `namespace`, `name`                                                               |
| `kubeca_certificate_ready`                             | gauge 0/1 | `namespace`, `name`                                                               |
| `kubeca_issuance_total`                                | counter   | `issuer`, `profile`, `trigger`, `result` (`success`, `policy_violation`, `error`) |
| `kubeca_issuance_duration_seconds`                     | histogram | `issuer`, `profile`                                                               |
| `kubeca_clusterissuer_ca_expiration_timestamp_seconds` | gauge     | `issuer`                                                                          |
| `perf_ca_signreq` (xpki), `controller_runtime_*`       | existing  |                                                                                   |

Logs: one `INFO` line per issuance and per permanent failure; `DEBUG` for
`needsIssuance` decisions and requeue times; never key material; the
certificate text only at `DEBUG`.

## Failure modes

| Failure                                    | Behavior                                                                                                | Operator action                                             |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| Operator down                              | Existing Secrets stay valid until `notAfter`; renewals resume on start (list + watch)                   | Restore within `renewBefore`; alert on expiration gauge     |
| KMS unavailable                            | `IssuanceFailed` transient: backoff retries, `failedAttempts`, `Warning` events, `result=error` counter; `Ready` stays `True` while the stored certificate is valid | Fix KMS/IAM                   |
| CA certificate near expiry                 | ClusterIssuer `Ready=True`/`CAExpiring` when `caNotAfter < now +` the longest lifetime it can sign (the longest profile expiry, or `maxDuration` when shorter); issuance clipped, `renewBefore` falls back to a third of the clipped lifetime | Rotate the CA, restart, Certificates re-issue (`CAChanged`) |
| CA certificate expired                     | ClusterIssuer `Ready=False`/`CAExpired`; Certificates report `IssuerNotReady`                           | Rotate the CA, restart                                      |
| Policy violation                           | `Ready=False`/`PolicyViolation`, no retry, event                                                        | Fix the spec or the policy                                  |
| Request rejected by the xpki profile       | `Ready=False`/`IssuanceFailed`, attempted once: the status update does not enqueue the Certificate again (`CertificateChanged`) | Fix the spec or the profile; `renew-requested` retries      |
| Secret deleted                             | Re-issued at once, new key                                                                              | none                                                        |
| Status write fails after the Secret write  | The error is retried; the retry takes `revision` and the honoured `renew-requested` from the Secret's annotations, so nothing is issued again | none                                                        |
| Two ClusterIssuers publish the same `caBundle.configMapName` into a namespace | The second finds the first's ConfigMap: `ConfigMapConflict` event, no retry loop        | Give each ClusterIssuer its own `configMapName`             |
| `ca.crt` or the chain in `tls.crt` removed or replaced | Restored in place from the ClusterIssuer, no re-issuance, one `WARNING` line                 | none                                                        |
| Secret exists and is not ours              | `SecretConflict`, no overwrite, re-checked every 5 min                                                  | Delete or label the Secret for adoption                     |
| Secret is not `kubernetes.io/tls`          | `SecretConflict` before any decision, even when labeled for adoption and matching                       | Delete it (the type is immutable)                           |
| Pod deleted                                | Certificate and Secret garbage-collected                                                                | none                                                        |
| Webhook unavailable (`failurePolicy=Fail`) | Labeled Pods are rejected at admission                                                                  | Keep 2 replicas; see D-6                                    |
| `helm upgrade` cleared the `caBundle`      | Repaired within a minute by the running operator                                                        | none                                                        |
| Clock skew between nodes                   | Covered by the profile `backdate` (5 m)                                                                 | Keep NTP                                                    |
| Application does not reload               | Uses the old certificate until it restarts; fails at `notAfter`                                         | Add a reloader; alert on handshake errors                   |

## Compatibility and migration

1. Install the CRDs (`kubectl apply -f examples/kubeca/crds` before a
   `helm upgrade`; Helm only installs `crds/` on install) and run the
   chart with `operator.enabled` (default); the CSR signer keeps running.
2. Create a `ClusterIssuer` for the existing `kubeca.svc` issuer with the
   short-lived profiles (`peer-24h`, `server-24h`, `client-24h`:
   `expiry: 24h`, `backdate: 5m`, shipped in the chart's CA
   configuration), or shorten the existing profiles once no init container
   depends on them.
3. Per workload: replace the `emptyDir` + init container with a
   `Certificate` (or the inject label) and a Secret volume. File names do
   not change; add a reloader if the application caches the certificate.
4. When no CSR client remains, start with `-disable-csr-signer`
   (`csrSigner.enabled: false`) and remove the `csr-creator` bindings.

`kubecertinit` is kept for clusters in migration (FINDINGS KUBECA-003).

## Decisions taken

All nine decisions of the proposal were taken with v0.9; the text above
reflects them. For reference:

| ID  | Decision                                          | Taken as                                                                                                                                       |
| --- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| D-1 | API group                                         | `kubeca.effectivesecurity`, also the label and annotation prefix                                                                                |
| D-2 | Where the private key is generated and stored     | In the operator, stored in a `kubernetes.io/tls` Secret; keys rotate every renewal; in-Pod keys are future work                                 |
| D-3 | Process layout                                    | Same `kubeca` binary and manager, `-enable-operator`; one Authority and KMS session, one chart                                                 |
| D-4 | Pod integration scope                             | Label-driven Pod controller and the mutating webhook for `generateName` Pods, both shipped                                                     |
| D-5 | Defaults                                          | `duration` = profile `expiry`; profile `expiry: 24h`, `backdate: 5m`; `renewBefore` = `duration / 3`; ECDSA P-256; `rotationPolicy: Always`     |
| D-6 | Webhook `failurePolicy` and certificate bootstrap | `Fail` with the PDB and two replicas recommended; the serving certificate is self-issued **in process** from the Authority (not a `Certificate` object), the `caBundle` patched and re-checked by the operator |
| D-7 | KUBECA-001 (CSR signer approval)                  | The in-process approver with `-approve=off|audit|enforce`; the binary defaults to `off`, the chart to `enforce`                                 |
| D-8 | Issuer kinds                                      | `ClusterIssuer` only in `v1alpha1`                                                                                                             |
| D-9 | SPIFFE identity                                   | `ClusterIssuer.spec.spiffe.trustDomain`; the Pod flow adds `spiffe://<td>/ns/<ns>/sa/<sa>`; the approver accepts any trust domain for the requester's namespace and ServiceAccount |

## Future work

- In-Pod keys: a `CertificateRequest`-style resource carrying a CSR, with
  a sidecar or a CSI driver generating the key; the Certificate controller
  then only signs.
- Hot reload of the CA configuration and CA certificate rotation without a
  restart (file watcher, `Authority` rebuild, `CAChanged` re-issuance) and
  bundle versioning for the rotation overlap.
- `ValidatingAdmissionPolicy` (CEL) for Certificate specs, generated from
  the ClusterIssuer policy.
- The controllers under envtest and the e2e in CI (PLAN.md P7).
- Revocation signals (CRL/OCSP are xpki features; not needed with 24 h
  lifetimes).
