# KubeCA Operator

Status: proposed (2026-10-06). API: [operator-api.md](operator-api.md).
Execution plan and open decisions: [`PLAN.md`](../../PLAN.md). Examples:
[`examples/operator`](../../examples/operator).

## Goals

- Issue **short-lived** certificates (target 24 h) to workloads and **renew
  them automatically** before expiry, without restarting Pods.
- Make the certificate a Kubernetes object (`Certificate`) with a status an
  operator can read, alert on and act on.
- Enforce policy per namespace and ServiceAccount, not only per CA profile.
- Keep the CA key in KMS/HSM and keep xpki as the signing engine with the
  v1.0 contract ([xpki-1.0-conformance.md](../xpki-1.0-conformance.md)).
- Keep the existing CSR flow working during migration.

Non-goals for the first release: keys that never leave the Pod (CSI driver
or in-Pod CSR mode), revocation (short lifetimes replace it), CA key
rotation without a restart, a namespaced `Issuer` kind.

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

| Requirement (INTENT)                  | Mechanism                                                                                                            |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Watch Pods and react                  | Pod controller on Pods labeled `kubeca.effectivesecurity/inject=true`; mutating webhook for Pods with `generateName` |
| Watch Secrets and renew them          | Certificate controller `Owns` its Secrets; `RequeueAfter` at the renewal time; drift detection                       |
| Add `Certificate` API                 | CRDs `Certificate` (namespaced) and `ClusterIssuer` (cluster-scoped), group `kubeca.effectivesecurity`, `v1alpha1`   |
| Manage complete certificate lifecycle | Issue → store → renew → rotate key → re-issue on spec/CA change → garbage-collect with the owner                     |

## Components

All run in the existing `kubeca` process (D-3): one controller-runtime
manager, one xpki `authority.Authority`, one KMS session, one metrics
endpoint, one leader election. New flags: `-enable-operator`,
`-disable-csr-signer`, `-cluster-domain`, `-webhook-port`,
`-ca-bundle-configmap`.

| Component                | Package (planned)                           | Watches                                                                   | Writes                                                                    |
| ------------------------ | ------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| ClusterIssuer controller | `internal/operator/issuer`                  | `ClusterIssuer`                                                           | `ClusterIssuer.status` (Ready, CA cert, profiles), optional CA ConfigMaps |
| Certificate controller   | `internal/operator/certificate`             | `Certificate`, owned `Secret`s, `ClusterIssuer` (map to its Certificates) | `Secret` (`kubernetes.io/tls`), `Certificate.status`, Events              |
| Pod controller           | `internal/operator/pod`                     | Pods with the inject label; Services (for names)                          | `Certificate` owned by the Pod                                            |
| Pod mutating webhook     | `internal/operator/webhook`                 | Pod `CREATE` with the inject label                                        | Secret-name annotation, volume and mounts on the Pod                      |
| Policy                   | `internal/operator/policy`                  | pure functions                                                            | nothing; shared by the controllers and the webhook                        |
| Names                    | `internal/k8snames` (moved from `certinit`) | pure functions                                                            | nothing                                                                   |
| CSR signer (existing)    | `internal/controller`                       | `CertificateSigningRequest`                                               | unchanged                                                                 |

The `authority.Authority` and `Issuer.Sign` are safe for concurrent use
(XPKI-055), so the Certificate controller runs with
`MaxConcurrentReconciles` > 1 (default 4).

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
    CC->>CC: generate key (ECDSA P-256 default), build CSR with validated SAN (csr.ParseSAN)
    CC->>X: Sign(SignRequest{Request, Profile, SAN, NotBefore, NotAfter})
    X->>K: sign
    X-->>CC: leaf PEM
    CC->>API: create/update Secret (tls.crt, tls.key, ca.crt; ownerRef Certificate)
    CC->>API: patch status (Ready=True, notAfter, renewalTime, serial, revision)
    CC->>API: event Issued / Renewed
    Note over CC: RequeueAfter = renewalTime − now
```

Step details:

1. **Resolve the issuer.** `spec.issuerRef.name` → `ClusterIssuer`; it must
   be `Ready` and its `spec.profiles` (or the profiles the xpki issuer
   serves) must include `spec.profile`. Otherwise `Ready=False`,
   `reason=IssuerNotReady`, requeue in 1 min (the ClusterIssuer controller
   also re-queues every Certificate of an issuer when the issuer's status
   changes).
2. **Evaluate policy** (`internal/operator/policy`): namespace selector,
   `maxDuration`, allowed DNS/URI/email regexes with `${NAMESPACE}`,
   `${NAME}` and `${SERVICE_ACCOUNT}` substituted, `allowIPAddresses`. A
   violation sets `Ready=False`, `reason=PolicyViolation`, emits a
   `Warning` event and returns **without error** (no retry until the spec
   or the ClusterIssuer changes). The xpki profile regexes still apply as a
   second gate.
3. **Decide whether to issue** (`needsIssuance`, a pure function with table
   tests):
   - no Secret, or `tls.crt`/`tls.key` missing or unparsable (`SecretMissing`);
   - the Secret is not owned by this Certificate (`SecretConflict`, no
     overwrite; an operator may delete it or label it
     `kubeca.effectivesecurity/adopt=true`);
   - the certificate does not match the spec: names, common name, key
     algorithm/size, usages implied by the profile, or issuer AKI differs
     from the current CA SKI (`SpecChanged`, `CAChanged`);
   - `now ≥ renewalTime` where `renewalTime = notAfter − renewBefore −
jitter` (`Renewal`);
   - the annotation `kubeca.effectivesecurity/renew-requested` differs
     from `status.lastRenewRequest` (`Requested`).
     The reason becomes the `Issuing` condition reason and the metric
     `trigger` label.
4. **Key.** Generate a new key for every issuance when
   `spec.privateKey.rotationPolicy=Always` (default), reuse the Secret's
   key with `Never`. Algorithms: ECDSA (256/384/521) and RSA
   (2048/3072/4096), the key types xpki's `csr.KeyRequest` supports.
5. **SAN.** Assemble `dnsNames`, `ipAddresses`, `uris`, `emailAddresses`
   plus `kubernetesNames` discovery (`internal/k8snames`), validate with
   `csr.ParseSAN` early so a bad spec is a `PolicyViolation` rather than a
   signing error.
6. **Validity** (XPKI-054). Read the profile from the issuer
   (`Issuer.Profile(name)`):

   ```text
   backdate  = profile.backdate (default 5m)
   notBefore = now.Truncate(1m) − backdate        // the earliest the issuer accepts
   lifetime  = min(spec.duration or profile.expiry, profile.expiry, issuer policy maxDuration)
   notAfter  = notBefore + lifetime
   ```

   Both times are set explicitly in the `SignRequest`, so `lifetime` never
   exceeds `expiry` by the backdate (the mistake the release notes warn
   about). The usable time is `lifetime − backdate`; profiles for
   short-lived certificates should keep `backdate` at the 5 m default.
   `status.notAfter` is read from the issued certificate (the issuer clips
   it to the CA's `NotAfter`).

7. **Sign.** `Issuer.Sign(csr.SignRequest{Request, Profile, SAN, NotBefore,
NotAfter})`. The SAN in the request is authoritative (it replaces the
   CSR names); the CSR carries the same names so that clients that inspect
   the CSR see them. Errors are classified: xpki policy and parse errors
   are permanent (`IssuanceFailed`, no retry, event), provider/KMS errors
   are transient (returned, exponential backoff, `failedAttempts++`,
   `lastFailureTime`).
8. **Store.** `Secret` of type `kubernetes.io/tls` named `spec.secretName`
   (default: the Certificate name) with `tls.crt` (leaf + issuer chain, the
   same bytes the CSR controller writes), `tls.key` (PEM), `ca.crt` (the
   issuer's root bundle), labels `kubeca.effectivesecurity/managed=true`
   and the annotations listed in the API document, `secretTemplate`
   labels/annotations, and a controller owner reference to the
   Certificate. Written with `controllerutil.CreateOrUpdate`; a Secret that
   exists without the owner reference is a conflict (step 3).
9. **Status and signals.** Patch `status` (conditions `Ready`, `Issuing`;
   `notBefore`, `notAfter`, `renewalTime`, `serialNumber`, `issuerLabel`,
   `revision+1`, `failedAttempts=0`), emit `Issued` or `Renewed`, update
   the metrics, log one `INFO` line (`ns`, `name`, `issuer`, `profile`,
   `serial`, `not_after`, `trigger`).
10. **Schedule.** Return `RequeueAfter = renewalTime − now`. The informer
    resync (10 h default) and the Secret watch are the safety nets.

## Renewal and Secret watch

- **Renewal time.** `renewBefore` defaults to a third of `duration`
  (24 h → 8 h). Jitter is deterministic per certificate (hash of the serial
  modulo 10 % of `renewBefore`), so several replicas agree and a fleet
  issued at the same time does not renew at the same second.
- **Secret deleted.** `Owns(&corev1.Secret{})` enqueues the Certificate;
  `needsIssuance` sees `SecretMissing` and re-issues at once with a new key.
- **Secret edited.** The same watch runs the drift check; a certificate
  that no longer matches the key or the spec is re-issued. The controller
  never "repairs" foreign edits silently: it re-issues and logs the trigger.
- **Spec changed.** Names, profile, duration, key parameters trigger
  `SpecChanged`. `renewBefore` and `secretTemplate` changes do not re-issue
  (status and Secret metadata are updated in place).
- **CA changed.** When the ClusterIssuer's CA certificate changes (restart
  with a new issuer certificate), the ClusterIssuer controller enqueues
  every Certificate of that issuer; the AKI check re-issues them, spread by
  the jitter.
- **Manual renewal.** Annotate the Certificate with
  `kubeca.effectivesecurity/renew-requested=<any new value>`; `kubectl`
  plugin work is out of scope.
- **Outage budget.** A certificate issued at T is valid until T + 24 h and
  renewed at T + 16 h (± jitter). The operator or KMS can be down for up to
  8 h before any TLS failure. Alert on
  `kubeca_certificate_expiration_timestamp_seconds − time() < renewBefore / 2`.
- **Key rotation.** With `rotationPolicy=Always` every renewal uses a new
  key; a leaked key is valid for at most one lifetime.

## Pod integration

Two ways to get a Secret into a Pod, both producing a `Certificate` owned
by the Pod (garbage-collected with it):

1. **Known Pod names (bare Pods, Pods created by your own controllers,
   Jobs with a fixed name).** Label the Pod
   `kubeca.effectivesecurity/inject: "true"`, annotate it with the
   issuer and profile, and mount the Secret `<pod-name>-tls` (or the name
   given in the `secret-name` annotation) as a volume. The Pod controller
   sees the Pod, derives the names (Pod IP and DNS name,
   hostname/subdomain, selecting Services, SPIFFE URI
   `spiffe://<trustDomain>/ns/<ns>/sa/<sa>` when the issuer defines a trust
   domain, plus the `san` annotation), creates the Certificate, and the
   kubelet starts the containers as soon as the Secret exists (a missing
   Secret keeps the Pod in `ContainerCreating`, which replaces today's
   init-container wait). When the Pod IP changes (restart on another
   node), the Certificate is updated and re-issued. StatefulSets cannot
   template `secretName` per ordinal: they use one shared workload
   `Certificate` whose DNS names include the wildcard
   `*.<headless-service>.<ns>.svc.cluster.local`
   (`examples/operator/statefulset.yaml`), or the webhook below.
2. **Generated names (Deployments, Jobs).** A mutating webhook on Pod
   `CREATE` with the inject label generates a unique Secret name
   (`kubeca-<8 random chars>`), records it in the `secret-name` annotation,
   and injects the volume and the mounts (`mount-path`, default `/etc/tls`,
   into the containers listed in the `containers` annotation or all of
   them). The Pod controller then proceeds as above. The webhook sees an
   empty `metadata.name` for `generateName` Pods, which is why the Secret
   name is generated rather than derived.

Application side: the Secret volume is updated in place by the kubelet
within its sync period (1 min by default) plus the cache propagation delay;
`subPath` mounts never update. Applications reload the files on change,
for example with porto's `tlsconfig.NewKeypairReloader(label, certPath,
keyPath, checkInterval)` and its `GetKeypairFunc`/`GetClientCertificateFunc`
on the `tls.Config`, or a `tls.Config.GetCertificate` that stats the files.
`ca.crt` in the same Secret gives clients the root for peer verification.

`kubecertinit` keeps working unchanged; the Secret keys `tls.crt` and
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
  the CA-side gate.
- **Secrets.** Keys live in etcd like every TLS Secret; enable encryption
  at rest. The operator needs `create/update/patch/delete/get/list/watch`
  on Secrets; the cache is restricted to `managed=true` Secrets, and
  conflicts are detected with an uncached read (`APIReader`) before
  creating. The operator never reads unlabeled Secrets.
- **Operator identity.** The operator's ServiceAccount holds the KMS role.
  The webhook serving certificate is itself a `Certificate` (profile
  `webhook`, in the operator namespace) whose `ca.crt` is patched into the
  `MutatingWebhookConfiguration.caBundle` by the chart's job or by the
  ClusterIssuer controller (D-6).
- **Audit.** Every issuance is an Event on the Certificate (and on the Pod
  for the Pod flow), an `INFO` log line with the serial, and a counter.
  `status.revision` and the Secret annotations (`serial`, `not-after`,
  `revision`) tie a Secret to the issuance.
- **CSR signer.** Unchanged until the approver decided for KUBECA-001
  ships (D-7). Deployments can disable it with `-disable-csr-signer` once
  nothing uses the CSR API.

## High availability and scale

- Leader election on by default in operator mode (`leases`; chart adds the
  rule). Controllers run on the leader; the webhook server runs on every
  replica (controller-runtime runnables without leader election), so two
  replicas keep admission available during a leader failover.
- Informer caches use `cache.Options.ByObject` label selectors for Secrets
  (`managed=true`) and Pods (`inject=true`); Certificates and
  ClusterIssuers are cached fully. Services are cached fully (needed for
  name discovery); a `transform` strips `managedFields`.
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
`CertificateUpdated` on Pods; `Ready`, `IssuerNotFound`, `CAExpiring` on
ClusterIssuers.

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
| KMS unavailable                            | `IssuanceFailed` transient: backoff retries, `failedAttempts`, `Warning` events, `result=error` counter | Fix KMS/IAM                                                 |
| CA certificate near expiry                 | ClusterIssuer `Ready=False`/`CAExpiring` when `caNotAfter < now + maxDuration`; issuance clipped        | Rotate the CA, restart, Certificates re-issue (`CAChanged`) |
| Policy violation                           | `Ready=False`/`PolicyViolation`, no retry, event                                                        | Fix the spec or the policy                                  |
| Secret deleted                             | Re-issued at once, new key                                                                              | none                                                        |
| Secret exists and is not ours              | `SecretConflict`, no overwrite                                                                          | Delete or label the Secret for adoption                     |
| Pod deleted                                | Certificate and Secret garbage-collected                                                                | none                                                        |
| Webhook unavailable (`failurePolicy=Fail`) | Labeled Pods are rejected at admission                                                                  | Keep 2 replicas; see D-6                                    |
| Clock skew between nodes                   | Covered by the profile `backdate` (5 m)                                                                 | Keep NTP                                                    |
| Application does not reload                | Uses the old certificate until it restarts; fails at `notAfter`                                         | Add a reloader; alert on handshake errors                   |

## Compatibility and migration

1. Install the CRDs and run `kubeca` with `-enable-operator`; the CSR
   signer keeps running.
2. Create a `ClusterIssuer` for the existing `kubeca.svc` issuer with
   short-lived profiles (`peer-24h`, `server-24h`, `client-24h`:
   `expiry: 24h`, `backdate: 5m`), or shorten the existing profiles once no
   init container depends on them.
3. Per workload: replace the `emptyDir` + init container with a
   `Certificate` (or the inject label) and a Secret volume. File names do
   not change; add a reloader if the application caches the certificate.
4. When no CSR client remains, start with `-disable-csr-signer` and remove
   the `csr-creator` bindings.

`kubecertinit` is kept and maintained (FINDINGS KUBECA-003..008) for
clusters that cannot run the webhook.

## Decisions

Numbered decisions, with the recommendation; tracked in
[`PLAN.md`](../../PLAN.md) until taken.

| ID  | Decision                                          | Recommendation                                                                                                                                                                                                                           | Alternatives considered                                                                                    |
| --- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| D-1 | API group                                         | `kubeca.effectivesecurity` (the organization's domain; also the label/annotation prefix)                                                                                                                                                 | `kubeca.io` (not owned), `kubeca.effective-security.github.io`                                             |
| D-2 | Where the private key is generated and stored     | In the operator, stored in a `kubernetes.io/tls` Secret; keys rotate every renewal                                                                                                                                                       | In-Pod key with a CSR-mode `CertificateRequest` (keys never in etcd; needs a sidecar or CSI driver); later |
| D-3 | Process layout                                    | Same `kubeca` binary and manager, `-enable-operator`; one Authority and KMS session, one chart                                                                                                                                           | Separate `kubeca-operator` binary and Deployment (two KMS principals, two configs)                         |
| D-4 | Pod integration scope                             | Label-driven Pod controller first (P5), mutating webhook for `generateName` Pods next (P6)                                                                                                                                               | Webhook only; CSI driver; keep `kubecertinit` and add a renewing sidecar                                   |
| D-5 | Defaults                                          | `duration` = profile `expiry`; profile `expiry: 24h`, `backdate: 5m`; `renewBefore` = `duration / 3`; ECDSA P-256; `rotationPolicy: Always`                                                                                              | 12 h / 4 h for stricter environments; RSA 2048 for legacy clients                                          |
| D-6 | Webhook `failurePolicy` and certificate bootstrap | `Fail` with two replicas and a PodDisruptionBudget; the webhook certificate is a `Certificate` in the operator namespace, `caBundle` patched by the operator                                                                             | `Ignore` (Pods start without TLS silently); cert-manager-issued webhook cert                               |
| D-7 | KUBECA-001 (CSR signer approval)                  | Decided (FINDINGS KUBECA-001): an in-process approver that approves a CSR when its names match the requester's Pods and Services (ROADMAP, "CSR approval policy"); opt-in `-approve` first, `enforce` by default when the operator ships | Keep implicit approval; external approver                                                                  |
| D-8 | Issuer kinds                                      | `ClusterIssuer` only in `v1alpha1`                                                                                                                                                                                                       | Namespaced `Issuer` (needs per-namespace CA config; no use case yet)                                       |
| D-9 | SPIFFE identity                                   | `ClusterIssuer.spec.spiffe.trustDomain`; Pod flow adds `spiffe://<td>/ns/<ns>/sa/<sa>`; profile `allowed_uri` and issuer policy pin the namespace                                                                                        | Trust domain per namespace annotation                                                                      |

## Future work

- In-Pod keys: a `CertificateRequest`-style resource carrying a CSR, with
  a sidecar or a CSI driver generating the key; the Certificate controller
  then only signs.
- Hot reload of the CA configuration and CA certificate rotation without a
  restart (file watcher, `Authority` rebuild, `CAChanged` re-issuance).
- Trust bundles: a `ca.crt` ConfigMap per namespace maintained by the
  ClusterIssuer controller (`spec.caBundle`), and bundle versioning for CA
  rotation overlap.
- `ValidatingAdmissionPolicy` (CEL) for Certificate specs, generated from
  the ClusterIssuer policy.
- Revocation signals (CRL/OCSP are xpki features; not needed with 24 h
  lifetimes).
