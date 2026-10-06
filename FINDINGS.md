# FINDINGS

Open bugs, security issues and correctness problems in
`github.com/effective-security/kubeca`.

Use the **ID** (`KUBECA-NNN`) in code comments, reviews and commits. Update
**Status** in the same change as the code or decision, and keep
[PLAN.md](PLAN.md) in step when a finding is scheduled there. When a finding
is fixed, remove it from this file and summarize the fix in the release notes
of the next version (`Documentation/RELEASE_NOTES_<version>.md`). IDs are
never reused; gaps are fixed or removed findings. The next free ID is
**KUBECA-014**.

KUBECA-002, 004, 005, 007, 008, 009, 010 and 011 were fixed in v0.8
([`Documentation/RELEASE_NOTES_0.8.md`](Documentation/RELEASE_NOTES_0.8.md));
006, 012 and 013 were reduced there and keep the remaining scope below. The
items closed while adopting xpki v1.0 are in
[`Documentation/xpki-1.0-conformance.md`](Documentation/xpki-1.0-conformance.md).

## Status

| Status         | Meaning                                                |
| -------------- | ------------------------------------------------------ |
| Open           | Not started                                            |
| In Progress    | Being fixed                                            |
| Needs Decision | Behavior or compatibility change that needs a decision |

Type: **security** > **bug** > **race** > **correctness** > **performance** > **docs**.

Severity: **CRITICAL** > **HIGH** > **MEDIUM** > **LOW**.

Line numbers are omitted; the symbol name is the stable reference.

## Index

| ID         | Package             | Location                               | Title                                                              | Type     | Severity | Status         |
| ---------- | ------------------- | -------------------------------------- | ------------------------------------------------------------------ | -------- | -------- | -------------- |
| KUBECA-001 | internal/controller | `isCertificateRequestApproved`         | CSRs are signed without an Approved condition                      | security | HIGH     | Open (decided) |
| KUBECA-003 | internal/certinit   | `requestCertificate`                   | Private key is written with mode 0644                              | security | MEDIUM   | Needs Decision |
| KUBECA-006 | internal/certinit   | `waitForCertificate`                   | Wait has no deadline by default and polls instead of watching      | bug      | LOW      | Needs Decision |
| KUBECA-012 | examples/kubeca     | `templates/role-csr-approver.yaml`, `values.yaml` | Unused approver role, unused `autoscaling` values, external certs Secret | docs | LOW | Open     |
| KUBECA-013 | internal/controller | `Reconcile`                            | Policy rejections are retried forever instead of failing the CSR   | bug      | MEDIUM   | Open           |

## KUBECA-001: CSRs are signed without an Approved condition

**Location:** `internal/controller/certificatesigningrequest.go`,
`isCertificateRequestApproved`, `getCertApprovalCondition`.

**Behavior:** the reconciler signs a CSR when it has a signer name, no
certificate yet and no `Denied` condition. An `Approved` condition is not
required (the code comment says "implicitly approve"). Nothing in the chart
or in `kubecertinit` approves CSRs: the `csr-creator` role documented for
workloads grants `create/get/list/watch` only, and the `kubeca:csr-approver`
ClusterRole bound to the controller is never exercised by the code.

**Impact:** any principal that can create CertificateSigningRequests (the
documented `csr-creator` ClusterRole grants that cluster-wide) obtains a
certificate for every name the profile's `allowed_fields` and regexes
permit, with no approval step. The Kubernetes API contract says a signer
populates `status.certificate` after an `Approved` condition is present.
Today the only policy is the xpki profile (`allowed_dns`, `allowed_uri`,
`allowed_fields`), and the shipped chart leaves the regexes commented out.

**Options:** (a) add an approval step to the controller that sets
`Approved` when the CSR's names match the Pod and Service names of the
requesting ServiceAccount's namespace (the operator design performs this
check inside the Certificate controller instead); (b) require `Approved`
and document that an external approver (or `kubectl certificate approve`)
is needed, which breaks the current init-container flow; (c) keep implicit
approval and make the profile regexes mandatory in the chart. Decide before
the operator ships, because the operator keeps this controller for
compatibility ([PLAN.md](PLAN.md) D-7).

**Decision:** we can not have a manual Approval, as certificates are issued at every deployment, so it should be automatic.
I think option (a) add an approval step to the controller that sets
`Approved` when the CSR's names match the Pod and Service names of the
requesting ServiceAccount's namespace (the operator design performs this
check inside the Certificate controller instead)

**Next:** implement the approver as described in [ROADMAP.md](ROADMAP.md),
"CSR approval policy": opt-in first (a flag that defaults to the current
implicit behavior), so that existing deployments whose CSRs carry names the
approver cannot derive (`localhost`, `0.0.0.0`, bare Service names from
`-san`) keep working until their policy is reviewed; then flip the default.
It needs the controller to read Pods and Services cluster-wide, a `Denied`
condition with a reason for mismatches, and tests with the fake client.
KUBECA-013 (set `Failed`) is implemented in the same change.

## KUBECA-003: Private key is written with mode 0644

**Location:** `requestCertificate`, the `os.WriteFile(keyFile, ...)` call
(`keyFileMode`; the `TODO` explains that `0600` made the application
container fail with access denied).

**Impact:** every process in the Pod, whatever its UID, can read
`tls.key`; with an `emptyDir` shared between containers that includes
sidecars. [AGENTS.md](AGENTS.md) requires `0600` for key files.

**Decision needed:** either run the init container and the application
containers with the same `runAsUser` and write `0600`, or write `0640` and
require `securityContext.fsGroup` on the Pod. Both change the documented
Pod template; pick one and document it in `examples/initcontainer`.

**Decision:** Let's keep it open for now, I need to investigate Helm deployement in production first.

## KUBECA-006: Wait has no deadline by default and polls instead of watching

**Location:** `waitForCertificate` in `internal/certinit/certreq.go`;
`-timeout` in `cmd/kubecertinit/main.go`.

**Fixed in v0.8:** the wait honours the command context (`-timeout`, 0 by
default), stops on a `Failed` condition as well as `Denied`, detects a
deleted CSR with `apierrors.IsNotFound` instead of a string match, and
`Pods.Get` uses the context. `examples/initcontainer` sets `-timeout=10m`.

**Remaining:** without `-timeout` the init container still waits for ever
when the controller is down or the CSR is rejected (KUBECA-013), and it
polls every 5 s (`pollInterval`) instead of watching the CSR.

**Decision needed:** a non-zero default for `-timeout` (10 minutes is the
example's value) changes the failure mode of existing Pods from "stuck in
`Init`" to "init container restarted by the kubelet with backoff", which
also creates a new CSR per attempt. Pick the default with the approver
(KUBECA-001) so a rejected CSR fails fast instead of timing out. A watch
with a resource version replaces the poll in the same change.

## KUBECA-012: Unused approver role, unused `autoscaling` values, external certs Secret

**Location:** `examples/kubeca/templates/role-csr-approver.yaml`,
`rolebinding.yaml`, `values.yaml`, `deployment.yml`.

**Fixed in v0.8:** cluster-scoped RBAC no longer carries
`metadata.namespace`; a namespaced Role on `coordination.k8s.io/leases`
(and events) is bound to the controller so `-enable-leader-election` works;
`replicaCount.default`, `imagePullSecrets`, `nodeSelector.default`,
`tolerations.default` and `affinity.default` are rendered.

**Remaining:** `kubeca:csr-approver` is bound but the controller never
approves (it becomes necessary with KUBECA-001's approver, so keep it);
`autoscaling` in `values.yaml` has no template; the certs Secret
`<fullname>-certs-secret-tf` must exist before install and is documented
only in the README.

**Fix:** keep the approver role for KUBECA-001, add an HPA template or
delete `autoscaling`, and either template the certs Secret from values or
document it in `values.yaml`.

## KUBECA-013: Policy rejections are retried forever instead of failing the CSR

**Location:** `Reconcile`, the `issuer.Sign` error path.

**Behavior:** every `Sign` error is returned from `Reconcile`, so
controller-runtime requeues with exponential backoff (up to about 16
minutes between attempts) until the CSR cleaner removes the pending CSR
after 24 hours. xpki v1.0 rejects more requests permanently than before
(an invalid or duplicate SAN, a name outside `allowed_dns`/`allowed_uri`,
a CSR extension not in `allowed_extensions`), so a bad request costs hours
of retries, the CSR never gets a `Failed` condition, and an init container
without `-timeout` waits for ever (KUBECA-006).

**Reduced in v0.8:** every failed attempt now emits a `Warning` event
`SigningFailed` with the error on the CSR, so `kubectl describe csr` shows
the reason; `kubecertinit` stops on a `Failed` condition once one is set.

**Fix:** classify `Sign` errors: policy and parse failures set the `Failed`
condition (reason `SigningFailed`, the error message), and return
`ctrl.Result{}` without an error; KMS and API failures keep the current
retry. xpki returns untyped errors for policy rejections, so a reliable
split needs typed (sentinel) errors from `authority.Issuer.Sign` or a
conservative classifier that treats only provider and API errors as
transient. Implement with the approver (KUBECA-001), which gives the
controller a `Denied` path for names and leaves `Failed` for the remaining
signing errors.
