# FINDINGS

Open bugs, security issues and correctness problems in
`github.com/effective-security/kubeca`.

Use the **ID** (`KUBECA-NNN`) in code comments, reviews and commits. Update
**Status** in the same change as the code or decision, and keep
[PLAN.md](PLAN.md) in step when a finding is scheduled there. When a finding
is fixed, remove it from this file and summarize the fix in the release notes
of the next version (`Documentation/RELEASE_NOTES_<version>.md`). IDs are
never reused; gaps are fixed or removed findings. The next free ID is
**KUBECA-018**.

KUBECA-002, 004, 005, 007, 008, 009, 010 and 011 were fixed in v0.8
([`Documentation/RELEASE_NOTES_0.8.md`](Documentation/RELEASE_NOTES_0.8.md));
KUBECA-001, 006, 012, 013, 014, 015, 016 and 017 in v0.9
([`Documentation/RELEASE_NOTES_0.9.md`](Documentation/RELEASE_NOTES_0.9.md)).
The items closed while adopting xpki v1.0 are in
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

| ID         | Package           | Location             | Title                                 | Type     | Severity | Status         |
| ---------- | ----------------- | -------------------- | ------------------------------------- | -------- | -------- | -------------- |
| KUBECA-003 | internal/certinit | `requestCertificate` | Private key is written with mode 0644 | security | MEDIUM   | Needs Decision |

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

**Note (v0.9):** the init-container flow is deprecated; the operator's
Secret volumes are mounted by the kubelet with the Pod's `fsGroup` and
`defaultMode` (0644 unless set), so workloads that migrate to a
`Certificate` can set `secret.defaultMode: 0400` on the volume and leave
this finding behind.
