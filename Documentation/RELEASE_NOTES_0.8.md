# kubeca v0.8 release notes

v0.8 adopts xpki v1.0 ([xpki-1.0-conformance.md](xpki-1.0-conformance.md))
and fixes the findings of the 2026-10-06 review that could be changed
without altering what a working deployment does. Finding IDs (`KUBECA-NNN`)
refer to [FINDINGS.md](../FINDINGS.md); the fixed ones are removed from it
and recorded here.

Nothing is required from existing deployments. The new flags are optional,
the chart renders the same objects plus a namespaced Role, and the CSR
signing contract is unchanged.

## Fixes

### Controller (`kubeca`)

- **KUBECA-002**: a CSR deleted between the watch event and the reconcile
  returns at once instead of running the reconcile on an empty object and
  logging "CSR does not have a signer name".
- **KUBECA-011**: the explicit `cryptoprov.Register` calls for `SoftHSM`,
  `AWSKMS` and `GCPKMS`, which xpki v1.0 providers already perform in
  `init()`, are gone (the providers are blank-imported); only the `PKCS11`
  alias is registered, and a registration error exits with status 1 instead
  of being discarded. The `AWSKMS-1/-2` and `GCPKMS-1/-2` aliases of
  earlier builds no longer exist; a token config names `AWSKMS` or `GCPKMS`.
- Logging: the controller-runtime global logger (metrics server, leader
  election) goes through the xlog adapter, so every line of `kubeca` is an
  xlog JSON object (`time`, `level`, `pkg`, `func`, `src`); `-debug` now
  sets the xlog level to `DEBUG` instead of switching controller-runtime to
  console output. The signing `NOTICE` line is one line per issuance
  (`status=signed`, `name`, `issuer`, `profile`, `serial`, `not_after`,
  `elapsed`); the certificate text moved to `DEBUG`, and the CSR is logged
  under `name` (a string) instead of `ns` (a `NamespacedName` object with an
  empty namespace).
- **KUBECA-013 (reduced)**: every failed signing attempt emits a `Warning`
  event `SigningFailed` with the error on the CSR, so `kubectl describe
  csr` shows why a request is not issued. The retry behaviour is unchanged;
  the remaining work is in FINDINGS.
- **KUBECA-009**: the go-logr sink is immutable. `WithValues` and
  `WithName` return new sinks instead of mutating the shared one, so values
  added for one controller or reconcile no longer appear on unrelated lines.
  Names are logged under `src` and nested names are dot-separated. logr
  verbosity 1 is logged at xlog `TRACE` and 2 and above at `DEBUG`, so
  controller-runtime's debug lines no longer appear at `INFO`. `Error` with
  a nil error no longer panics.

### Init container (`kubecertinit`)

- **KUBECA-004**: `-service-names` works: each name is added to the SAN as
  `<name>.<namespace>.svc.<cluster-domain>` and, with
  `-include-unqualified`, `<name>.<namespace>.svc`. Duplicates of names that
  `-query-k8s` already found are dropped by xpki. A deployment that passes
  the flag gets these names in its next certificate.
- **KUBECA-005**: the CSR no longer sets `spec.extra` (`issuer`,
  `profile`); the API server replaced it with the requester's identity
  anyway.
- **KUBECA-006 (reduced)**: the wait for the certificate honours the
  command context, stops on a `Failed` condition as well as `Denied`, and
  detects a deleted CSR with `apierrors.IsNotFound`. The new `-timeout`
  flag bounds the wait (`0`, the default, waits for ever as before). The
  Pod read uses the same context.
- **KUBECA-007**: a headless Service (`clusterIP: None`) selecting the Pod
  no longer adds the DNS name `None` to the certificate; an empty
  `clusterIP` is skipped too.
- IPv6: the Pod DNS name of an IPv6 Pod is `fd00--1.<ns>.pod.<domain>`
  (colons become dashes, as CoreDNS expects). Before, `-query-k8s` built
  `fd00::1.<ns>.pod.<domain>`, which xpki v1.0 rejects, so the init
  container failed on IPv6 clusters. A Pod whose status has no IP yet gets
  no Pod DNS name instead of an invalid one.
- **KUBECA-008**: the new `-usages` flag (comma-separated
  `certificates.k8s.io` key usages) lets a profile other than `peer`,
  `server` or `client` be requested; the built-in table remains the
  default for those three. The error for an unknown profile without
  `-usages` now says so.
- `-labels` entries are trimmed (`a = b` becomes `a=b`); an entry without
  `=`, with an empty key or with `=` in the value is still dropped.

### Both commands

- **KUBECA-010**: `-version` prints the build version and both commands log
  it at start-up. `make build` links it with `-ldflags` from `GIT_VERSION`
  (`v<.VERSION>.<commit count>[-<host>]`); a plain `go build` reports the
  module version or VCS revision. `internal/version/current.go` is ordinary
  source; `current.template` and the generated file are gone, and `make
  version` prints the version string instead of generating a file.

### Chart (`examples/kubeca`, moved from `helm/kubeca`)

- **KUBECA-012 (reduced)**: ClusterRoles and ClusterRoleBindings no longer
  carry `metadata.namespace`; a namespaced Role and RoleBinding on
  `coordination.k8s.io/leases` and events make `-enable-leader-election`
  work; `replicaCount.default`, `imagePullSecrets`, `nodeSelector.default`,
  `tolerations.default` and `affinity.default` are rendered (all default to
  the previous output).
- `etc/ca-config.kubeca.yaml` drops the `allowed_extensions` entries that
  xpki v1.0 ignores and documents the v1.0 rules (see the conformance
  report). Issued certificates do not change.

### Key ceremony and local test

`scripts/gen_root.sh` and `scripts/gen_ca.sh` create the root and the G1
issuing CA on two KMS (`Documentation/key-ceremony.md`); `docker-compose.yml`
runs two local-kms emulators for it, and `make minikube-all` deploys the
chart into minikube with the ceremony output and verifies the init-container
flow end to end (README, "Local test with minikube").

## Behaviour changes to be aware of

| Area                 | Change                                                                                                   | Who notices                                          |
| -------------------- | -------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| `-service-names`     | Adds `<name>.<ns>.svc[.<domain>]` names to the certificate                                              | Deployments passing the flag (it was a no-op before) |
| Headless Services    | `None` is no longer a DNS SAN                                                                            | Pods selected by a headless Service with `-query-k8s` |
| `Failed` condition   | `kubecertinit` exits 2 when a signer sets it                                                             | Nobody today: this controller never sets it           |
| Logging              | controller-runtime `V(1)`+ lines move from `INFO` to `TRACE`/`DEBUG`; named loggers log `src=<name>`; controller-runtime's own lines use the xlog JSON shape; `-debug` no longer switches to console output | Log consumers grepping those lines |
| Events               | `SigningFailed` warnings on CSRs the CA rejects                                                          | `kubectl describe csr`, event exporters               |
| Chart                | New Role/RoleBinding in the release namespace                                                            | `helm upgrade` creates them                           |

## Still open

KUBECA-001 (CSR approval; decided: an automatic in-controller approver,
see ROADMAP), KUBECA-003 (key file mode), and the remaining scope of
KUBECA-006, 012 and 013 in [FINDINGS.md](../FINDINGS.md). The operator
work is in [PLAN.md](../PLAN.md).
