# Design documents

| Document                             | Status                 | Content                                                                                                     |
| ------------------------------------ | ---------------------- | ----------------------------------------------------------------------------------------------------------- |
| [operator.md](operator.md)           | Implemented (v0.9)     | KubeCA Operator: controllers, issuance and renewal, Pod integration, security, HA, observability, decisions |
| [operator-api.md](operator-api.md)   | Implemented (v1alpha1) | `ClusterIssuer` and `Certificate` CRDs (`kubeca.effectivesecurity/v1alpha1`), Secret and Pod contracts      |
| [initcontainer.md](initcontainer.md) | Deprecated (v0.9)      | The init-container flow: `kubecertinit` + CSR API + `kubeca` signer with the in-process approver            |

Related: [`../../PLAN.md`](../../PLAN.md) (what remains of the operator
plan), [`../../examples`](../../examples/README.md) (manifests),
[`../xpki-1.0-conformance.md`](../xpki-1.0-conformance.md) (the signing
contract the designs rely on), [`../../ROADMAP.md`](../../ROADMAP.md),
[`../RELEASE_NOTES_0.9.md`](../RELEASE_NOTES_0.9.md).

Conventions: a design document describes mechanism and contracts, not
schedule. Decisions that need an owner are numbered `D-n` and tracked in
`PLAN.md` until taken; once taken, the decision is folded into the design
text. All nine operator decisions were taken in v0.9 and are listed at the
end of `operator.md` for reference.
