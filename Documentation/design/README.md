# Design documents

| Document                             | Status   | Content                                                                                                     |
| ------------------------------------ | -------- | ----------------------------------------------------------------------------------------------------------- |
| [initcontainer.md](initcontainer.md) | Shipped  | The current flow: `kubecertinit` + CSR API + `kubeca` signer. Components, sequence, security, limits        |
| [operator.md](operator.md)           | Proposed | KubeCA Operator: controllers, issuance and renewal, Pod integration, security, HA, observability, decisions |
| [operator-api.md](operator-api.md)   | Proposed | `ClusterIssuer` and `Certificate` CRDs (`kubeca.effectivesecurity/v1alpha1`), Secret and Pod contracts      |

Related: [`../../PLAN.md`](../../PLAN.md) (execution plan and open
decisions), [`../../examples`](../../examples/README.md) (manifests),
[`../xpki-1.0-conformance.md`](../xpki-1.0-conformance.md) (the signing
contract the designs rely on), [`../../ROADMAP.md`](../../ROADMAP.md).

Conventions: a design document describes mechanism and contracts, not
schedule. Decisions that need an owner are numbered `D-n` and tracked in
`PLAN.md`; once taken, the decision is folded into the design text and the
`D-n` row is removed.
