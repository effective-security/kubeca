# Examples

| Directory                       | Owner                 | Status     | Content                                                                                                                      |
| ------------------------------- | --------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------- |
| [kubeca/](kubeca)               | Cluster administrator | Current    | The Helm chart: CRDs, controller (operator, webhook, CSR signer), RBAC, CA configuration and profiles, `ClusterIssuer`       |
| [shop/](shop)                   | Application team      | Current    | What a namespace deploys to get certificates from the operator: `Certificate`s, the inject label, a StatefulSet; `e2e/` for the minikube test |
| [initcontainer/](initcontainer) | Application team      | Deprecated | The `kubecertinit` init container, its RBAC, and the certmonitor variant the minikube test deploys                          |

Deploy order: the chart first (`kubeca/README.md`), then the application
manifests (`shop/README.md`). Each directory's README lists its files, what
they show and the order to apply them. `make minikube-all` runs the whole
sequence against the local KMS emulators (root README, "Local test with
minikube").
