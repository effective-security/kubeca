# initcontainer: the deprecated init-container flow

Deprecated since v0.9. A workload runs `kubecertinit` as an init container,
which creates a `certificates.k8s.io` CSR for the Pod, waits for the kubeca
CSR signer to approve (`-approve=enforce`, the chart default) and sign it,
and writes `tls.key`, `tls.csr` and `tls.crt` into a shared volume. The
certificate is never renewed, hence the year-long `peer`, `server` and
`client` profiles. Kept for the migration period; new workloads use
[`../shop`](../shop).

| Step | File                                                 | What it is                                                                                                                                  |
| ---- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | [`rbac.yaml`](rbac.yaml)                             | The `shop` namespace (labeled like `../shop/namespace.yaml`, so applying both keeps the operator policy label), the `web` ServiceAccount, the `kubeca:csr-creator` ClusterRole (CSRs are cluster-scoped) and the Role for `-query-k8s` |
| 2    | [`deployment.yaml`](deployment.yaml)                 | A Deployment with the init container writing into an in-memory `emptyDir` the application container mounts                                 |
| test | [`dummy-deployment.yaml`](dummy-deployment.yaml)     | The certmonitor variant `make minikube-test` deploys (replaces `deployment.yaml` in the minikube setup)                                     |

```sh
kubectl apply -f examples/initcontainer/rbac.yaml
kubectl apply -f examples/initcontainer/deployment.yaml
kubectl -n shop get pods -w
kubectl get csr                              # Approved,Issued
```

The `kubeca:csr-creator` ClusterRole is created here, not by the chart
(`csrSigner.createCSRCreatorRole` is off by default so the two never
collide). Migration: replace the `emptyDir` and the init container with a
`Certificate` and a Secret volume (file names unchanged) or the inject
label, and add a reloader; see "Migrating from the init container" in the
root README.
