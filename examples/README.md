# Examples

| Directory                       | Status      | Content                                                                                                                                             |
| ------------------------------- | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| [initcontainer/](initcontainer) | Works today | A Deployment with the `kubecertinit` init container, the RBAC its ServiceAccount needs, and `dummy-deployment.yaml` (busybox) for the minikube test |
| [kubeca/](kubeca)               | Works today | The Helm chart; `minikube.yaml` and `etc/aws-dev-kms-minikube.yaml` are the overlay for the minikube test                                           |
| [operator/](operator)           | Proposed    | Manifests for the planned `kubeca.effectivesecurity/v1alpha1` API; validated in PLAN.md batches P4 and P7                                           |

The init-container manifests assume `kubeca` is installed from
`examples/kubeca` with the issuer label `kubeca.svc` and the profiles of
`examples/kubeca/etc/ca-config.kubeca.yaml`. Apply them with:

```sh
kubectl apply -f examples/initcontainer/rbac.yaml
kubectl apply -f examples/initcontainer/deployment.yaml
kubectl -n shop get pods -w
kubectl get csr
```

The operator manifests target the design in
[`Documentation/design/operator-api.md`](../Documentation/design/operator-api.md);
the CRDs do not exist in a cluster yet, so `kubectl apply` fails until
batch P1 ships. Keep them in sync with the API document.
