# kubeca: the Helm chart

Everything kubeca needs to run: the two CRDs (`crds/`), the controller
Deployment (operator, Pod mutating webhook and the CSR signer of the
deprecated init-container flow in one process), its RBAC, the xpki CA
configuration with the profiles (`etc/`), the `ClusterIssuer` that binds
the issuer to a policy, and the webhook Service and configuration. The
only thing the chart does not create is the Secret with the issuing CA
files, which comes from the key ceremony. Application manifests are in
[`../shop`](../shop).

| Path                              | Content                                                                                                                                              |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `crds/`                           | The `Certificate` and `ClusterIssuer` CRDs (copied from `config/crd/bases` by `make manifests`). Helm installs them on the first install only       |
| `etc/ca-config.kubeca.yaml`       | The issuer `kubeca.svc` and the profiles: `peer-24h`, `server-24h`, `client-24h` (operator), `webhook` (the webhook's own certificate), and the legacy `peer`, `server`, `client` (init container); `extraProfiles` are appended |
| `etc/aws-*.yaml`                  | Crypto provider token configurations (AWS KMS, the local emulator, minikube)                                                                         |
| `templates/`                      | Deployment (readiness on `/readyz`), ConfigMaps, ServiceAccount, ClusterRoles and bindings (`kubeca:operator`, `kubeca:csr-signer`), leader-election Role, webhook Service and `MutatingWebhookConfiguration`, PodDisruptionBudget, `ClusterIssuer`s, and the `ValidatingAdmissionPolicy` that lets only the operator write Certificates controlled by a Pod (Kubernetes 1.30+) |
| `values.yaml`                     | Defaults: operator and webhook on, `csrSigner.approve: enforce`, one `ClusterIssuer` named `kubeca` for namespaces labeled `kubeca.effectivesecurity/enabled=true` |
| `local.yaml`, `aws-dev.yaml`, `minikube.yaml` | Value overlays: the local KMS emulator, an EKS cluster with IRSA, the minikube e2e (adds the `e2e-5m` profile and exposes every profile)   |

Install sequence (release and namespace `kubeca`):

```sh
# 1. the issuing CA from the key ceremony (Documentation/key-ceremony.md)
kubectl create namespace kubeca
kubectl -n kubeca create secret generic kubeca-certs-secret-tf \
  --from-file=kubeca_ca_g1.pem --from-file=kubeca_ca_g1.key --from-file=kubeca_root.pem
# 2. the CRDs: Helm applies crds/ on install but never on upgrade
kubectl apply -f examples/kubeca/crds/
# 3. the chart with the overlay of your environment
helm upgrade --install kubeca examples/kubeca -n kubeca -f examples/kubeca/aws-dev.yaml
# 4. the operator is up when its ClusterIssuer is Ready
kubectl get clusterissuer kubeca
kubectl -n kubeca logs deploy/kubeca
```

`image.tag` is `main`, the image CI pushes on every push to `main`; pin a
`sha-<commit>` or `v0.9.<n>` tag in production (the image must know the
flags the chart passes, v0.9 or later).

Values that change behaviour: `operator.enabled`, `operator.podCertificatePolicy` and `operator.webhook.*`,
`clusterIssuers` (profiles exposed, SPIFFE trust domain, namespace selector,
name policy, CA bundle ConfigMap), `csrSigner.enabled` and
`csrSigner.approve` (`off` | `audit` | `enforce`), `extraProfiles`,
`clusterDomain`, `metricsPort`, `healthProbePort`, `certs.secretName`, `replicaCount.default`
(2 by default: the webhook's `failurePolicy: Fail` needs a replica up
during rollouts). Render and lint before installing:

```sh
helm lint examples/kubeca -f examples/kubeca/local.yaml
# --api-versions renders the admission policy, which Helm otherwise only
# renders against a cluster that serves it
helm template kubeca examples/kubeca -f examples/kubeca/local.yaml --namespace kubeca \
  --api-versions admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy
```

The chart's `ClusterIssuer` is deleted with the release; the
`Certificate`s of the applications then report `IssuerNotReady` until a
ClusterIssuer of that name exists again.
