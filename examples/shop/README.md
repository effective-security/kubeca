# shop: application-side demo of the operator

What an application team deploys in its own namespace once kubeca is
installed from [`../kubeca`](../kubeca). Nothing here belongs to the CA:
the CA configuration, the profiles, the `ClusterIssuer` and the RBAC of
the controller all live in the chart. The namespace is `shop`; the
workload containers run `certmonitor` (`cmd/certmonitor`), which logs the
certificate it loaded and every renewal (`kubectl -n shop logs ...`). Its
image is distroless, so `kubectl exec` into it does not work; read the
files from the Secret. Every manifest runs as is in the minikube setup of
the root README (`make minikube-images` loads the `certmonitor` image).

Prerequisites: the chart installed with `operator.enabled: true` (the
default) and `kubectl get clusterissuer kubeca` showing `READY True`.

| Step | File                                                     | What it shows                                                                                                                                           |
| ---- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | [`namespace.yaml`](namespace.yaml)                       | The namespace with the opt-in label `kubeca.effectivesecurity/enabled=true` (the ClusterIssuer policy selects it) and the ServiceAccounts of the demos  |
| 2    | [`certificate.yaml`](certificate.yaml)                   | One `Certificate` per workload (`web-tls`, profile `server-24h`, Service names and SPIFFE ID), mounted by a Deployment as a Secret volume               |
| 3    | [`pod.yaml`](pod.yaml)                                   | A Pod with a known name and the inject label: the Pod controller creates `Certificate/worker-1` owned by the Pod, the webhook injects `worker-1-tls`; `certmonitor` prints the certificate and each renewal (15-minute lifetime, renewed every 3 to 5 minutes) |
| 4    | [`deployment-injected.yaml`](deployment-injected.yaml)   | Per-Pod certificates for a Deployment: the webhook generates a Secret name per Pod and mounts it into the `api` container only                          |
| 5    | [`statefulset.yaml`](statefulset.yaml)                   | A StatefulSet sharing one wildcard certificate (`*.db.shop.svc.cluster.local`) over its headless Service                                                |
| e2e  | [`e2e/workload.yaml`](e2e/workload.yaml)                 | The workload of `make minikube-test`: a 5-minute certificate renewed during the test and a bare Pod injected by the webhook (names prefixed `e2e-`)     |

Apply in order and watch:

```sh
kubectl apply -f examples/shop/namespace.yaml
kubectl apply -f examples/shop/certificate.yaml
kubectl -n shop get certs                    # READY, SECRET, NOT AFTER, RENEWAL
kubectl -n shop get secret web-tls -o yaml   # tls.crt, tls.key, ca.crt
kubectl -n shop get configmap kubeca-ca      # the root bundle (ClusterIssuer.spec.caBundle)
kubectl apply -f examples/shop/pod.yaml
kubectl -n shop logs -f worker-1             # "certificate loaded", then "certificate reloaded" every 3 to 5 min
kubectl apply -f examples/shop/deployment-injected.yaml
kubectl -n shop get pods -o custom-columns=NAME:.metadata.name,SECRET:.metadata.annotations.kubeca\.effectivesecurity/secret-name
kubectl apply -f examples/shop/statefulset.yaml
kubectl -n shop get certs,events
```

Renew a certificate by hand with
`kubectl -n shop annotate cert web-tls kubeca.effectivesecurity/renew-requested=$(date +%s) --overwrite`.
Remove everything with `kubectl delete ns shop` (the Secrets and the
Pod-owned Certificates are garbage-collected).

Names must satisfy both the ClusterIssuer policy (`allowedDNSNames`,
`allowedURIs`, the namespace selector) and the xpki profile's
`allowed_fields`/regexes; the `Ready` condition and the events say which
one rejected a request. The SPIFFE trust domain of these manifests is
`cluster.local`, the chart's default.
