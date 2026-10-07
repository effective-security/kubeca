// Command kubeca is the Kubernetes CA controller.
//
// It runs one controller-runtime manager with an xpki authority.Authority
// whose keys live in the configured crypto provider (-hsm-cfg: AWS KMS,
// GCP KMS or PKCS#11) and the issuers and profiles of -ca-cfg. Two sets of
// controllers share it:
//
//   - the CertificateSigningRequest signer (unless -disable-csr-signer):
//     it signs certificates.k8s.io/v1 CSRs whose signerName is
//     `<issuer-label>/<profile>`, after the in-process approver decided
//     them when -approve is enforce (KUBECA-001), and marks a rejected
//     request Failed (KUBECA-013). The init-container flow of
//     kubecertinit uses it and is deprecated.
//   - the operator (-enable-operator): the ClusterIssuer, Certificate and
//     Pod controllers of the kubeca.effectivesecurity/v1alpha1 API, which
//     issue short-lived certificates into Secrets and renew them, plus the
//     Pod mutating webhook (-enable-webhook) with a self-issued serving
//     certificate.
//
// Usage:
//
//	kubeca -ca-cfg=/kubeca/etc/ca-config.kubeca.yaml \
//	       -hsm-cfg=/kubeca/etc/aws-kms-us-west-2.yaml \
//	       -enable-operator -enable-webhook -webhook-namespace=kubeca \
//	       -approve=enforce -cluster-domain=cluster.local \
//	       -metrics-addr=:9090 -health-probe-addr=:8081 [-debug] [-stackdriver] \
//	       [-enable-leader-election=false] [-leader-election-id=kube-ca-leader-election]
//
// /healthz and /readyz are served on -health-probe-addr; with
// -enable-webhook, /readyz fails until the webhook server accepts TLS
// connections, so the webhook Service sends admission requests only to
// replicas that can answer them. Leader election is on by default in
// operator mode. See README.md and
// Documentation/design/operator.md for the flows and the RBAC the
// controller needs.
package main
