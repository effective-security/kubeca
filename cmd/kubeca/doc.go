// Command kubeca is the Kubernetes CA controller.
//
// It runs a controller-runtime manager that watches certificates.k8s.io/v1
// CertificateSigningRequest objects whose signerName is
// `<issuer-label>/<profile>` for an issuer loaded from the xpki CA
// configuration (-ca-cfg) and signs them with a key held by the configured
// crypto provider (-hsm-cfg: AWS KMS, GCP KMS or PKCS#11). The signed
// certificate followed by the issuer chain is written to the CSR status.
//
// Usage:
//
//	kubeca -ca-cfg=/kubeca/etc/ca-config.kubeca.yaml \
//	       -hsm-cfg=/kubeca/etc/aws-kms-us-west-2.yaml \
//	       -metrics-addr=:9090 [-debug] [-stackdriver] \
//	       [-enable-leader-election -leader-election-id=kube-ca-leader-election]
//
// See README.md and Documentation/design/initcontainer.md for the
// end-to-end flow and the RBAC the controller needs.
package main
