// Command kubecertinit requests a TLS certificate for the Pod it runs in.
//
// It is meant to run as an init container: it generates an ECDSA P-256 key,
// builds a CSR with the names derived from the Pod and its Services
// (-query-k8s) plus the explicit -san values, creates a
// certificates.k8s.io/v1 CertificateSigningRequest for the given -signer
// (`<issuer-label>/<profile>`), waits until kubeca signs it, and writes
// tls.key, tls.csr and tls.crt into -cert-dir, which the application
// containers share through a volume.
//
// Usage:
//
//	kubecertinit -namespace=$(NAMESPACE) -pod-name=$(POD_NAME) \
//	    -signer=kubeca.svc/peer -cert-dir=/etc/tls -query-k8s \
//	    -san=spiffe://example/ns/$(NAMESPACE)/sa/web,$(POD_IP)
//
// The exit status is 2 on any error. The wait for the certificate has no
// deadline (KUBECA-006).
package main
