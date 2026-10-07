// Package issuer implements the ClusterIssuer controller: it resolves
// spec.issuerLabel in the running xpki Authority, checks the exposed
// profiles and the policy, publishes the CA certificate, the root bundle,
// the subject key id and the profiles in the status, flags an expiring or
// expired CA, and writes the root bundle into the ConfigMap named by
// spec.caBundle in every namespace that holds a Certificate of the issuer.
//
// The Authority is loaded once at start-up, so a ClusterIssuer that is not
// Ready because of IssuerNotFound stays so until kubeca restarts with a
// configuration that serves the label.
package issuer
