// Package certificate implements the Certificate controller: for every
// Certificate it resolves the ClusterIssuer and the xpki profile, evaluates
// the policy, decides whether an issuance is needed (needsIssuance in
// renewal.go), generates the key and the CSR, signs with the Authority,
// writes the kubernetes.io/tls Secret (secret.go), records the status and
// requeues itself for the renewal time.
//
// Files: reconciler.go (Reconcile, watches, status), issuance.go (issuer
// resolution, names, validity, key, CSR, Sign), secret.go (read, conflict
// detection, write), renewal.go (needsIssuance, renewal time, jitter).
//
// Errors are split: a *permanentError (policy, conflict, a request the
// issuer rejects) is recorded in the Ready condition and an event and is
// not retried until the spec, the issuer or the Secret changes; every
// other error (API server, KMS) is returned so controller-runtime retries
// it with backoff.
package certificate
