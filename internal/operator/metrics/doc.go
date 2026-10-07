// Package metrics defines the Prometheus metrics of the operator and
// registers them with controller-runtime's registry, so the manager's
// /metrics endpoint serves them next to the controller_runtime_* and xpki
// metrics. Every metric is registered once in init(). The package
// remembers the issuer and profile labels last observed for each
// Certificate, so that a Certificate that moves to another issuer or
// profile does not leave a stale expiration series behind.
// The functions are safe for concurrent use by the reconcile workers.
//
//	metrics.ObserveCertificate(cert.Namespace, cert.Name, issuer, profile, ready, notAfter, renewal)
//	metrics.ForgetCertificate(req.Namespace, req.Name) // the Certificate is gone
package metrics
