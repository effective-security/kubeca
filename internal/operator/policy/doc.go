// Package policy evaluates a ClusterIssuer's policy against a Certificate
// request: the namespace selector, the duration bound and the allowed
// DNS, URI, email and IP names; the subject common name is checked
// against the DNS expressions. It is pure: the caller (the Certificate
// controller) passes the namespace labels, the ServiceAccount of the Pod
// the Certificate belongs to and the already assembled names, and a
// Violation says what was denied.
//
//	violation := policy.Evaluate(issuer.Spec.Policy, policy.Request{
//		Namespace:       cert.Namespace,
//		NamespaceLabels: ns.Labels,
//		Name:            cert.Name,
//		ServiceAccount:  serviceAccount, // of the owning Pod, "" otherwise
//		ClusterDomain:   "cluster.local",
//		CommonName:      cert.Spec.CommonName,
//		SAN:             san, // *csr.SAN from csr.ParseSAN
//	})
//
// Compile checks the regexes of a policy once, so the ClusterIssuer
// controller can report a bad policy instead of denying every request.
package policy
