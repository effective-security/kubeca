// Package certinit implements the init-container side of the CSR flow:
// name discovery for a Pod, key and CSR generation, submission of a
// CertificateSigningRequest and the wait for its certificate.
//
// The init-container flow is deprecated since v0.9: it issues one
// certificate per Pod start and never renews it. New workloads use the
// operator's Certificate resource or the inject label
// (Documentation/design/operator.md); the package is kept for the
// migration period. (The package is not marked with a Deprecated: tag so
// that cmd/kubecertinit, the command of this flow, stays staticcheck
// clean.)
//
//	client, err := certinit.NewClient("", namespace) // "" = in-cluster config
//	if err != nil {
//		return err
//	}
//	r := &certinit.Request{
//		Namespace:     namespace,
//		PodName:       podName,
//		SignerName:    "kubeca.svc/peer",
//		CertDir:       "/etc/tls",
//		ClusterDomain: "cluster.local", // suffix of the names -query-k8s derives
//		QueryK8s:      true,
//	}
//	return r.Create(ctx, client)
//
// CertClient holds the three narrow interfaces the package needs
// (MinPods, MinServices, MinCertificates), so the tests use testify mocks
// instead of a cluster.
package certinit
