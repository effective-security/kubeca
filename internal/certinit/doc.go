// Package certinit implements the init-container side of the CSR flow:
// name discovery for a Pod, key and CSR generation, submission of a
// CertificateSigningRequest and the wait for its certificate.
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
