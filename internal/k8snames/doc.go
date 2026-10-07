// Package k8snames derives the names a Kubernetes Pod may carry in a
// certificate: its Pod DNS name, the hostname/subdomain name, the names
// and addresses of the Services that select it, and its SPIFFE ID. The
// functions are pure (they take the Pod and the Services, they do not call
// the API) and are shared by the init container (internal/certinit), the
// CSR approver (internal/controller) and the operator's Pod controller
// (internal/operator/pod).
//
//	names := k8snames.ForPod(pod, services, k8snames.Options{
//		ClusterDomain:      "cluster.local",
//		IncludeUnqualified: true,
//	})
//	san := append(names.DNS, names.IPs...)
package k8snames
