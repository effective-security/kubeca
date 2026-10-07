// Package pod implements the Pod controller of the operator: for every
// Pod labeled kubeca.effectivesecurity/inject=true it derives the names
// the Pod may carry (internal/k8snames), the SPIFFE ID of its
// ServiceAccount when the ClusterIssuer has a trust domain, and the names
// of the san annotation, and creates or updates a Certificate owned by
// the Pod. The Certificate controller issues it into the Secret the Pod
// mounts; the kubelet starts the containers once the Secret exists, and
// the Certificate and the Secret are garbage-collected with the Pod.
//
// The informer cache of the manager only holds labeled Pods
// (operator.CacheOptions), so the controller never reads other Pods.
package pod
