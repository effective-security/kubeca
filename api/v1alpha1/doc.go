// Package v1alpha1 holds the kubeca.effectivesecurity/v1alpha1 API: the
// Certificate and ClusterIssuer kinds the KubeCA operator reconciles, the
// constants (group, labels, annotations, condition types and reasons) that
// the operator and its clients share, and the generated deepcopy methods.
//
// The package imports nothing from internal/; the controllers in
// internal/operator import it. CRDs are generated from the kubebuilder
// markers with `make manifests` into config/crd/bases and copied into the
// chart (examples/kubeca/crds); deepcopy with `make generate`.
//
// +kubebuilder:object:generate=true
// +groupName=kubeca.effectivesecurity
package v1alpha1

//go:generate controller-gen object paths="./..."
