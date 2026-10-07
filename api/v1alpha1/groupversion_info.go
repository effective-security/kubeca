package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the group and version of the kinds in this package.
	GroupVersion = schema.GroupVersion{Group: GroupName, Version: Version}

	// SchemeBuilder registers the kinds of this package with a scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the kinds of this package to a scheme; the operator
	// calls it on the manager's scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

// addKnownTypes registers the kinds and the meta types of the group.
func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion,
		&Certificate{}, &CertificateList{},
		&ClusterIssuer{}, &ClusterIssuerList{},
	)
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
