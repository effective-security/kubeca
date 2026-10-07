package v1alpha1

import (
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SPIFFESpec enables the SPIFFE identity of the Pod flow.
type SPIFFESpec struct {
	// TrustDomain of the URIs `spiffe://<trustDomain>/ns/<ns>/sa/<sa>` the
	// Pod controller adds.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	TrustDomain string `json:"trustDomain"`
}

// IssuerPolicy is the cluster administrator's policy for the Certificates
// of a ClusterIssuer; the xpki profile regexes remain the CA-side gate.
type IssuerPolicy struct {
	// NamespaceSelector limits the namespaces whose Certificates may use
	// this issuer; nil allows all.
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	// MaxDuration is the upper bound of Certificate.spec.duration; the
	// profile expiry bounds it as well.
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('1m')",message="maxDuration must be at least 1m"
	MaxDuration *metav1.Duration `json:"maxDuration,omitempty"`
	// AllowedDNSNames, AllowedURIs and AllowedEmailAddresses are RE2
	// regexes a name must match; the subject common name must match
	// AllowedDNSNames. ${NAMESPACE}, ${NAME}, ${SERVICE_ACCOUNT} and
	// ${CLUSTER_DOMAIN} are substituted, regex-quoted, with the
	// Certificate's namespace, name, the ServiceAccount of the Pod it
	// belongs to (empty for a Certificate that no Pod owns) and the
	// cluster domain of the operator (-cluster-domain). An absent list
	// allows every name of that type; an empty list denies the type
	// (pointers keep the two apart).
	AllowedDNSNames       *[]string `json:"allowedDNSNames,omitempty"`
	AllowedURIs           *[]string `json:"allowedURIs,omitempty"`
	AllowedEmailAddresses *[]string `json:"allowedEmailAddresses,omitempty"`
	// AllowIPAddresses permits IP SANs; default false.
	AllowIPAddresses bool `json:"allowIPAddresses,omitempty"`
}

// CABundleSpec publishes the issuer's root bundle.
type CABundleSpec struct {
	// ConfigMapName of the ConfigMap (key ca.crt) the ClusterIssuer
	// controller maintains in every namespace that has a Certificate of
	// this issuer.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	ConfigMapName string `json:"configMapName"`
}

// ClusterIssuerSpec binds an xpki issuer to a policy.
// +kubebuilder:validation:XValidation:rule="!has(self.defaultProfile) || !has(self.profiles) || size(self.profiles) == 0 || self.defaultProfile in self.profiles",message="defaultProfile must be listed in profiles"
type ClusterIssuerSpec struct {
	// IssuerLabel is the label of the issuer in the CA configuration
	// (authority.issuers[].label). Immutable.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="issuerLabel is immutable"
	IssuerLabel string `json:"issuerLabel"`
	// Profiles this ClusterIssuer exposes; empty exposes every profile the
	// issuer serves. Unknown entries make the issuer not Ready.
	Profiles []string `json:"profiles,omitempty"`
	// DefaultProfile is used by Certificates and Pods that omit the profile.
	DefaultProfile string `json:"defaultProfile,omitempty"`
	// SPIFFE enables the SPIFFE URI of the Pod flow.
	SPIFFE *SPIFFESpec `json:"spiffe,omitempty"`
	// Policy for the Certificates of this issuer; nil allows everything the
	// profile allows.
	Policy *IssuerPolicy `json:"policy,omitempty"`
	// CABundle publishes the root bundle into a ConfigMap per namespace.
	CABundle *CABundleSpec `json:"caBundle,omitempty"`
}

// ProfileStatus describes a profile the issuer serves.
type ProfileStatus struct {
	Name     string          `json:"name"`
	Expiry   metav1.Duration `json:"expiry,omitempty"`
	Backdate metav1.Duration `json:"backdate,omitempty"`
	Usages   []string        `json:"usages,omitempty"`
}

// ClusterIssuerStatus is the observed state of a ClusterIssuer.
type ClusterIssuerStatus struct {
	// Conditions: Ready.
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// IssuerKeyID is the subject key identifier of the issuing certificate.
	IssuerKeyID string `json:"issuerKeyID,omitempty"`
	// CACertificate is the issuing certificate and its chain, PEM.
	CACertificate string `json:"caCertificate,omitempty"`
	// RootCertificate is the root bundle, PEM (what ca.crt carries).
	RootCertificate string `json:"rootCertificate,omitempty"`
	// CANotAfter is the expiry of the issuing certificate.
	CANotAfter *metav1.Time `json:"caNotAfter,omitempty"`
	// Profiles the ClusterIssuer exposes, sorted by name.
	Profiles []ProfileStatus `json:"profiles,omitempty"`
}

// ClusterIssuer binds an xpki issuer, loaded from the CA configuration at
// start-up, to a policy and publishes its CA certificate.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=cissuer
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Label",type=string,JSONPath=`.spec.issuerLabel`
// +kubebuilder:printcolumn:name="CA Not After",type=string,JSONPath=`.status.caNotAfter`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type ClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterIssuerSpec   `json:"spec"`
	Status ClusterIssuerStatus `json:"status,omitempty"`
}

// ClusterIssuerList is a list of ClusterIssuers.
// +kubebuilder:object:root=true
type ClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterIssuer `json:"items"`
}

// TrustDomain returns spec.spiffe.trustDomain or "".
func (c *ClusterIssuer) TrustDomain() string {
	if c.Spec.SPIFFE != nil {
		return c.Spec.SPIFFE.TrustDomain
	}
	return ""
}

// ExposesProfile reports whether the ClusterIssuer exposes the profile:
// every profile when spec.profiles is empty, else a listed one. The
// profile must still be served by the xpki issuer.
func (c *ClusterIssuer) ExposesProfile(name string) bool {
	return len(c.Spec.Profiles) == 0 || slices.Contains(c.Spec.Profiles, name)
}
