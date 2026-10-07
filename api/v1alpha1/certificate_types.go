package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KeyAlgorithm is the private key algorithm of a Certificate.
// +kubebuilder:validation:Enum=ECDSA;RSA
type KeyAlgorithm string

// RotationPolicy says whether a renewal generates a new private key.
// +kubebuilder:validation:Enum=Always;Never
type RotationPolicy string

// IssuerReference names the ClusterIssuer of a Certificate. Kind and group
// are fixed in v1alpha1 (D-8).
type IssuerReference struct {
	// Name of the ClusterIssuer.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// KubernetesNames asks the controller to add the names of Services in the
// Certificate's namespace, like `kubecertinit -service-names`.
type KubernetesNames struct {
	// Services in the same namespace whose DNS names (`<svc>.<ns>.svc.<domain>`)
	// are added; a missing Service is a PolicyViolation (ServiceNotFound).
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Services []string `json:"services,omitempty"`
	// IncludeUnqualified also adds the `<svc>.<ns>.svc` form.
	IncludeUnqualified bool `json:"includeUnqualified,omitempty"`
	// IncludeClusterIP also adds the Services' cluster addresses (both
	// families of a dual-stack Service) as IP SANs.
	IncludeClusterIP bool `json:"includeClusterIP,omitempty"`
}

// PrivateKeySpec describes the private key the controller generates.
// +kubebuilder:validation:XValidation:rule="!has(self.size) || ((!has(self.algorithm) || self.algorithm == 'ECDSA') ? self.size in [256, 384, 521] : self.size in [2048, 3072, 4096])",message="size must be 256, 384 or 521 for ECDSA and 2048, 3072 or 4096 for RSA"
type PrivateKeySpec struct {
	// Algorithm of the key; default ECDSA.
	// +kubebuilder:default=ECDSA
	Algorithm KeyAlgorithm `json:"algorithm,omitempty"`
	// Size: the ECDSA curve (256, 384, 521) or the RSA modulus bits (2048,
	// 3072, 4096); default 256 for ECDSA and 2048 for RSA.
	// +kubebuilder:validation:Enum=256;384;521;2048;3072;4096
	Size int `json:"size,omitempty"`
	// RotationPolicy: Always (default) generates a new key for every
	// issuance; Never reuses the key stored in the Secret.
	// +kubebuilder:default=Always
	RotationPolicy RotationPolicy `json:"rotationPolicy,omitempty"`
}

// SecretTemplate adds labels and annotations to the Secret. Keys with the
// kubeca.effectivesecurity/ prefix are reserved and ignored; the others
// must be valid Kubernetes label and annotation keys and values, or the
// Certificate fails with PolicyViolation before anything is signed.
type SecretTemplate struct {
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// CertificateSpec describes one certificate and the Secret that holds it.
// +kubebuilder:validation:XValidation:rule="(has(self.dnsNames) && size(self.dnsNames) > 0) || (has(self.ipAddresses) && size(self.ipAddresses) > 0) || (has(self.uris) && size(self.uris) > 0) || (has(self.emailAddresses) && size(self.emailAddresses) > 0) || (has(self.kubernetesNames) && has(self.kubernetesNames.services) && size(self.kubernetesNames.services) > 0)",message="at least one name is required"
// +kubebuilder:validation:XValidation:rule="!has(self.renewBefore) || !has(self.duration) || duration(self.renewBefore) < duration(self.duration)",message="renewBefore must be shorter than duration"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.secretName) || has(self.secretName)",message="secretName cannot be removed once set"
type CertificateSpec struct {
	// IssuerRef names the ClusterIssuer that signs the certificate.
	IssuerRef IssuerReference `json:"issuerRef"`
	// Profile of the issuer; default the issuer's defaultProfile. It must
	// be one the ClusterIssuer exposes.
	Profile string `json:"profile,omitempty"`
	// SecretName of the kubernetes.io/tls Secret; default metadata.name.
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="secretName is immutable"
	SecretName string `json:"secretName,omitempty"`
	// CommonName of the subject; not added to the SAN automatically. The
	// issuer policy checks it against allowedDNSNames.
	// +kubebuilder:validation:MaxLength=64
	CommonName string `json:"commonName,omitempty"`
	// DNSNames, IPAddresses, URIs and EmailAddresses are the subject
	// alternative names; validated with xpki csr.ParseSAN, duplicates
	// dropped.
	DNSNames       []string `json:"dnsNames,omitempty"`
	IPAddresses    []string `json:"ipAddresses,omitempty"`
	URIs           []string `json:"uris,omitempty"`
	EmailAddresses []string `json:"emailAddresses,omitempty"`
	// KubernetesNames adds the names of Services in the namespace.
	KubernetesNames *KubernetesNames `json:"kubernetesNames,omitempty"`
	// Duration of the certificate; default the profile expiry. Bounded at
	// issuance by the profile expiry and the issuer policy's maxDuration.
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('1m')",message="duration must be at least 1m"
	Duration *metav1.Duration `json:"duration,omitempty"`
	// RenewBefore is how long before notAfter the certificate is renewed;
	// default a third of the duration.
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('30s')",message="renewBefore must be at least 30s"
	RenewBefore *metav1.Duration `json:"renewBefore,omitempty"`
	// PrivateKey parameters; default ECDSA P-256, rotated on every issuance.
	PrivateKey *PrivateKeySpec `json:"privateKey,omitempty"`
	// SecretTemplate adds labels and annotations to the Secret.
	SecretTemplate *SecretTemplate `json:"secretTemplate,omitempty"`
}

// CertificateStatus is the observed state of a Certificate.
type CertificateStatus struct {
	// Conditions: Ready and Issuing. observedGeneration tracks
	// metadata.generation.
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// NotBefore and NotAfter of the stored certificate.
	NotBefore *metav1.Time `json:"notBefore,omitempty"`
	NotAfter  *metav1.Time `json:"notAfter,omitempty"`
	// RenewalTime is notAfter − renewBefore − jitter.
	RenewalTime *metav1.Time `json:"renewalTime,omitempty"`
	// SerialNumber of the stored certificate, hex with colons.
	SerialNumber string `json:"serialNumber,omitempty"`
	// IssuerLabel and IssuerKeyID identify the xpki issuer that signed it.
	IssuerLabel string `json:"issuerLabel,omitempty"`
	IssuerKeyID string `json:"issuerKeyID,omitempty"`
	// Revision counts the issuances; the Secret carries the same value.
	Revision int64 `json:"revision,omitempty"`
	// FailedAttempts since the last successful issuance, with the time of
	// the last failure.
	FailedAttempts  int32        `json:"failedAttempts,omitempty"`
	LastFailureTime *metav1.Time `json:"lastFailureTime,omitempty"`
	// LastRenewRequest is the renew-requested annotation value the last
	// issuance honoured.
	LastRenewRequest string `json:"lastRenewRequest,omitempty"`
}

// Certificate describes one certificate and the Secret that holds it; the
// Certificate controller issues, renews and re-issues it.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=cert;certs
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.spec.secretName`
// +kubebuilder:printcolumn:name="Issuer",type=string,JSONPath=`.spec.issuerRef.name`
// +kubebuilder:printcolumn:name="Profile",type=string,JSONPath=`.spec.profile`
// +kubebuilder:printcolumn:name="Not After",type=string,JSONPath=`.status.notAfter`
// +kubebuilder:printcolumn:name="Renewal",type=string,JSONPath=`.status.renewalTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type Certificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateSpec   `json:"spec"`
	Status CertificateStatus `json:"status,omitempty"`
}

// CertificateList is a list of Certificates.
// +kubebuilder:object:root=true
type CertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Certificate `json:"items"`
}

// SecretNameOrDefault returns spec.secretName, or the Certificate name.
func (c *Certificate) SecretNameOrDefault() string {
	if c.Spec.SecretName != "" {
		return c.Spec.SecretName
	}
	return c.Name
}

// KeyAlgorithmOrDefault returns the key algorithm and size, with the
// defaults (ECDSA 256, RSA 2048) applied.
func (c *Certificate) KeyAlgorithmOrDefault() (KeyAlgorithm, int) {
	algo, size := KeyAlgorithmECDSA, 0
	if pk := c.Spec.PrivateKey; pk != nil {
		if pk.Algorithm != "" {
			algo = pk.Algorithm
		}
		size = pk.Size
	}
	if size == 0 {
		if algo == KeyAlgorithmRSA {
			size = DefaultRSAKeySize
		} else {
			size = DefaultECDSAKeySize
		}
	}
	return algo, size
}

// RotationPolicyOrDefault returns spec.privateKey.rotationPolicy or Always.
func (c *Certificate) RotationPolicyOrDefault() RotationPolicy {
	if pk := c.Spec.PrivateKey; pk != nil && pk.RotationPolicy != "" {
		return pk.RotationPolicy
	}
	return RotationPolicyAlways
}
