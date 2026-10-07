package v1alpha1

// Group and version of the API; also the prefix of every label and
// annotation the operator reads or writes.
const (
	GroupName = "kubeca.effectivesecurity"
	Version   = "v1alpha1"

	// KindCertificate and KindClusterIssuer are the kind names.
	KindCertificate   = "Certificate"
	KindClusterIssuer = "ClusterIssuer"
)

// Labels. LabelInject selects the Pods the Pod controller and the webhook
// handle; LabelManaged marks the Secrets the Certificate controller writes
// and restricts its informer cache; LabelAdopt lets an operator hand a
// pre-existing Secret to the controller; LabelEnabled is the conventional
// namespace opt-in label used by the examples' namespaceSelector.
const (
	LabelInject  = GroupName + "/inject"
	LabelManaged = GroupName + "/managed"
	LabelAdopt   = GroupName + "/adopt"
	LabelEnabled = GroupName + "/enabled"

	// TrueValue is the value of the boolean labels above.
	TrueValue = "true"
)

// Annotations on Pods (parameters of the Pod flow), on Certificates
// (manual renewal) and on Secrets (provenance of the stored certificate).
const (
	// AnnotationIssuer names the ClusterIssuer of a Pod's certificate; it is
	// also written on the Secret.
	AnnotationIssuer = GroupName + "/issuer"
	// AnnotationProfile selects the profile; defaults to the issuer's
	// defaultProfile. Also written on the Secret.
	AnnotationProfile = GroupName + "/profile"
	// AnnotationSAN adds comma-separated names to a Pod's certificate.
	AnnotationSAN = GroupName + "/san"
	// AnnotationSecretName is the Secret a Pod's certificate is written to;
	// default <pod-name>-tls. The webhook sets a generated name for
	// generateName Pods.
	AnnotationSecretName = GroupName + "/secret-name"
	// AnnotationMountPath is the webhook's mount path; default /etc/tls.
	AnnotationMountPath = GroupName + "/mount-path"
	// AnnotationContainers lists, comma-separated, the containers the
	// webhook mounts the Secret into; default all.
	AnnotationContainers = GroupName + "/containers"
	// AnnotationDuration and AnnotationRenewBefore override the Certificate
	// fields of a Pod's certificate.
	AnnotationDuration    = GroupName + "/duration"
	AnnotationRenewBefore = GroupName + "/renew-before"
	// AnnotationRenewRequested on a Certificate triggers a renewal when its
	// value differs from status.lastRenewRequest. On a Secret it is the
	// request the stored certificate honoured, restored into the status
	// with AnnotationRevision when the status write after the issuance
	// failed.
	AnnotationRenewRequested = GroupName + "/renew-requested"

	// AnnotationCertificate on a Secret is "<namespace>/<name>" of the
	// owning Certificate.
	AnnotationCertificate = GroupName + "/certificate"
	// AnnotationSerial, AnnotationNotBefore, AnnotationNotAfter,
	// AnnotationIssuedAt and AnnotationRevision on a Secret describe the
	// stored certificate; issued-at is when the controller signed it (the
	// renewal is never scheduled sooner than a minute after it), and
	// AnnotationDuration (the Pod annotation key reused) the lifetime that
	// was requested, so a changed duration re-issues.
	AnnotationSerial    = GroupName + "/serial"
	AnnotationNotBefore = GroupName + "/not-before"
	AnnotationNotAfter  = GroupName + "/not-after"
	AnnotationIssuedAt  = GroupName + "/issued-at"
	AnnotationRevision  = GroupName + "/revision"
)

// Condition types of Certificate and ClusterIssuer status.
const (
	// ConditionReady is True when the Secret holds a valid certificate that
	// matches the spec (Certificate), or when the issuer is loaded and its
	// CA is valid (ClusterIssuer).
	ConditionReady = "Ready"
	// ConditionIssuing is True while an issuance is in progress or being
	// retried; its reason is the trigger.
	ConditionIssuing = "Issuing"
)

// Reasons of the Ready condition of a Certificate.
const (
	ReasonIssued          = "Issued"
	ReasonPending         = "Pending"
	ReasonIssuerNotReady  = "IssuerNotReady"
	ReasonPolicyViolation = "PolicyViolation"
	ReasonIssuanceFailed  = "IssuanceFailed"
	ReasonSecretConflict  = "SecretConflict"
	ReasonExpired         = "Expired"
)

// Reasons of the Issuing condition of a Certificate: the issuance trigger
// while True, the outcome while False. The triggers are also the value of
// the `trigger` label of the kubeca_issuance_total metric.
const (
	ReasonInitial       = "Initial"
	ReasonRenewal       = "Renewal"
	ReasonSpecChanged   = "SpecChanged"
	ReasonSecretMissing = "SecretMissing"
	ReasonCAChanged     = "CAChanged"
	ReasonRequested     = "Requested"
	ReasonFailed        = "Failed"
)

// Reasons of the Ready condition of a ClusterIssuer.
const (
	ReasonLoaded          = "Loaded"
	ReasonIssuerNotFound  = "IssuerNotFound"
	ReasonProfileNotFound = "ProfileNotFound"
	ReasonInvalidPolicy   = "InvalidPolicy"
	ReasonCAExpiring      = "CAExpiring"
	ReasonCAExpired       = "CAExpired"
)

// Event reasons. A failure recorded in a condition is also an event with
// the condition reason (PolicyViolation, IssuanceFailed, SecretConflict,
// IssuerNotReady on Certificates; IssuerNotFound, ProfileNotFound,
// InvalidPolicy, CAExpiring, CAExpired on ClusterIssuers).
const (
	EventIssued             = "Issued"
	EventRenewed            = "Renewed"
	EventReady              = "Ready"
	EventCertificateCreated = "CertificateCreated"
	EventCertificateUpdated = "CertificateUpdated"
	EventInvalidPod         = "InvalidPod"
	// EventConfigMapConflict on a ClusterIssuer: a ConfigMap named by
	// spec.caBundle exists in a namespace and is not managed by kubeca.
	EventConfigMapConflict = "ConfigMapConflict"
)

// Keys of the kubernetes.io/tls Secret the Certificate controller writes:
// the values of corev1.TLSCertKey, corev1.TLSPrivateKeyKey and
// corev1.ServiceAccountRootCAKey, spelled out so that this package keeps
// importing k8s.io/apimachinery only (a test of the Certificate controller
// pins them to the corev1 constants).
const (
	SecretKeyCertificate = "tls.crt"
	SecretKeyPrivateKey  = "tls.key"
	SecretKeyCA          = "ca.crt"
)

// Defaults of the Pod flow and the webhook.
const (
	// DefaultMountPath is where the webhook mounts the Secret.
	DefaultMountPath = "/etc/tls"
	// DefaultSecretSuffix is appended to a Pod name for the default Secret
	// name of the Pod flow.
	DefaultSecretSuffix = "-tls"
	// GeneratedSecretPrefix starts the Secret names the webhook generates
	// for generateName Pods.
	GeneratedSecretPrefix = "kubeca-"
	// InjectedVolumeName is the name of the Secret volume the webhook adds.
	InjectedVolumeName = "kubeca-tls"
)

// Key algorithms and sizes of Certificate.spec.privateKey.
const (
	KeyAlgorithmECDSA KeyAlgorithm = "ECDSA"
	KeyAlgorithmRSA   KeyAlgorithm = "RSA"

	DefaultECDSAKeySize = 256
	DefaultRSAKeySize   = 2048

	RotationPolicyAlways RotationPolicy = "Always"
	RotationPolicyNever  RotationPolicy = "Never"
)
