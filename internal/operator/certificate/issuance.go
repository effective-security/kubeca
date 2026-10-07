package certificate

import (
	"cmp"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/kubeca/api/v1alpha1"
	"github.com/effective-security/kubeca/internal/k8snames"
	"github.com/effective-security/kubeca/internal/operator/policy"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/csr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// defaultBackdate is xpki's backdate for a profile without one.
	defaultBackdate = 5 * time.Minute
	// renewBeforeFraction: renewBefore defaults to duration / 3.
	renewBeforeFraction = 3
	// minUsableLifetime is the least a certificate must stay valid after
	// its issuance (duration minus the profile backdate): below it the
	// renewal could not be scheduled minRenewalDelay after the issuance
	// and still precede the expiry.
	minUsableLifetime = 2 * time.Minute

	pemTypeCertificateRequest = "CERTIFICATE REQUEST"
	pemTypeCertificate        = "CERTIFICATE"

	// podKind and podAPIVersion identify the owner reference of a Pod
	// flow Certificate.
	podKind       = "Pod"
	podAPIVersion = "v1"
)

// issuanceContext is everything resolved from the Certificate, the
// ClusterIssuer and the Authority before the issuance decision.
type issuanceContext struct {
	issuer      *v1alpha1.ClusterIssuer
	xpkiIssuer  *authority.Issuer
	profileName string
	profile     *authority.CertProfile
	// san are the validated, deduplicated names; names is their string
	// form for the CSR.
	san   *csr.SAN
	names []string
	// duration is the bounded lifetime; renewBefore the effective one.
	duration    time.Duration
	renewBefore time.Duration
	backdate    time.Duration
	algorithm   v1alpha1.KeyAlgorithm
	keySize     int
}

// resolve validates the Secret template, finds the ClusterIssuer, the
// xpki issuer and the profile, assembles and validates the names and
// evaluates the policy.
func (r *Reconciler) resolve(ctx context.Context, cert *v1alpha1.Certificate) (*issuanceContext, error) {
	if err := validateSecretTemplate(cert); err != nil {
		return nil, err
	}
	ic := &issuanceContext{issuer: &v1alpha1.ClusterIssuer{}}
	issuerName := cert.Spec.IssuerRef.Name
	if err := r.Get(ctx, client.ObjectKey{Name: issuerName}, ic.issuer); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, permanent(v1alpha1.ReasonIssuerNotReady, fmt.Sprintf("ClusterIssuer %q not found", issuerName))
		}
		return nil, errors.WithMessagef(err, "unable to get ClusterIssuer %q", issuerName)
	}
	if ready := meta.FindStatusCondition(ic.issuer.Status.Conditions, v1alpha1.ConditionReady); ready == nil || ready.Status != metav1.ConditionTrue {
		msg := fmt.Sprintf("ClusterIssuer %q is not ready", issuerName)
		if ready != nil {
			msg += ": " + ready.Reason + ": " + ready.Message
		}
		return nil, permanent(v1alpha1.ReasonIssuerNotReady, msg)
	}
	xpkiIssuer, err := r.Authority.GetIssuerByLabel(ic.issuer.Spec.IssuerLabel)
	if err != nil {
		return nil, permanent(v1alpha1.ReasonIssuerNotReady, fmt.Sprintf("issuer %q of ClusterIssuer %q is not loaded", ic.issuer.Spec.IssuerLabel, issuerName))
	}
	ic.xpkiIssuer = xpkiIssuer

	ic.profileName = cert.Spec.Profile
	if ic.profileName == "" {
		ic.profileName = ic.issuer.Spec.DefaultProfile
	}
	if ic.profileName == "" {
		return nil, permanent(v1alpha1.ReasonPolicyViolation, fmt.Sprintf("no profile: set spec.profile or defaultProfile on ClusterIssuer %q", issuerName))
	}
	if !ic.issuer.ExposesProfile(ic.profileName) {
		return nil, permanent(v1alpha1.ReasonPolicyViolation, fmt.Sprintf("profile %q is not exposed by ClusterIssuer %q", ic.profileName, issuerName))
	}
	ic.profile = xpkiIssuer.Profile(ic.profileName)
	if ic.profile == nil {
		return nil, permanent(v1alpha1.ReasonPolicyViolation, fmt.Sprintf("profile %q is not served by issuer %q", ic.profileName, ic.issuer.Spec.IssuerLabel))
	}

	if err := r.assembleNames(ctx, cert, ic); err != nil {
		return nil, err
	}
	if err := r.evaluatePolicy(ctx, cert, ic); err != nil {
		return nil, err
	}

	var requested time.Duration
	if cert.Spec.Duration != nil {
		requested = cert.Spec.Duration.Duration
	}
	ic.duration = policy.BoundDuration(requested, ic.profile.Expiry.TimeDuration(), policy.MaxDuration(ic.issuer.Spec.Policy))
	if ic.duration <= 0 {
		return nil, permanent(v1alpha1.ReasonPolicyViolation, fmt.Sprintf("profile %q has no expiry and the Certificate no duration", ic.profileName))
	}
	ic.backdate = ic.profile.Backdate.TimeDuration()
	if ic.backdate == 0 {
		ic.backdate = defaultBackdate
	}
	usable := ic.duration - ic.backdate
	if usable < minUsableLifetime {
		return nil, permanent(v1alpha1.ReasonPolicyViolation,
			fmt.Sprintf("duration %s minus the backdate %s of profile %q leaves less than %s of usable lifetime", ic.duration, ic.backdate, ic.profileName, minUsableLifetime))
	}
	ic.renewBefore = ic.duration / renewBeforeFraction
	if rb := cert.Spec.RenewBefore; rb != nil && rb.Duration > 0 && rb.Duration < ic.duration {
		ic.renewBefore = rb.Duration
	}
	// the renewal must land after the issuance plus minRenewalDelay even
	// when the issuance happened at the end of the (truncated) minute
	if ic.renewBefore > usable-minRenewalDelay {
		ic.renewBefore = usable / renewBeforeFraction
	}
	ic.algorithm, ic.keySize = cert.KeyAlgorithmOrDefault()
	return ic, nil
}

// assembleNames collects the spec names and the Service names of
// spec.kubernetesNames, validates them with csr.ParseSAN and checks that
// the profile copies every name type present.
func (r *Reconciler) assembleNames(ctx context.Context, cert *v1alpha1.Certificate, ic *issuanceContext) error {
	names := slices.Concat(cert.Spec.DNSNames, cert.Spec.IPAddresses, cert.Spec.URIs, cert.Spec.EmailAddresses)
	if kn := cert.Spec.KubernetesNames; kn != nil {
		opts := k8snames.Options{ClusterDomain: r.ClusterDomain, IncludeUnqualified: kn.IncludeUnqualified}
		for _, name := range kn.Services {
			var svc corev1.Service
			if err := r.Get(ctx, client.ObjectKey{Namespace: cert.Namespace, Name: name}, &svc); err != nil {
				if apierrors.IsNotFound(err) {
					return permanent(v1alpha1.ReasonPolicyViolation, fmt.Sprintf("ServiceNotFound: Service %q not found in namespace %q", name, cert.Namespace))
				}
				return errors.WithMessagef(err, "unable to get Service %s/%s", cert.Namespace, name)
			}
			names = append(names, k8snames.ServiceNames(svc.Name, svc.Namespace, opts)...)
			if kn.IncludeClusterIP {
				names = append(names, k8snames.ClusterIPs(&svc)...)
			}
		}
	}
	san, err := csr.ParseSAN(names)
	if err != nil {
		return permanent(v1alpha1.ReasonPolicyViolation, "invalid names: "+err.Error())
	}
	if len(san.DNSNames)+len(san.IPAddresses)+len(san.URIs)+len(san.EmailAddresses) == 0 {
		return permanent(v1alpha1.ReasonPolicyViolation, "at least one name is required")
	}
	if fields := ic.profile.AllowedCSRFields; fields != nil {
		switch {
		case len(san.DNSNames) > 0 && !fields.DNSNames:
			return permanent(v1alpha1.ReasonPolicyViolation, fmt.Sprintf("profile %q does not allow DNS names", ic.profileName))
		case len(san.IPAddresses) > 0 && !fields.IPAddresses:
			return permanent(v1alpha1.ReasonPolicyViolation, fmt.Sprintf("profile %q does not allow IP addresses", ic.profileName))
		case len(san.URIs) > 0 && !fields.URIs:
			return permanent(v1alpha1.ReasonPolicyViolation, fmt.Sprintf("profile %q does not allow URIs", ic.profileName))
		case len(san.EmailAddresses) > 0 && !fields.EmailAddresses:
			return permanent(v1alpha1.ReasonPolicyViolation, fmt.Sprintf("profile %q does not allow email addresses", ic.profileName))
		}
	}
	ic.san = san
	ic.names = sanStrings(san)
	return nil
}

// evaluatePolicy applies the ClusterIssuer policy; the namespace labels
// are read only when the policy has a namespace selector.
func (r *Reconciler) evaluatePolicy(ctx context.Context, cert *v1alpha1.Certificate, ic *issuanceContext) error {
	p := ic.issuer.Spec.Policy
	if p == nil {
		return nil
	}
	serviceAccount, err := r.podServiceAccount(ctx, cert)
	if err != nil {
		return err
	}
	req := policy.Request{
		Namespace:      cert.Namespace,
		Name:           cert.Name,
		ServiceAccount: serviceAccount,
		ClusterDomain:  r.ClusterDomain,
		CommonName:     cert.Spec.CommonName,
		SAN:            ic.san,
	}
	if p.NamespaceSelector != nil {
		var ns corev1.Namespace
		if err := r.Get(ctx, client.ObjectKey{Name: cert.Namespace}, &ns); err != nil {
			return errors.WithMessagef(err, "unable to get Namespace %q", cert.Namespace)
		}
		req.NamespaceLabels = ns.Labels
	}
	if v := policy.Evaluate(p, req); v != nil {
		return permanent(v1alpha1.ReasonPolicyViolation, v.Error())
	}
	return nil
}

// podServiceAccount returns the ServiceAccount the policy placeholder
// ${SERVICE_ACCOUNT} expands to: that of the labeled Pod (read from the
// cache, which holds labeled Pods only) that controls the Certificate,
// when the Certificate is exactly the one the Pod controller writes for
// it: the owner reference carries the Pod's UID, and the name, secretName
// and issuer are the ones derived from the Pod (v1alpha1.PodCertificateName,
// v1alpha1.PodSecretName, the issuer annotation). Anything else, a direct
// Certificate or an annotation included, expands it to "", so a policy
// that uses the placeholder denies the request. An error is returned only
// for API failures.
//
// Owner references are written by whoever creates the Certificate, so the
// chart's ValidatingAdmissionPolicy (templates/admission-policy.yaml)
// lets only the operator create a Pod-controlled Certificate or change its
// spec or owners. Without it, a Certificate author who copies a Pod's UID
// can still only have the Pod's identity written into the Pod's own
// Secret, which nobody can read who cannot already read that Secret.
func (r *Reconciler) podServiceAccount(ctx context.Context, cert *v1alpha1.Certificate) (string, error) {
	owner := metav1.GetControllerOf(cert)
	if owner == nil || owner.Kind != podKind || owner.APIVersion != podAPIVersion {
		return "", nil
	}
	var pod corev1.Pod
	if err := r.Get(ctx, client.ObjectKey{Namespace: cert.Namespace, Name: owner.Name}, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			return "", nil
		}
		return "", errors.WithMessagef(err, "unable to get Pod %s/%s", cert.Namespace, owner.Name)
	}
	secretAnnotation := pod.Annotations[v1alpha1.AnnotationSecretName]
	if pod.UID != owner.UID ||
		cert.Name != v1alpha1.PodCertificateName(pod.Name, secretAnnotation) ||
		cert.SecretNameOrDefault() != v1alpha1.PodSecretName(pod.Name, secretAnnotation) ||
		cert.Spec.IssuerRef.Name != pod.Annotations[v1alpha1.AnnotationIssuer] {
		return "", nil
	}
	return cmp.Or(pod.Spec.ServiceAccountName, k8snames.DefaultServiceAccount), nil
}

// issued is the outcome of one signature.
type issued struct {
	leaf *x509.Certificate
	// certPEM is the leaf followed by the issuer chain; keyPEM the private key.
	certPEM []byte
	keyPEM  []byte
}

// issue generates (or reuses) the key, builds the CSR and signs it. The
// names travel in the CSR so that the profile's allowed_fields and
// regexes apply; the subject common name is passed as the trusted request
// subject. The validity window is computed explicitly (XPKI-054).
func (r *Reconciler) issue(cert *v1alpha1.Certificate, ic *issuanceContext, s *stored) (*issued, error) {
	key, err := r.privateKey(cert, ic, s)
	if err != nil {
		return nil, err
	}
	template := x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: cert.Spec.CommonName},
		DNSNames:       ic.san.DNSNames,
		IPAddresses:    ic.san.IPAddresses,
		URIs:           ic.san.URIs,
		EmailAddresses: ic.san.EmailAddresses,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to create CSR")
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificateRequest, Bytes: der})

	// the clock is read right before Sign so that the issuer's own "now"
	// is in the same minute (see signerr.IsPermanent on the window check)
	now := r.Clock.Now()
	notBefore := now.Truncate(time.Minute).Add(-ic.backdate)
	req := csr.SignRequest{
		Request:   string(csrPEM),
		Profile:   ic.profileName,
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(ic.duration),
	}
	if cert.Spec.CommonName != "" {
		req.Subject = &csr.X509Subject{CommonName: cert.Spec.CommonName}
	}
	leaf, raw, err := ic.xpkiIssuer.Sign(req)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to sign")
	}
	if detail := namesDrift(leaf, ic.san); detail != "" {
		return nil, permanent(v1alpha1.ReasonIssuanceFailed,
			fmt.Sprintf("profile %q issued a certificate that does not carry the requested names (%s); check its allowed_fields", ic.profileName, detail))
	}
	keyPEM, err := certutil.EncodePrivateKeyToPEM(key)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to encode private key")
	}
	return &issued{leaf: leaf, certPEM: certificatePEM(string(raw), ic), keyPEM: keyPEM}, nil
}

// certificatePEM is the tls.crt content: the leaf followed by the issuer
// chain (Issuer.PEM, the issuing certificate and its bundle).
func certificatePEM(leafPEM string, ic *issuanceContext) []byte {
	certPEM := strings.TrimSpace(leafPEM) + "\n"
	if chain := strings.TrimSpace(ic.xpkiIssuer.PEM()); chain != "" {
		certPEM += chain + "\n"
	}
	return []byte(certPEM)
}

// privateKey returns the stored key when rotationPolicy is Never and the
// key matches the spec, else a new key.
func (r *Reconciler) privateKey(cert *v1alpha1.Certificate, ic *issuanceContext, s *stored) (crypto.Signer, error) {
	if cert.RotationPolicyOrDefault() == v1alpha1.RotationPolicyNever && s != nil && s.key != nil && keyMatches(s.key.Public(), ic.algorithm, ic.keySize) {
		return s.key, nil
	}
	return generateKey(ic.algorithm, ic.keySize)
}

// generateKey creates an ECDSA or RSA key of the given size.
func generateKey(algorithm v1alpha1.KeyAlgorithm, size int) (crypto.Signer, error) {
	switch algorithm {
	case v1alpha1.KeyAlgorithmECDSA, "":
		var curve elliptic.Curve
		switch size {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, permanent(v1alpha1.ReasonPolicyViolation, fmt.Sprintf("unsupported ECDSA key size %d", size))
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		return key, errors.WithMessage(err, "unable to generate ECDSA key")
	case v1alpha1.KeyAlgorithmRSA:
		switch size {
		case 2048, 3072, 4096:
		default:
			return nil, permanent(v1alpha1.ReasonPolicyViolation, fmt.Sprintf("unsupported RSA key size %d", size))
		}
		key, err := rsa.GenerateKey(rand.Reader, size)
		return key, errors.WithMessage(err, "unable to generate RSA key")
	default:
		return nil, permanent(v1alpha1.ReasonPolicyViolation, fmt.Sprintf("unsupported key algorithm %q", algorithm))
	}
}

// keyMatches reports whether a public key has the algorithm and size.
func keyMatches(pub crypto.PublicKey, algorithm v1alpha1.KeyAlgorithm, size int) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return (algorithm == v1alpha1.KeyAlgorithmECDSA || algorithm == "") && k.Curve.Params().BitSize == size
	case *rsa.PublicKey:
		return algorithm == v1alpha1.KeyAlgorithmRSA && k.N.BitLen() == size
	default:
		return false
	}
}

// sanStrings returns the names of a SAN as strings, in type order.
func sanStrings(san *csr.SAN) []string {
	names := slices.Clone(san.DNSNames)
	for _, ip := range san.IPAddresses {
		names = append(names, ip.String())
	}
	for _, u := range san.URIs {
		names = append(names, u.String())
	}
	return append(names, san.EmailAddresses...)
}

// namesDrift compares the names of a certificate with the requested SAN
// and describes the first difference, or "".
func namesDrift(leaf *x509.Certificate, san *csr.SAN) string {
	if !sameFold(leaf.DNSNames, san.DNSNames) {
		return fmt.Sprintf("DNS names %v, requested %v", leaf.DNSNames, san.DNSNames)
	}
	if !sameIPs(leaf.IPAddresses, san.IPAddresses) {
		return fmt.Sprintf("IP addresses %v, requested %v", leaf.IPAddresses, san.IPAddresses)
	}
	leafURIs := make([]string, 0, len(leaf.URIs))
	for _, u := range leaf.URIs {
		leafURIs = append(leafURIs, u.String())
	}
	wantURIs := make([]string, 0, len(san.URIs))
	for _, u := range san.URIs {
		wantURIs = append(wantURIs, u.String())
	}
	if !sameStrings(leafURIs, wantURIs) {
		return fmt.Sprintf("URIs %v, requested %v", leafURIs, wantURIs)
	}
	if !sameFold(leaf.EmailAddresses, san.EmailAddresses) {
		return fmt.Sprintf("email addresses %v, requested %v", leaf.EmailAddresses, san.EmailAddresses)
	}
	return ""
}

func sameStrings(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}

func sameFold(a, b []string) bool {
	lower := func(list []string) []string {
		out := make([]string, 0, len(list))
		for _, s := range list {
			out = append(out, strings.ToLower(s))
		}
		return out
	}
	return sameStrings(lower(a), lower(b))
}

func sameIPs(a, b []net.IP) bool {
	format := func(list []net.IP) []string {
		out := make([]string, 0, len(list))
		for _, ip := range list {
			out = append(out, ip.String())
		}
		return out
	}
	return sameStrings(format(a), format(b))
}

// formatSerial renders a serial number as upper-case hex pairs separated
// by colons.
func formatSerial(serial *big.Int) string {
	raw := serial.Bytes()
	if len(raw) == 0 {
		raw = []byte{0}
	}
	parts := make([]string, 0, len(raw))
	for _, b := range raw {
		parts = append(parts, fmt.Sprintf("%02X", b))
	}
	return strings.Join(parts, ":")
}
