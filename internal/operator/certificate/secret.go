package certificate

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/kubeca/api/v1alpha1"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// stored is the parsed content of the Secret of a Certificate.
type stored struct {
	secret *corev1.Secret
	// leaf and chain come from tls.crt; key from tls.key. Any of them is
	// nil when the data is missing or unparsable, and problem says why.
	leaf    *x509.Certificate
	chain   []*x509.Certificate
	key     crypto.Signer
	problem string
	// cached is true when the Secret came from the informer cache, which
	// can lag the controller's own last write (see confirmSecret)
	cached bool
}

// readSecret returns the Secret of the Certificate, nil when it does not
// exist, or a SecretConflict permanentError when it exists and is not
// ours or is not a kubernetes.io/tls Secret (conflictMessage), before any
// issuance or adoption decision. The cache holds only managed Secrets, so
// a miss is confirmed with the uncached APIReader.
func (r *Reconciler) readSecret(ctx context.Context, cert *v1alpha1.Certificate) (*stored, error) {
	return r.readSecretFrom(ctx, cert, true)
}

// readSecretFrom reads the Secret from the cache first when cached is
// true, else (and on a cache miss) from the API server.
func (r *Reconciler) readSecretFrom(ctx context.Context, cert *v1alpha1.Certificate, cached bool) (*stored, error) {
	key := client.ObjectKey{Namespace: cert.Namespace, Name: cert.SecretNameOrDefault()}
	var secret corev1.Secret
	var err error
	if cached {
		err = r.Get(ctx, key, &secret)
	}
	if !cached || apierrors.IsNotFound(err) {
		cached = false
		err = r.APIReader.Get(ctx, key, &secret)
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
	}
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to get Secret %s", key)
	}
	if msg := conflictMessage(cert, &secret); msg != "" {
		return nil, permanent(v1alpha1.ReasonSecretConflict, msg)
	}
	s := parseStored(&secret)
	s.cached = cached
	return s, nil
}

// confirmSecret re-reads, from the API server, a Secret that came from the
// cache, before a decision to sign: the cache can still hold the Secret as
// it was before this controller's last write (a retry right after a failed
// status patch), and deciding on it would sign again what restoreStatus
// recovers from the current Secret. It returns the Secret to decide on and
// whether it differs from s.
func (r *Reconciler) confirmSecret(ctx context.Context, cert *v1alpha1.Certificate, s *stored) (*stored, bool, error) {
	if s == nil || !s.cached {
		return s, false, nil
	}
	fresh, err := r.readSecretFrom(ctx, cert, false)
	if err != nil {
		return nil, false, err
	}
	changed := fresh == nil || fresh.secret.ResourceVersion != s.secret.ResourceVersion
	return fresh, changed, nil
}

// conflictMessage says why an existing Secret cannot be written, or "".
// Ours: controlled by this Certificate, or by a Certificate of the same
// name that no longer exists (a re-created Certificate adopts it), or
// without a controller but labeled managed or adopt. Ours or not, a
// Secret whose type is not kubernetes.io/tls cannot hold the certificate
// (the type is immutable), so even a matching one is never adopted.
func conflictMessage(cert *v1alpha1.Certificate, secret *corev1.Secret) string {
	if owner := metav1.GetControllerOf(secret); owner != nil {
		if owner.UID != cert.UID && !isCertificateRef(owner, cert.Name) {
			return fmt.Sprintf("Secret %q is controlled by %s %q; use another secretName", secret.Name, owner.Kind, owner.Name)
		}
	} else if secret.Labels[v1alpha1.LabelManaged] != v1alpha1.TrueValue && secret.Labels[v1alpha1.LabelAdopt] != v1alpha1.TrueValue {
		return fmt.Sprintf("Secret %q exists and is not managed by kubeca; delete it or label it %s=%s", secret.Name, v1alpha1.LabelAdopt, v1alpha1.TrueValue)
	}
	if secret.Type != corev1.SecretTypeTLS {
		return fmt.Sprintf("Secret %q has type %q, not %s; delete it", secret.Name, secret.Type, corev1.SecretTypeTLS)
	}
	return ""
}

func isCertificateRef(ref *metav1.OwnerReference, name string) bool {
	return ref.APIVersion == v1alpha1.GroupVersion.String() && ref.Kind == v1alpha1.KindCertificate && ref.Name == name
}

// parseStored parses tls.crt and tls.key; a missing or invalid entry
// leaves the field nil and sets problem.
func parseStored(secret *corev1.Secret) *stored {
	s := &stored{secret: secret}
	certPEM, ok := secret.Data[v1alpha1.SecretKeyCertificate]
	if !ok || len(certPEM) == 0 {
		s.problem = "Secret has no " + v1alpha1.SecretKeyCertificate
		return s
	}
	chain, err := certutil.ParseChainFromPEM(certPEM)
	if err != nil || len(chain) == 0 {
		s.problem = v1alpha1.SecretKeyCertificate + " is not a PEM certificate"
		return s
	}
	s.leaf, s.chain = chain[0], chain
	keyPEM, ok := secret.Data[v1alpha1.SecretKeyPrivateKey]
	if !ok || len(keyPEM) == 0 {
		s.problem = "Secret has no " + v1alpha1.SecretKeyPrivateKey
		return s
	}
	key, err := certutil.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		s.problem = v1alpha1.SecretKeyPrivateKey + " is not a PEM private key"
		return s
	}
	s.key = key
	return s
}

// writeSecret creates or updates the Secret with the issued certificate.
// The Secret type is set on creation; an existing Secret passed
// readSecret, so it is a kubernetes.io/tls Secret we may write.
func (r *Reconciler) writeSecret(ctx context.Context, cert *v1alpha1.Certificate, ic *issuanceContext, s *stored, out *issued, revision int64, issuedAt time.Time) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: cert.Namespace,
			Name:      cert.SecretNameOrDefault(),
		},
		Type: corev1.SecretTypeTLS,
	}
	create := s == nil || s.secret == nil
	if !create {
		secret = s.secret.DeepCopy()
	}
	secret.Labels = secretLabels(cert, secret.Labels)
	secret.Annotations = secretAnnotations(cert, ic, secret.Annotations)
	secret.Annotations[v1alpha1.AnnotationSerial] = formatSerial(out.leaf.SerialNumber)
	secret.Annotations[v1alpha1.AnnotationNotBefore] = out.leaf.NotBefore.UTC().Format(time.RFC3339)
	secret.Annotations[v1alpha1.AnnotationNotAfter] = out.leaf.NotAfter.UTC().Format(time.RFC3339)
	secret.Annotations[v1alpha1.AnnotationIssuedAt] = issuedAt.UTC().Format(time.RFC3339)
	secret.Annotations[v1alpha1.AnnotationDuration] = ic.duration.String()
	secret.Annotations[v1alpha1.AnnotationRevision] = strconv.FormatInt(revision, 10)
	// with the revision, what restoreStatus needs when the status patch
	// after this write fails
	if requested := cert.Annotations[v1alpha1.AnnotationRenewRequested]; requested != "" {
		secret.Annotations[v1alpha1.AnnotationRenewRequested] = requested
	} else {
		delete(secret.Annotations, v1alpha1.AnnotationRenewRequested)
	}
	secret.Data = map[string][]byte{
		v1alpha1.SecretKeyCertificate: out.certPEM,
		v1alpha1.SecretKeyPrivateKey:  out.keyPEM,
		v1alpha1.SecretKeyCA:          caBundlePEM(ic),
	}
	if err := r.own(cert, secret); err != nil {
		return err
	}
	if create {
		if err := r.Create(ctx, secret); err != nil {
			return errors.WithMessagef(err, "unable to create Secret %s/%s", secret.Namespace, secret.Name)
		}
		return nil
	}
	if err := r.Update(ctx, secret); err != nil {
		return errors.WithMessagef(err, "unable to update Secret %s/%s", secret.Namespace, secret.Name)
	}
	return nil
}

// own sets the controller reference of the Certificate on the Secret
// without blockOwnerDeletion (so no finalizers permission is needed under
// the OwnerReferencesPermissionEnforcement admission plugin); a stale
// reference of a deleted Certificate with our name is replaced
// (conflictMessage accepted it).
func (r *Reconciler) own(cert *v1alpha1.Certificate, secret *corev1.Secret) error {
	secret.OwnerReferences = slices.DeleteFunc(secret.OwnerReferences, func(ref metav1.OwnerReference) bool {
		return isCertificateRef(&ref, cert.Name) && ref.UID != cert.UID
	})
	if err := controllerutil.SetControllerReference(cert, secret, r.Scheme, controllerutil.WithBlockOwnerDeletion(false)); err != nil {
		return permanent(v1alpha1.ReasonSecretConflict, err.Error())
	}
	return nil
}

// restoreStatus takes status.revision and status.lastRenewRequest from the
// Secret when the Secret's revision annotation is ahead of the status: the
// Secret is written before the status patch, and when that patch fails the
// retry must neither count the issuance again nor honour the same renewal
// request a second time. A Secret at or behind the status changes nothing.
func restoreStatus(cert *v1alpha1.Certificate, s *stored) {
	if s == nil || s.secret == nil {
		return
	}
	revision, err := strconv.ParseInt(s.secret.Annotations[v1alpha1.AnnotationRevision], 10, 64)
	if err != nil || revision <= cert.Status.Revision {
		return
	}
	cert.Status.Revision = revision
	cert.Status.LastRenewRequest = s.secret.Annotations[v1alpha1.AnnotationRenewRequested]
}

// syncSecret brings the Secret of an up-to-date certificate in line
// without re-issuing: secretTemplate changes, the controller reference (an
// adopted Secret whose certificate already matches) and the trust data an
// issuance would write today, which a user or a tool may have removed or
// replaced while the leaf and the key still match (repairTrustData). The
// Secret is updated only when something differs.
func (r *Reconciler) syncSecret(ctx context.Context, cert *v1alpha1.Certificate, ic *issuanceContext, s *stored) error {
	desired := s.secret.DeepCopy()
	desired.Labels = secretLabels(cert, desired.Labels)
	desired.Annotations = secretAnnotations(cert, ic, desired.Annotations)
	if err := r.own(cert, desired); err != nil {
		return err
	}
	repaired := repairTrustData(s, ic, desired)
	if len(repaired) == 0 && maps.Equal(desired.Labels, s.secret.Labels) && maps.Equal(desired.Annotations, s.secret.Annotations) &&
		equality.Semantic.DeepEqual(desired.OwnerReferences, s.secret.OwnerReferences) {
		return nil
	}
	if err := r.Update(ctx, desired); err != nil {
		return errors.WithMessagef(err, "unable to update Secret %s/%s", desired.Namespace, desired.Name)
	}
	if len(repaired) > 0 {
		logger.ContextKV(ctx, xlog.WARNING,
			"ns", cert.Namespace,
			"name", cert.Name,
			"status", "secret_repaired",
			"reason", "restored "+strings.Join(repaired, ", ")+" of Secret "+desired.Name)
	}
	s.secret = desired
	return nil
}

// repairTrustData sets, in secret.Data, the parts of the Secret that do
// not depend on the issuance and differ from what writeSecret would write
// now: tls.crt when its issuer chain is not the issuer's (the stored leaf
// is kept), and ca.crt when it is not the ClusterIssuer's root bundle. It
// returns the keys it set.
func repairTrustData(s *stored, ic *issuanceContext, secret *corev1.Secret) []string {
	var repaired []string
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: s.leaf.Raw})
	if want := certificatePEM(string(leafPEM), ic); !sameChain(s.chain, s.secret.Data[v1alpha1.SecretKeyCertificate], want) {
		secret.Data[v1alpha1.SecretKeyCertificate] = want
		repaired = append(repaired, v1alpha1.SecretKeyCertificate)
	}
	if want := caBundlePEM(ic); !bytes.Equal(s.secret.Data[v1alpha1.SecretKeyCA], want) {
		secret.Data[v1alpha1.SecretKeyCA] = want
		repaired = append(repaired, v1alpha1.SecretKeyCA)
	}
	return repaired
}

// sameChain reports whether the stored chain (parsed from storedPEM) holds
// the certificates of want, in order; the PEM text may differ. When want
// does not parse, the bytes are compared.
func sameChain(chain []*x509.Certificate, storedPEM, want []byte) bool {
	wantChain, err := certutil.ParseChainFromPEM(want)
	if err != nil {
		return bytes.Equal(storedPEM, want)
	}
	return slices.EqualFunc(chain, wantChain, func(a, b *x509.Certificate) bool {
		return bytes.Equal(a.Raw, b.Raw)
	})
}

// caBundlePEM is the ca.crt content: the root bundle the ClusterIssuer
// publishes.
func caBundlePEM(ic *issuanceContext) []byte {
	return []byte(ic.issuer.Status.RootCertificate)
}

// secretLabels merges the existing labels, the template labels (reserved
// prefix skipped) and the managed label.
func secretLabels(cert *v1alpha1.Certificate, existing map[string]string) map[string]string {
	labels := maps.Clone(existing)
	if labels == nil {
		labels = map[string]string{}
	}
	if cert.Spec.SecretTemplate != nil {
		maps.Copy(labels, templateEntries(cert.Spec.SecretTemplate.Labels))
	}
	labels[v1alpha1.LabelManaged] = v1alpha1.TrueValue
	return labels
}

// secretAnnotations merges the existing annotations, the template
// annotations (reserved prefix skipped) and the provenance annotations.
func secretAnnotations(cert *v1alpha1.Certificate, ic *issuanceContext, existing map[string]string) map[string]string {
	annotations := maps.Clone(existing)
	if annotations == nil {
		annotations = map[string]string{}
	}
	if cert.Spec.SecretTemplate != nil {
		maps.Copy(annotations, templateEntries(cert.Spec.SecretTemplate.Annotations))
	}
	annotations[v1alpha1.AnnotationCertificate] = cert.Namespace + "/" + cert.Name
	annotations[v1alpha1.AnnotationIssuer] = ic.issuer.Name
	annotations[v1alpha1.AnnotationProfile] = ic.profileName
	return annotations
}

// templateEntries returns the template entries the Secret gets: those
// without the operator's reserved prefix.
func templateEntries(entries map[string]string) map[string]string {
	kept := maps.Clone(entries)
	maps.DeleteFunc(kept, func(key, _ string) bool {
		return strings.HasPrefix(key, v1alpha1.GroupName+"/")
	})
	return kept
}

// validateSecretTemplate checks the labels and annotations secretTemplate
// adds to the Secret with the API server's own metadata rules. The CRD
// accepts any string, and a template the Secret write rejects must be a
// PolicyViolation before anything is signed, not a transient error whose
// retry signs again. The errors are sorted, so the condition message is
// the same on every reconcile.
func validateSecretTemplate(cert *v1alpha1.Certificate) error {
	template := cert.Spec.SecretTemplate
	if template == nil {
		return nil
	}
	path := field.NewPath("spec", "secretTemplate")
	errs := metav1validation.ValidateLabels(templateEntries(template.Labels), path.Child("labels"))
	errs = append(errs, apivalidation.ValidateAnnotations(templateEntries(template.Annotations), path.Child("annotations"))...)
	if len(errs) == 0 {
		return nil
	}
	messages := make([]string, 0, len(errs))
	for _, err := range errs {
		messages = append(messages, err.Error())
	}
	slices.Sort(messages)
	return permanent(v1alpha1.ReasonPolicyViolation, "invalid secretTemplate: "+strings.Join(messages, "; "))
}
