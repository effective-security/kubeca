package certificate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"hash/fnv"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/effective-security/kubeca/api/v1alpha1"
	"github.com/effective-security/xpki/certutil"
)

const (
	// jitterFraction: the renewal jitter is below renewBefore / 10.
	jitterFraction = 10
	// minRenewalDelay is the shortest time between an issuance and the
	// renewal of its certificate, whatever renewBefore and the backdate
	// leave: it rules out a re-issuance loop on a short lifetime.
	minRenewalDelay = time.Minute
)

// needsIssuance decides whether the Certificate must be (re-)issued and
// returns the trigger (an Issuing reason) with a detail, or "" when the
// stored certificate is up to date. The checks run in this order: a
// missing or invalid Secret, a key that does not match the certificate, a
// manual renewal request (the renew-requested annotation differs from
// status.lastRenewRequest; removing the annotation is a change too, so the
// status never keeps a value a later request would repeat), a changed CA,
// a spec that differs from the certificate, an expired certificate, the
// renewal time.
func needsIssuance(cert *v1alpha1.Certificate, s *stored, ic *issuanceContext, renewal, now time.Time) (trigger, detail string) {
	if s == nil || s.leaf == nil || s.key == nil {
		if cert.Status.Revision == 0 {
			return v1alpha1.ReasonInitial, "no certificate issued yet"
		}
		if s == nil {
			return v1alpha1.ReasonSecretMissing, "Secret " + cert.SecretNameOrDefault() + " does not exist"
		}
		return v1alpha1.ReasonSecretMissing, s.problem
	}
	if !publicKeysEqual(s.key.Public(), s.leaf.PublicKey) {
		return v1alpha1.ReasonSecretMissing, "private key does not match the certificate"
	}
	if requested := cert.Annotations[v1alpha1.AnnotationRenewRequested]; requested != cert.Status.LastRenewRequest {
		if requested == "" {
			return v1alpha1.ReasonRequested, "renewal request " + cert.Status.LastRenewRequest + " removed"
		}
		return v1alpha1.ReasonRequested, "renewal requested: " + requested
	}
	if keyID := ic.issuer.Status.IssuerKeyID; keyID != "" && !strings.EqualFold(certutil.GetAuthorityKeyID(s.leaf), keyID) {
		return v1alpha1.ReasonCAChanged, fmt.Sprintf("issuer key id %s, certificate signed by %s", keyID, certutil.GetAuthorityKeyID(s.leaf))
	}
	if detail := specDrift(cert, s, ic); detail != "" {
		return v1alpha1.ReasonSpecChanged, detail
	}
	if !now.Before(s.leaf.NotAfter) {
		return v1alpha1.ReasonRenewal, "certificate expired at " + s.leaf.NotAfter.UTC().Format(time.RFC3339)
	}
	if !now.Before(renewal) {
		return v1alpha1.ReasonRenewal, "renewal time " + renewal.UTC().Format(time.RFC3339) + " reached"
	}
	return "", ""
}

// effectiveRenewalTime is the renewal time of the stored certificate:
// recomputed from the leaf and the current renewBefore (a renewBefore
// change applies without re-issuance), never sooner than minRenewalDelay
// after the issuance recorded in the Secret's issued-at annotation (the
// notBefore plus the backdate when the annotation is missing).
func effectiveRenewalTime(s *stored, ic *issuanceContext) time.Time {
	if s == nil || s.leaf == nil {
		return time.Time{}
	}
	issuedAt := s.leaf.NotBefore.Add(ic.backdate)
	if value := s.secret.Annotations[v1alpha1.AnnotationIssuedAt]; value != "" {
		if t, err := time.Parse(time.RFC3339, value); err == nil {
			issuedAt = t
		}
	}
	return renewalTime(s.leaf, ic.renewBefore, issuedAt)
}

// specDrift describes the first difference between the stored
// certificate and the spec: issuer, profile, duration, common name,
// names, key, usages; "" when they match.
func specDrift(cert *v1alpha1.Certificate, s *stored, ic *issuanceContext) string {
	if issuer := s.secret.Annotations[v1alpha1.AnnotationIssuer]; issuer != "" && issuer != ic.issuer.Name {
		return fmt.Sprintf("issuer changed from %s to %s", issuer, ic.issuer.Name)
	}
	if profile := s.secret.Annotations[v1alpha1.AnnotationProfile]; profile != "" && profile != ic.profileName {
		return fmt.Sprintf("profile changed from %s to %s", profile, ic.profileName)
	}
	// the requested lifetime is compared through the annotation, not the
	// leaf's validity: the issuer may have clipped NotAfter to its own. An
	// absent annotation (an adopted Secret) is not compared; an unparsable
	// one is drift, so that the re-issuance writes it again
	if value := s.secret.Annotations[v1alpha1.AnnotationDuration]; value != "" {
		requested, err := time.ParseDuration(value)
		switch {
		case err != nil:
			return fmt.Sprintf("duration annotation %q is not a duration", value)
		case requested != ic.duration:
			return fmt.Sprintf("duration changed from %s to %s", requested, ic.duration)
		}
	}
	if s.leaf.Subject.CommonName != cert.Spec.CommonName {
		return fmt.Sprintf("common name %q, spec %q", s.leaf.Subject.CommonName, cert.Spec.CommonName)
	}
	if detail := namesDrift(s.leaf, ic.san); detail != "" {
		return "names changed: " + detail
	}
	if !keyMatches(s.leaf.PublicKey, ic.algorithm, ic.keySize) {
		return fmt.Sprintf("key is not %s %d", ic.algorithm, ic.keySize)
	}
	ku, eku, _ := ic.profile.Usages()
	if s.leaf.KeyUsage != ku || !sameExtKeyUsages(s.leaf.ExtKeyUsage, eku) {
		return fmt.Sprintf("key usages differ from profile %s", ic.profileName)
	}
	return ""
}

func sameExtKeyUsages(a, b []x509.ExtKeyUsage) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}

// publicKeysEqual compares two public keys.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	switch k := a.(type) {
	case *ecdsa.PublicKey:
		other, ok := b.(*ecdsa.PublicKey)
		return ok && k.Equal(other)
	case *rsa.PublicKey:
		other, ok := b.(*rsa.PublicKey)
		return ok && k.Equal(other)
	default:
		return false
	}
}

// renewalTime is notAfter − renewBefore − jitter, and never sooner than
// minRenewalDelay after issuedAt. A renewBefore that is not shorter than
// the certificate's lifetime (the issuer clipped the certificate to its
// own expiry, for instance) falls back to a third of the lifetime.
func renewalTime(leaf *x509.Certificate, renewBefore time.Duration, issuedAt time.Time) time.Time {
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	if renewBefore <= 0 || renewBefore >= lifetime {
		renewBefore = lifetime / renewBeforeFraction
	}
	renewal := leaf.NotAfter.Add(-renewBefore).Add(-jitter(leaf.SerialNumber, renewBefore))
	if earliest := issuedAt.Add(minRenewalDelay); renewal.Before(earliest) {
		renewal = earliest
	}
	return renewal
}

// jitter is deterministic per certificate (hash of the serial number) and
// below renewBefore / jitterFraction, so replicas agree and a fleet issued
// at the same time does not renew at the same second.
func jitter(serial *big.Int, renewBefore time.Duration) time.Duration {
	window := renewBefore / jitterFraction
	if window <= 0 || serial == nil {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write(serial.Bytes())
	return time.Duration(h.Sum64() % uint64(window))
}
