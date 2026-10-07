package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/effective-security/kubeca/api/v1alpha1"
	"github.com/effective-security/kubeca/internal/testauthority"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRenewalTime(t *testing.T) {
	t.Parallel()
	notBefore := time.Date(2026, 10, 6, 9, 55, 0, 0, time.UTC)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}
	j := jitter(leaf.SerialNumber, 8*time.Hour)
	assert.Less(t, j, 48*time.Minute)
	assert.Equal(t, j, jitter(leaf.SerialNumber, 8*time.Hour), "deterministic")
	assert.NotEqual(t, j, jitter(big.NewInt(987654321), 8*time.Hour))
	assert.Equal(t, time.Duration(0), jitter(leaf.SerialNumber, 5*time.Nanosecond))
	assert.Equal(t, time.Duration(0), jitter(nil, time.Hour))

	issuedAt := notBefore.Add(5 * time.Minute)
	assert.Equal(t, leaf.NotAfter.Add(-8*time.Hour).Add(-j), renewalTime(leaf, 8*time.Hour, issuedAt))
	// renewBefore not shorter than the lifetime: a third of the lifetime
	third := renewalTime(leaf, 0, issuedAt)
	assert.Equal(t, leaf.NotAfter.Add(-8*time.Hour).Add(-j), third)
	assert.Equal(t, third, renewalTime(leaf, 24*time.Hour, issuedAt))
	assert.Equal(t, third, renewalTime(leaf, 48*time.Hour, issuedAt))
	// never sooner than a minute after the issuance
	assert.Equal(t, issuedAt.Add(time.Minute), renewalTime(leaf, 23*time.Hour+59*time.Minute, issuedAt))
	late := issuedAt.Add(23 * time.Hour)
	assert.Equal(t, late.Add(time.Minute), renewalTime(leaf, 8*time.Hour, late))
}

func TestEffectiveRenewalTime(t *testing.T) {
	t.Parallel()
	notBefore := time.Date(2026, 10, 6, 9, 55, 0, 0, time.UTC)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: notBefore, NotAfter: notBefore.Add(24 * time.Hour)}
	ic := &issuanceContext{renewBefore: 8 * time.Hour, backdate: 5 * time.Minute}
	assert.True(t, effectiveRenewalTime(nil, ic).IsZero())
	assert.True(t, effectiveRenewalTime(&stored{}, ic).IsZero())
	// without the annotation the issuance is estimated as notBefore + backdate
	s := &stored{leaf: leaf, secret: &corev1.Secret{}}
	assert.Equal(t, renewalTime(leaf, 8*time.Hour, notBefore.Add(5*time.Minute)), effectiveRenewalTime(s, ic))
	// the annotation wins; a renewBefore change applies without re-issuance
	issuedAt := notBefore.Add(5*time.Minute + 42*time.Second)
	s.secret.Annotations = map[string]string{v1alpha1.AnnotationIssuedAt: issuedAt.Format(time.RFC3339)}
	assert.Equal(t, renewalTime(leaf, 8*time.Hour, issuedAt), effectiveRenewalTime(s, ic))
	ic.renewBefore = 23*time.Hour + 59*time.Minute
	assert.Equal(t, issuedAt.Add(time.Minute), effectiveRenewalTime(s, ic))
	s.secret.Annotations[v1alpha1.AnnotationIssuedAt] = "garbage"
	assert.Equal(t, renewalTime(leaf, ic.renewBefore, notBefore.Add(5*time.Minute)), effectiveRenewalTime(s, ic))
}

func TestFormatSerial(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "00", formatSerial(big.NewInt(0)))
	assert.Equal(t, "01:F4", formatSerial(big.NewInt(500)))
	assert.Equal(t, "DE:AD:BE:EF", formatSerial(big.NewInt(0xdeadbeef)))
}

// issueFor signs a certificate with the test CA through the real
// issuance path, so needsIssuance sees what the controller stores.
func issueFor(t *testing.T, ca *testauthority.CA, ic *issuanceContext, cert *v1alpha1.Certificate, now time.Time) *stored {
	t.Helper()
	r := &Reconciler{Authority: ca.Authority, Clock: fixedClock{now}}
	out, err := r.issue(cert, ic, nil)
	require.NoError(t, err)
	key, err := certutil.ParsePrivateKeyPEM(out.keyPEM)
	require.NoError(t, err)
	return &stored{
		secret: &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					v1alpha1.AnnotationIssuer:  ic.issuer.Name,
					v1alpha1.AnnotationProfile: ic.profileName,
				},
			},
		},
		leaf: out.leaf,
		key:  key,
	}
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time                             { return c.now }
func (c fixedClock) Since(t time.Time) time.Duration            { return c.now.Sub(t) }
func (c fixedClock) After(time.Duration) <-chan time.Time       { panic("unused") }
func (c fixedClock) NewTimer(time.Duration) clockTimer          { panic("unused") }
func (c fixedClock) Sleep(time.Duration)                        { panic("unused") }
func (c fixedClock) Tick(time.Duration) <-chan time.Time        { panic("unused") }
func (c fixedClock) NewTicker(time.Duration) clockTicker        { panic("unused") }
func (c fixedClock) AfterFunc(time.Duration, func()) clockTimer { panic("unused") }

func contextFor(t *testing.T, ca *testauthority.CA, profile string, names ...string) *issuanceContext {
	t.Helper()
	xi, err := ca.GetIssuerByLabel(testauthority.IssuerLabel)
	require.NoError(t, err)
	san, err := csr.ParseSAN(names)
	require.NoError(t, err)
	return &issuanceContext{
		issuer: &v1alpha1.ClusterIssuer{
			ObjectMeta: metav1.ObjectMeta{Name: "kubeca"},
			Spec:       v1alpha1.ClusterIssuerSpec{IssuerLabel: testauthority.IssuerLabel},
			Status:     v1alpha1.ClusterIssuerStatus{IssuerKeyID: xi.SubjectKID()},
		},
		xpkiIssuer:  xi,
		profileName: profile,
		profile:     xi.Profile(profile),
		san:         san,
		names:       sanStrings(san),
		duration:    24 * time.Hour,
		renewBefore: 8 * time.Hour,
		backdate:    5 * time.Minute,
		algorithm:   v1alpha1.KeyAlgorithmECDSA,
		keySize:     256,
	}
}

func TestNeedsIssuance(t *testing.T) {
	ca := testauthority.New(t)
	// xpki checks NotBefore against the real clock, so the fake "now" is
	// the real time; 30 s ahead so a minute boundary passing during the
	// test never makes the issuer's window later than ours
	now := time.Now().Add(30 * time.Second).UTC()
	cert := &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "web-tls", Namespace: "shop"},
		Spec: v1alpha1.CertificateSpec{
			IssuerRef:  v1alpha1.IssuerReference{Name: "kubeca"},
			Profile:    testauthority.ProfileServer,
			CommonName: "web.shop.svc",
			DNSNames:   []string{"web.shop.svc", "web.shop.svc.cluster.local"},
		},
		Status: v1alpha1.CertificateStatus{Revision: 1},
	}
	ic := contextFor(t, ca, testauthority.ProfileServer, "web.shop.svc", "web.shop.svc.cluster.local")
	s := issueFor(t, ca, ic, cert, now)
	assert.Equal(t, now.Truncate(time.Minute).Add(-5*time.Minute), s.leaf.NotBefore)
	assert.Equal(t, s.leaf.NotBefore.Add(24*time.Hour), s.leaf.NotAfter)

	trigger, detail := needsIssuance(cert, s, ic, effectiveRenewalTime(s, ic), now)
	assert.Empty(t, trigger, detail)

	t.Run("duration annotation", func(t *testing.T) {
		annotated := *s
		annotated.secret = s.secret.DeepCopy()
		for value, want := range map[string]string{
			"24h0m0s": "",
			"12h0m0s": "duration changed from 12h0m0s to 24h0m0s",
			"garbage": `duration annotation "garbage" is not a duration`,
		} {
			annotated.secret.Annotations = map[string]string{v1alpha1.AnnotationDuration: value}
			trigger, detail := needsIssuance(cert, &annotated, ic, effectiveRenewalTime(&annotated, ic), now)
			if want == "" {
				assert.Empty(t, trigger, detail)
				continue
			}
			assert.Equal(t, v1alpha1.ReasonSpecChanged, trigger, value)
			assert.Equal(t, want, detail, value)
		}
	})
	t.Run("initial", func(t *testing.T) {
		fresh := cert.DeepCopy()
		fresh.Status.Revision = 0
		trigger, detail := needsIssuance(fresh, nil, ic, effectiveRenewalTime(nil, ic), now)
		assert.Equal(t, v1alpha1.ReasonInitial, trigger)
		assert.Equal(t, "no certificate issued yet", detail)
	})
	t.Run("secret missing", func(t *testing.T) {
		trigger, detail := needsIssuance(cert, nil, ic, effectiveRenewalTime(nil, ic), now)
		assert.Equal(t, v1alpha1.ReasonSecretMissing, trigger)
		assert.Equal(t, "Secret web-tls does not exist", detail)
	})
	t.Run("secret invalid", func(t *testing.T) {
		broken := parseStored(&corev1.Secret{Data: map[string][]byte{"tls.crt": []byte("junk")}})
		trigger, detail := needsIssuance(cert, broken, ic, effectiveRenewalTime(broken, ic), now)
		assert.Equal(t, v1alpha1.ReasonSecretMissing, trigger)
		assert.Equal(t, "tls.crt is not a PEM certificate", detail)

		noKey := parseStored(&corev1.Secret{Data: map[string][]byte{"tls.crt": testca.ToPEM(s.leaf)}})
		trigger, detail = needsIssuance(cert, noKey, ic, effectiveRenewalTime(noKey, ic), now)
		assert.Equal(t, v1alpha1.ReasonSecretMissing, trigger)
		assert.Equal(t, "Secret has no tls.key", detail)

		empty := parseStored(&corev1.Secret{})
		_, detail = needsIssuance(cert, empty, ic, effectiveRenewalTime(empty, ic), now)
		assert.Equal(t, "Secret has no tls.crt", detail)
	})
	t.Run("key mismatch", func(t *testing.T) {
		other := issueFor(t, ca, ic, cert, now)
		mixed := &stored{secret: s.secret, leaf: s.leaf, key: other.key}
		trigger, detail := needsIssuance(cert, mixed, ic, effectiveRenewalTime(mixed, ic), now)
		assert.Equal(t, v1alpha1.ReasonSecretMissing, trigger)
		assert.Equal(t, "private key does not match the certificate", detail)
	})
	t.Run("requested", func(t *testing.T) {
		req := cert.DeepCopy()
		req.Annotations = map[string]string{v1alpha1.AnnotationRenewRequested: "now"}
		trigger, detail := needsIssuance(req, s, ic, effectiveRenewalTime(s, ic), now)
		assert.Equal(t, v1alpha1.ReasonRequested, trigger)
		assert.Equal(t, "renewal requested: now", detail)
		req.Status.LastRenewRequest = "now"
		trigger, _ = needsIssuance(req, s, ic, effectiveRenewalTime(s, ic), now)
		assert.Empty(t, trigger)
		// removed after it was honoured: one renewal, which clears the status
		req.Annotations = nil
		trigger, detail = needsIssuance(req, s, ic, effectiveRenewalTime(s, ic), now)
		assert.Equal(t, v1alpha1.ReasonRequested, trigger)
		assert.Equal(t, "renewal request now removed", detail)
		req.Status.LastRenewRequest = ""
		trigger, _ = needsIssuance(req, s, ic, effectiveRenewalTime(s, ic), now)
		assert.Empty(t, trigger)
	})
	t.Run("ca changed", func(t *testing.T) {
		changed := contextFor(t, ca, testauthority.ProfileServer, "web.shop.svc", "web.shop.svc.cluster.local")
		changed.issuer.Status.IssuerKeyID = "0102"
		trigger, detail := needsIssuance(cert, s, changed, effectiveRenewalTime(s, changed), now)
		assert.Equal(t, v1alpha1.ReasonCAChanged, trigger)
		assert.Equal(t, "issuer key id 0102, certificate signed by "+certutil.GetSubjectKeyID(ca.Issuer.Certificate), detail)
	})
	t.Run("spec changed", func(t *testing.T) {
		tcases := []struct {
			name   string
			ic     *issuanceContext
			cert   *v1alpha1.Certificate
			detail string
		}{
			{
				name:   "names",
				ic:     contextFor(t, ca, testauthority.ProfileServer, "web.shop.svc", "api.shop.svc"),
				detail: "names changed: DNS names [web.shop.svc web.shop.svc.cluster.local], requested [web.shop.svc api.shop.svc]",
			},
			{
				name:   "profile",
				ic:     contextFor(t, ca, testauthority.ProfilePeer, "web.shop.svc", "web.shop.svc.cluster.local"),
				detail: "profile changed from server-24h to peer-24h",
			},
			{
				name: "common name",
				cert: func() *v1alpha1.Certificate {
					c := cert.DeepCopy()
					c.Spec.CommonName = "other"
					return c
				}(),
				detail: `common name "web.shop.svc", spec "other"`,
			},
			{
				name: "key size",
				ic: func() *issuanceContext {
					c := contextFor(t, ca, testauthority.ProfileServer, "web.shop.svc", "web.shop.svc.cluster.local")
					c.keySize = 384
					return c
				}(),
				detail: "key is not ECDSA 384",
			},
			{
				name: "key algorithm",
				ic: func() *issuanceContext {
					c := contextFor(t, ca, testauthority.ProfileServer, "web.shop.svc", "web.shop.svc.cluster.local")
					c.algorithm, c.keySize = v1alpha1.KeyAlgorithmRSA, 2048
					return c
				}(),
				detail: "key is not RSA 2048",
			},
			{
				name: "usages",
				ic: func() *issuanceContext {
					c := contextFor(t, ca, testauthority.ProfileServer, "web.shop.svc", "web.shop.svc.cluster.local")
					c.profile = c.xpkiIssuer.Profile(testauthority.ProfilePeer)
					return c
				}(),
				detail: "key usages differ from profile server-24h",
			},
		}
		for _, tc := range tcases {
			t.Run(tc.name, func(t *testing.T) {
				c, i := cert, ic
				if tc.cert != nil {
					c = tc.cert
				}
				if tc.ic != nil {
					i = tc.ic
				}
				trigger, detail := needsIssuance(c, s, i, effectiveRenewalTime(s, i), now)
				assert.Equal(t, v1alpha1.ReasonSpecChanged, trigger)
				assert.Equal(t, tc.detail, detail)
			})
		}
	})
	t.Run("renewal", func(t *testing.T) {
		renewal := effectiveRenewalTime(s, ic)
		trigger, _ := needsIssuance(cert, s, ic, renewal, renewal.Add(-time.Second))
		assert.Empty(t, trigger)
		trigger, detail := needsIssuance(cert, s, ic, renewal, renewal)
		assert.Equal(t, v1alpha1.ReasonRenewal, trigger)
		assert.Equal(t, "renewal time "+renewal.UTC().Format(time.RFC3339)+" reached", detail)
	})
	t.Run("expired", func(t *testing.T) {
		trigger, detail := needsIssuance(cert, s, ic, effectiveRenewalTime(s, ic), s.leaf.NotAfter)
		assert.Equal(t, v1alpha1.ReasonRenewal, trigger)
		assert.Equal(t, "certificate expired at "+s.leaf.NotAfter.UTC().Format(time.RFC3339), detail)
	})
}

func TestConflictMessage(t *testing.T) {
	t.Parallel()
	cert := &v1alpha1.Certificate{ObjectMeta: metav1.ObjectMeta{Name: "web-tls", Namespace: "shop", UID: "uid-1"}}
	ours := metav1.OwnerReference{APIVersion: v1alpha1.GroupVersion.String(), Kind: v1alpha1.KindCertificate, Name: "web-tls", UID: "uid-1", Controller: ptr(true)}
	stale := ours
	stale.UID = "uid-0"
	foreign := metav1.OwnerReference{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", UID: "x", Controller: ptr(true)}
	otherCert := ours
	otherCert.Name, otherCert.UID = "other", "uid-2"

	tls, opaque := corev1.SecretTypeTLS, corev1.SecretTypeOpaque
	secret := func(secretType corev1.SecretType, labels map[string]string, owners ...metav1.OwnerReference) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "web-tls", Labels: labels, OwnerReferences: owners},
			Type:       secretType,
		}
	}
	adopt := map[string]string{v1alpha1.LabelAdopt: "true"}
	wrongType := `Secret "web-tls" has type "Opaque", not kubernetes.io/tls; delete it`

	tcases := []struct {
		name   string
		secret *corev1.Secret
		want   string
	}{
		{"ours", secret(tls, nil, ours), ""},
		{"stale owner, same name", secret(tls, nil, stale), ""},
		{"managed label", secret(tls, map[string]string{v1alpha1.LabelManaged: "true"}), ""},
		{"adopt label", secret(tls, adopt), ""},
		{"foreign controller", secret(tls, nil, foreign), `Secret "web-tls" is controlled by Deployment "web"; use another secretName`},
		{"other Certificate", secret(tls, nil, otherCert), `Secret "web-tls" is controlled by Certificate "other"; use another secretName`},
		{"unmanaged", secret(tls, nil), `Secret "web-tls" exists and is not managed by kubeca; delete it or label it kubeca.effectivesecurity/adopt=true`},
		// ownership first, then the type: an Opaque Secret is never adopted
		{"unmanaged Opaque", secret(opaque, nil), `Secret "web-tls" exists and is not managed by kubeca; delete it or label it kubeca.effectivesecurity/adopt=true`},
		{"adopt label, Opaque", secret(opaque, adopt), wrongType},
		{"ours, Opaque", secret(opaque, nil, ours), wrongType},
		{"no type", secret("", adopt), `Secret "web-tls" has type "", not kubernetes.io/tls; delete it`},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, conflictMessage(cert, tc.secret))
		})
	}
}

func TestGenerateKey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		algo v1alpha1.KeyAlgorithm
		size int
	}{
		{v1alpha1.KeyAlgorithmECDSA, 256}, {v1alpha1.KeyAlgorithmECDSA, 384}, {v1alpha1.KeyAlgorithmECDSA, 521}, {v1alpha1.KeyAlgorithmRSA, 2048},
	} {
		key, err := generateKey(tc.algo, tc.size)
		require.NoError(t, err)
		assert.True(t, keyMatches(key.Public(), tc.algo, tc.size))
		assert.False(t, keyMatches(key.Public(), tc.algo, tc.size+1))
	}
	for _, tc := range []struct {
		algo v1alpha1.KeyAlgorithm
		size int
		msg  string
	}{
		{v1alpha1.KeyAlgorithmECDSA, 1024, "unsupported ECDSA key size 1024"},
		{v1alpha1.KeyAlgorithmRSA, 1024, "unsupported RSA key size 1024"},
		{"DSA", 1024, `unsupported key algorithm "DSA"`},
	} {
		_, err := generateKey(tc.algo, tc.size)
		require.Error(t, err)
		assert.Equal(t, tc.msg, err.Error())
		assert.True(t, isPermanent(err))
	}
	assert.False(t, keyMatches(nil, v1alpha1.KeyAlgorithmECDSA, 256))
	assert.False(t, publicKeysEqual(nil, nil))
}

func TestNamesDrift(t *testing.T) {
	t.Parallel()
	san, err := csr.ParseSAN([]string{"Web.shop.svc", "10.0.0.1", "spiffe://example.org/ns/shop/sa/web", "ops@example.org"})
	require.NoError(t, err)
	leaf := &x509.Certificate{Subject: pkix.Name{}}
	leaf.DNSNames = []string{"web.shop.svc"}
	leaf.IPAddresses = san.IPAddresses
	leaf.URIs = san.URIs
	leaf.EmailAddresses = []string{"OPS@example.org"}
	assert.Empty(t, namesDrift(leaf, san))
	leaf.IPAddresses = nil
	assert.Equal(t, "IP addresses [], requested [10.0.0.1]", namesDrift(leaf, san))
	leaf.IPAddresses = san.IPAddresses
	leaf.URIs = nil
	assert.Equal(t, "URIs [], requested [spiffe://example.org/ns/shop/sa/web]", namesDrift(leaf, san))
	leaf.URIs = san.URIs
	leaf.EmailAddresses = nil
	assert.Equal(t, "email addresses [], requested [ops@example.org]", namesDrift(leaf, san))
}

func ptr[T any](v T) *T { return &v }
