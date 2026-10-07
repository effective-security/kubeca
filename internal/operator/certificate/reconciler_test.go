package certificate_test

import (
	"cmp"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/kubeca/api/v1alpha1"
	"github.com/effective-security/kubeca/internal/operator/certificate"
	"github.com/effective-security/kubeca/internal/operator/index"
	"github.com/effective-security/kubeca/internal/operator/metrics"
	"github.com/effective-security/kubeca/internal/testauthority"
	"github.com/effective-security/xpki/certutil"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	clocktesting "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	issuerName = "kubeca"
	namespace  = "shop"
	certName   = "web-tls"
)

func ptr[T any](v T) *T { return &v }

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, v1alpha1.AddToScheme(s))
	return s
}

func drain(events chan string) []string {
	var out []string
	for {
		select {
		case e := <-events:
			out = append(out, e)
		default:
			return out
		}
	}
}

type fixture struct {
	ca       *testauthority.CA
	client   client.Client
	recorder *record.FakeRecorder
	clock    *clocktesting.FakeClock
	r        *certificate.Reconciler
}

// newFixture builds the reconciler over a fake client. The fake clock
// starts 30 s ahead of the real time: xpki validates NotBefore against the
// real clock, and the offset keeps our minute from ending before the
// issuer's during the test.
func newFixture(t *testing.T, ca *testauthority.CA, objs ...client.Object) *fixture {
	t.Helper()
	return newFixtureWithBuilder(t, ca, fake.NewClientBuilder().WithObjects(objs...))
}

func newFixtureWithBuilder(t *testing.T, ca *testauthority.CA, b *fake.ClientBuilder) *fixture {
	t.Helper()
	c := b.WithScheme(newScheme(t)).
		WithStatusSubresource(&v1alpha1.ClusterIssuer{}, &v1alpha1.Certificate{}).
		WithIndex(&v1alpha1.Certificate{}, index.CertificateIssuer, index.CertificateIssuerValue).
		WithIndex(&v1alpha1.Certificate{}, index.CertificateServices, index.CertificateServicesValue).
		Build()
	recorder := record.NewFakeRecorder(50)
	clk := clocktesting.NewFakeClock(time.Now().Add(30 * time.Second).UTC())
	return &fixture{
		ca:       ca,
		client:   c,
		recorder: recorder,
		clock:    clk,
		r: &certificate.Reconciler{
			Client:        c,
			APIReader:     c,
			Scheme:        c.Scheme(),
			Authority:     ca.Authority,
			Recorder:      recorder,
			Clock:         clk,
			ClusterDomain: "cluster.local",
		},
	}
}

func (f *fixture) reconcile(t *testing.T, name string) (ctrl.Result, error, *v1alpha1.Certificate) {
	t.Helper()
	res, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}})
	var cert v1alpha1.Certificate
	if gerr := f.client.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: name}, &cert); gerr != nil {
		return res, err, nil
	}
	return res, err, &cert
}

func (f *fixture) secret(t *testing.T, name string) *corev1.Secret {
	t.Helper()
	var s corev1.Secret
	err := f.client.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: name}, &s)
	if err != nil {
		return nil
	}
	return &s
}

func condition(t *testing.T, cert *v1alpha1.Certificate, condType string) *metav1.Condition {
	t.Helper()
	cond := meta.FindStatusCondition(cert.Status.Conditions, condType)
	require.NotNil(t, cond, condType)
	return cond
}

// readyIssuer is a ClusterIssuer whose status the ClusterIssuer
// controller would have written for the test Authority.
func readyIssuer(ca *testauthority.CA) *v1alpha1.ClusterIssuer {
	xi, _ := ca.GetIssuerByLabel(testauthority.IssuerLabel)
	return &v1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: issuerName},
		Spec: v1alpha1.ClusterIssuerSpec{
			IssuerLabel:    testauthority.IssuerLabel,
			Profiles:       []string{testauthority.ProfilePeer, testauthority.ProfileServer, testauthority.ProfileClient},
			DefaultProfile: testauthority.ProfilePeer,
			Policy: &v1alpha1.IssuerPolicy{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{v1alpha1.LabelEnabled: v1alpha1.TrueValue}},
				MaxDuration:       &metav1.Duration{Duration: 24 * time.Hour},
				AllowedDNSNames: ptr([]string{
					`^[a-z0-9-]+\.${NAMESPACE}\.svc(\.${CLUSTER_DOMAIN})?$`,
					`^localhost$`,
				}),
				AllowedURIs:      ptr([]string{`^spiffe://example\.org/ns/${NAMESPACE}/sa/[a-z0-9-]+$`}),
				AllowIPAddresses: true,
			},
		},
		Status: v1alpha1.ClusterIssuerStatus{
			Conditions: []metav1.Condition{{
				Type:               v1alpha1.ConditionReady,
				Status:             metav1.ConditionTrue,
				Reason:             v1alpha1.ReasonLoaded,
				LastTransitionTime: metav1.Now(),
			}},
			IssuerKeyID:     xi.SubjectKID(),
			RootCertificate: ca.RootPEM(),
		},
	}
}

func enabledNamespace() *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   namespace,
		Labels: map[string]string{v1alpha1.LabelEnabled: v1alpha1.TrueValue},
	}}
}

func webCertificate() *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: certName, Namespace: namespace, UID: "uid-web", Generation: 1},
		Spec: v1alpha1.CertificateSpec{
			IssuerRef:   v1alpha1.IssuerReference{Name: issuerName},
			Profile:     testauthority.ProfileServer,
			CommonName:  "web.shop.svc.cluster.local",
			DNSNames:    []string{"web.shop.svc.cluster.local", "web.shop.svc"},
			URIs:        []string{"spiffe://example.org/ns/shop/sa/web"},
			Duration:    &metav1.Duration{Duration: 24 * time.Hour},
			RenewBefore: &metav1.Duration{Duration: 8 * time.Hour},
			SecretTemplate: &v1alpha1.SecretTemplate{
				Labels:      map[string]string{"app": "web", v1alpha1.LabelAdopt: "ignored"},
				Annotations: map[string]string{"team": "shop"},
			},
		},
	}
}

func samePublicKey(t *testing.T, a, b any) bool {
	t.Helper()
	da, err := x509.MarshalPKIXPublicKey(a)
	require.NoError(t, err)
	db, err := x509.MarshalPKIXPublicKey(b)
	require.NoError(t, err)
	return string(da) == string(db)
}

func parseLeaf(t *testing.T, secret *corev1.Secret) (*x509.Certificate, []*x509.Certificate) {
	t.Helper()
	chain, err := certutil.ParseChainFromPEM(secret.Data["tls.crt"])
	require.NoError(t, err)
	require.NotEmpty(t, chain)
	return chain[0], chain
}

func TestIssueAndRenew(t *testing.T) {
	ca := testauthority.New(t)
	f := newFixture(t, ca, readyIssuer(ca), enabledNamespace(), webCertificate())
	t0 := f.clock.Now()

	// initial issuance
	res, err, cert := f.reconcile(t, certName)
	require.NoError(t, err)
	ready := condition(t, cert, v1alpha1.ConditionReady)
	assert.Equal(t, metav1.ConditionTrue, ready.Status)
	assert.Equal(t, v1alpha1.ReasonIssued, ready.Reason)
	assert.Equal(t, int64(1), ready.ObservedGeneration)
	issuing := condition(t, cert, v1alpha1.ConditionIssuing)
	assert.Equal(t, metav1.ConditionFalse, issuing.Status)
	assert.Equal(t, v1alpha1.ReasonIssued, issuing.Reason)
	assert.Equal(t, int64(1), cert.Status.Revision)
	assert.Equal(t, int32(0), cert.Status.FailedAttempts)
	assert.Nil(t, cert.Status.LastFailureTime)
	assert.Equal(t, testauthority.IssuerLabel, cert.Status.IssuerLabel)
	assert.Equal(t, certutil.GetSubjectKeyID(ca.Issuer.Certificate), cert.Status.IssuerKeyID)
	notBefore := t0.Truncate(time.Minute).Add(-5 * time.Minute)
	require.NotNil(t, cert.Status.NotBefore)
	assert.Equal(t, notBefore, cert.Status.NotBefore.Time.UTC())
	assert.Equal(t, notBefore.Add(24*time.Hour), cert.Status.NotAfter.Time.UTC())
	renewal := cert.Status.RenewalTime.Time.UTC()
	assert.True(t, renewal.After(notBefore.Add(24*time.Hour-8*time.Hour-48*time.Minute)), renewal)
	assert.False(t, renewal.After(notBefore.Add(24*time.Hour-8*time.Hour)), renewal)
	// the status time has second precision, the requeue delay has not
	assert.InDelta(t, renewal.Sub(t0).Seconds(), res.RequeueAfter.Seconds(), 1)
	assert.Regexp(t, `^([0-9A-F]{2}:)+[0-9A-F]{2}$`, cert.Status.SerialNumber)
	assert.Equal(t, "certificate "+cert.Status.SerialNumber+" valid until "+cert.Status.NotAfter.UTC().Format(time.RFC3339), ready.Message)

	secret := f.secret(t, certName)
	require.NotNil(t, secret)
	assert.Equal(t, corev1.SecretTypeTLS, secret.Type)
	assert.Equal(t, map[string]string{
		"app":                 "web",
		v1alpha1.LabelManaged: "true",
	}, secret.Labels)
	assert.Equal(t, map[string]string{
		"team":                         "shop",
		v1alpha1.AnnotationCertificate: "shop/web-tls",
		v1alpha1.AnnotationIssuer:      issuerName,
		v1alpha1.AnnotationProfile:     testauthority.ProfileServer,
		v1alpha1.AnnotationSerial:      cert.Status.SerialNumber,
		v1alpha1.AnnotationNotBefore:   notBefore.Format(time.RFC3339),
		v1alpha1.AnnotationNotAfter:    notBefore.Add(24 * time.Hour).Format(time.RFC3339),
		v1alpha1.AnnotationIssuedAt:    t0.Format(time.RFC3339),
		v1alpha1.AnnotationDuration:    "24h0m0s",
		v1alpha1.AnnotationRevision:    "1",
	}, secret.Annotations)
	owner := metav1.GetControllerOf(secret)
	require.NotNil(t, owner)
	assert.Equal(t, v1alpha1.KindCertificate, owner.Kind)
	assert.Equal(t, certName, owner.Name)
	assert.Equal(t, types.UID("uid-web"), owner.UID)
	require.NotNil(t, owner.BlockOwnerDeletion)
	assert.False(t, *owner.BlockOwnerDeletion, "no finalizers permission needed")
	assert.Equal(t, ca.RootPEM(), string(secret.Data["ca.crt"]))

	leaf, chain := parseLeaf(t, secret)
	require.Len(t, chain, 2, "leaf and issuing certificate")
	assert.Equal(t, "web.shop.svc.cluster.local", leaf.Subject.CommonName)
	assert.Equal(t, []string{"web.shop.svc.cluster.local", "web.shop.svc"}, leaf.DNSNames)
	require.Len(t, leaf.URIs, 1)
	assert.Equal(t, "spiffe://example.org/ns/shop/sa/web", leaf.URIs[0].String())
	assert.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, leaf.KeyUsage)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, leaf.ExtKeyUsage)
	assert.Equal(t, notBefore, leaf.NotBefore.UTC())
	key, err := certutil.ParsePrivateKeyPEM(secret.Data["tls.key"])
	require.NoError(t, err)
	assert.True(t, samePublicKey(t, leaf.PublicKey, key.Public()))
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root.Certificate)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(chain[1])
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "web.shop.svc", CurrentTime: t0})
	require.NoError(t, err)

	events := drain(f.recorder.Events)
	require.Len(t, events, 1)
	assert.Regexp(t, `^Normal Issued certificate [0-9A-F:]+ issued by kubeca/server-24h, not after .*, revision 1$`, events[0])
	firstSerial := cert.Status.SerialNumber
	firstVersion := secret.ResourceVersion

	// one hour later: nothing to do, same Secret, requeue at the renewal time
	f.clock.Step(time.Hour)
	res, err, cert = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, int64(1), cert.Status.Revision)
	assert.InDelta(t, renewal.Sub(f.clock.Now()).Seconds(), res.RequeueAfter.Seconds(), 1)
	assert.Equal(t, firstVersion, f.secret(t, certName).ResourceVersion)
	assert.Empty(t, drain(f.recorder.Events))

	// a secretTemplate change is applied in place
	require.NoError(t, f.client.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: certName}, cert))
	cert.Spec.SecretTemplate.Labels["tier"] = "frontend"
	require.NoError(t, f.client.Update(context.Background(), cert))
	_, err, cert = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, int64(1), cert.Status.Revision)
	secret = f.secret(t, certName)
	assert.Equal(t, "frontend", secret.Labels["tier"])
	assert.Equal(t, firstSerial, secret.Annotations[v1alpha1.AnnotationSerial])

	// at the renewal time (the status holds it to the second): renewed
	// with a new key, revision 2
	f.clock.SetTime(renewal.Add(time.Second))
	res, err, cert = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, int64(2), cert.Status.Revision)
	assert.NotEqual(t, firstSerial, cert.Status.SerialNumber)
	assert.Equal(t, v1alpha1.ReasonIssued, condition(t, cert, v1alpha1.ConditionIssuing).Reason)
	secret = f.secret(t, certName)
	assert.Equal(t, "2", secret.Annotations[v1alpha1.AnnotationRevision])
	renewedLeaf, _ := parseLeaf(t, secret)
	assert.False(t, samePublicKey(t, renewedLeaf.PublicKey, leaf.PublicKey), "rotationPolicy Always: new key")
	assert.Equal(t, f.clock.Now().Truncate(time.Minute).Add(-5*time.Minute), renewedLeaf.NotBefore.UTC())
	events = drain(f.recorder.Events)
	require.Len(t, events, 1)
	assert.Regexp(t, `^Normal Renewed certificate [0-9A-F:]+ issued by kubeca/server-24h, not after .*, revision 2$`, events[0])
	assert.Greater(t, res.RequeueAfter, 15*time.Hour)

	// the Secret is deleted: re-issued at once
	require.NoError(t, f.client.Delete(context.Background(), secret))
	f.clock.Step(time.Minute)
	_, err, cert = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, int64(3), cert.Status.Revision)
	require.NotNil(t, f.secret(t, certName))
	drain(f.recorder.Events)

	// a spec change re-issues
	require.NoError(t, f.client.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: certName}, cert))
	cert.Spec.DNSNames = append(cert.Spec.DNSNames, "localhost")
	require.NoError(t, f.client.Update(context.Background(), cert))
	_, err, cert = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, int64(4), cert.Status.Revision)
	changedLeaf, _ := parseLeaf(t, f.secret(t, certName))
	assert.Equal(t, []string{"web.shop.svc.cluster.local", "web.shop.svc", "localhost"}, changedLeaf.DNSNames)

	// a shorter duration re-issues; the stored lifetime is not consulted
	drain(f.recorder.Events)
	require.NoError(t, f.client.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: certName}, cert))
	cert.Spec.Duration = &metav1.Duration{Duration: 12 * time.Hour}
	cert.Spec.RenewBefore = &metav1.Duration{Duration: 4 * time.Hour}
	require.NoError(t, f.client.Update(context.Background(), cert))
	_, err, cert = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, int64(5), cert.Status.Revision)
	shorter, _ := parseLeaf(t, f.secret(t, certName))
	assert.Equal(t, 12*time.Hour, shorter.NotAfter.Sub(shorter.NotBefore))
	assert.Equal(t, "12h0m0s", f.secret(t, certName).Annotations[v1alpha1.AnnotationDuration])
	events = drain(f.recorder.Events)
	require.Len(t, events, 1)
	assert.Regexp(t, `^Normal Renewed`, events[0])

	// a renewal request re-issues once
	require.NoError(t, f.client.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: certName}, cert))
	cert.Annotations = map[string]string{v1alpha1.AnnotationRenewRequested: "2026-10-06"}
	require.NoError(t, f.client.Update(context.Background(), cert))
	_, err, cert = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, int64(6), cert.Status.Revision)
	assert.Equal(t, "2026-10-06", cert.Status.LastRenewRequest)
	_, err, cert = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, int64(6), cert.Status.Revision)

	// removing the annotation renews once and clears the status, so the
	// same value requests a renewal again later
	cert.Annotations = nil
	require.NoError(t, f.client.Update(context.Background(), cert))
	_, err, cert = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, int64(7), cert.Status.Revision)
	assert.Empty(t, cert.Status.LastRenewRequest)
	cert.Annotations = map[string]string{v1alpha1.AnnotationRenewRequested: "2026-10-06"}
	require.NoError(t, f.client.Update(context.Background(), cert))
	_, err, cert = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, int64(8), cert.Status.Revision)
	assert.Equal(t, "2026-10-06", cert.Status.LastRenewRequest)
}

// TestAdoptValidSecret: a Secret labeled for adoption whose certificate
// already matches is owned without re-issuance.
func TestAdoptValidSecret(t *testing.T) {
	ca := testauthority.New(t)
	f := newFixture(t, ca, readyIssuer(ca), enabledNamespace(), webCertificate())
	_, err, cert := f.reconcile(t, certName)
	require.NoError(t, err)
	secret := f.secret(t, certName)
	// a copy of the Secret without the owner, as a hand-made or restored
	// Secret would be
	orphan := secret.DeepCopy()
	orphan.OwnerReferences = nil
	orphan.ResourceVersion = ""
	orphan.Labels = map[string]string{v1alpha1.LabelAdopt: "true"}
	require.NoError(t, f.client.Delete(context.Background(), secret))
	require.NoError(t, f.client.Create(context.Background(), orphan))
	drain(f.recorder.Events)

	_, err, cert = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, int64(1), cert.Status.Revision, "not re-issued")
	assert.Empty(t, drain(f.recorder.Events))
	adopted := f.secret(t, certName)
	owner := metav1.GetControllerOf(adopted)
	require.NotNil(t, owner)
	assert.Equal(t, types.UID("uid-web"), owner.UID)
	assert.Equal(t, "true", adopted.Labels[v1alpha1.LabelManaged])
	assert.Equal(t, "web", adopted.Labels["app"], "template labels applied")
}

// TestAdoptOpaqueSecret: a Secret labeled for adoption whose certificate
// and key match but whose type is Opaque is a conflict, not adopted: the
// next renewal could not be written into it (the type is immutable).
func TestAdoptOpaqueSecret(t *testing.T) {
	ca := testauthority.New(t)
	f := newFixture(t, ca, readyIssuer(ca), enabledNamespace(), webCertificate())
	_, err, _ := f.reconcile(t, certName)
	require.NoError(t, err)
	secret := f.secret(t, certName)
	opaque := secret.DeepCopy()
	opaque.OwnerReferences = nil
	opaque.ResourceVersion = ""
	opaque.Type = corev1.SecretTypeOpaque
	opaque.Labels = map[string]string{v1alpha1.LabelAdopt: "true"}
	require.NoError(t, f.client.Delete(context.Background(), secret))
	require.NoError(t, f.client.Create(context.Background(), opaque))
	drain(f.recorder.Events)

	res, err, cert := f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{RequeueAfter: 5 * time.Minute}, res)
	ready := condition(t, cert, v1alpha1.ConditionReady)
	assert.Equal(t, metav1.ConditionFalse, ready.Status)
	assert.Equal(t, v1alpha1.ReasonSecretConflict, ready.Reason)
	assert.Equal(t, `Secret "web-tls" has type "Opaque", not kubernetes.io/tls; delete it`, ready.Message)
	assert.Equal(t, []string{"Warning SecretConflict " + ready.Message}, drain(f.recorder.Events))
	assert.Nil(t, metav1.GetControllerOf(f.secret(t, certName)), "not adopted")
	assert.Equal(t, int64(1), cert.Status.Revision)
}

// TestRepairTrustData: an up-to-date Secret whose ca.crt or issuer chain
// was removed or replaced gets them back without a re-issuance; the leaf
// and the key stay.
func TestRepairTrustData(t *testing.T) {
	ca := testauthority.New(t)
	f := newFixture(t, ca, readyIssuer(ca), enabledNamespace(), webCertificate())
	_, err, cert := f.reconcile(t, certName)
	require.NoError(t, err)
	issued := f.secret(t, certName)
	leaf, chain := parseLeaf(t, issued)
	require.Len(t, chain, 2)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	drain(f.recorder.Events)

	tcases := []struct {
		name   string
		damage func(*corev1.Secret)
	}{
		{"ca.crt removed", func(s *corev1.Secret) { delete(s.Data, "ca.crt") }},
		{"ca.crt replaced", func(s *corev1.Secret) { s.Data["ca.crt"] = leafPEM }},
		{"chain removed", func(s *corev1.Secret) { s.Data["tls.crt"] = leafPEM }},
		{"both", func(s *corev1.Secret) {
			s.Data["tls.crt"] = leafPEM
			delete(s.Data, "ca.crt")
		}},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			damaged := f.secret(t, certName)
			tc.damage(damaged)
			require.NoError(t, f.client.Update(context.Background(), damaged))

			_, err, got := f.reconcile(t, certName)
			require.NoError(t, err)
			assert.Equal(t, int64(1), got.Status.Revision, "not re-issued")
			assert.Equal(t, cert.Status.SerialNumber, got.Status.SerialNumber)
			assert.True(t, meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionReady))
			assert.Empty(t, drain(f.recorder.Events))
			repaired := f.secret(t, certName)
			assert.Equal(t, ca.RootPEM(), string(repaired.Data["ca.crt"]))
			assert.Equal(t, string(issued.Data["tls.crt"]), string(repaired.Data["tls.crt"]))
			assert.Equal(t, string(issued.Data["tls.key"]), string(repaired.Data["tls.key"]))

			// repaired once: the next reconcile writes nothing
			version := repaired.ResourceVersion
			_, err, _ = f.reconcile(t, certName)
			require.NoError(t, err)
			assert.Equal(t, version, f.secret(t, certName).ResourceVersion)
		})
	}
}

// TestServiceAccountPlaceholder: ${SERVICE_ACCOUNT} is the ServiceAccount
// of the Pod that controls the Certificate, and only for the Certificate
// the Pod controller writes for that Pod (its name, Secret and issuer);
// anything else the Certificate's author can write, an annotation or an
// owner reference with the Pod's real UID included (KUBECA-014), does not
// count. The admission policy of the chart is tested in internal/operator.
func TestServiceAccountPlaceholder(t *testing.T) {
	ca := testauthority.New(t)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "web-0",
			Namespace:   namespace,
			UID:         "uid-pod-web-0",
			Labels:      map[string]string{v1alpha1.LabelInject: v1alpha1.TrueValue},
			Annotations: map[string]string{v1alpha1.AnnotationIssuer: issuerName},
		},
		Spec: corev1.PodSpec{ServiceAccountName: "web"},
	}
	// ownedBy is a Certificate controlled by the Pod, named, stored and
	// issued as the Pod controller would, then changed by mutate
	ownedBy := func(uid types.UID, mutate func(*v1alpha1.Certificate)) *v1alpha1.Certificate {
		cert := webCertificate()
		cert.Name = pod.Name
		cert.UID = types.UID("uid-cert-" + pod.Name)
		cert.Spec.SecretName = pod.Name + "-tls"
		cert.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: "v1",
			Kind:       "Pod",
			Name:       pod.Name,
			UID:        uid,
			Controller: ptr(true),
		}}
		if mutate != nil {
			mutate(cert)
		}
		return cert
	}
	annotated := webCertificate()
	annotated.Annotations = map[string]string{v1alpha1.GroupName + "/service-account": "web"}
	noIssuer := pod.DeepCopy()
	noIssuer.Annotations = nil
	tcases := []struct {
		name   string
		pod    *corev1.Pod
		cert   *v1alpha1.Certificate
		reason string
	}{
		{name: "direct Certificate", cert: webCertificate(), reason: v1alpha1.ReasonPolicyViolation},
		{name: "annotation is not trusted", cert: annotated, reason: v1alpha1.ReasonPolicyViolation},
		{name: "the Pod's own Certificate", cert: ownedBy(pod.UID, nil), reason: v1alpha1.ReasonIssued},
		{name: "stale owner UID", cert: ownedBy("uid-old", nil), reason: v1alpha1.ReasonPolicyViolation},
		{name: "another Certificate owned by the Pod", cert: ownedBy(pod.UID, func(c *v1alpha1.Certificate) {
			c.Name = "evil"
		}), reason: v1alpha1.ReasonPolicyViolation},
		{name: "forged owner, Secret of the author's choice", cert: ownedBy(pod.UID, func(c *v1alpha1.Certificate) {
			c.Spec.SecretName = "attacker-output"
		}), reason: v1alpha1.ReasonPolicyViolation},
		// "other" is Ready with the same policy: only the issuer differs
		{name: "forged owner, another issuer", cert: ownedBy(pod.UID, func(c *v1alpha1.Certificate) {
			c.Spec.IssuerRef.Name = "other"
		}), reason: v1alpha1.ReasonPolicyViolation},
		{name: "forged owner of a Pod without an issuer", pod: noIssuer, cert: ownedBy(pod.UID, nil), reason: v1alpha1.ReasonPolicyViolation},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			ci := readyIssuer(ca)
			ci.Spec.Policy.AllowedURIs = ptr([]string{`^spiffe://example\.org/ns/${NAMESPACE}/sa/${SERVICE_ACCOUNT}$`})
			other := readyIssuer(ca)
			other.Name = "other"
			other.Spec.Policy.AllowedURIs = ci.Spec.Policy.AllowedURIs
			owner := cmp.Or(tc.pod, pod)
			f := newFixture(t, ca, ci, other, enabledNamespace(), owner.DeepCopy(), tc.cert)
			_, err, got := f.reconcile(t, tc.cert.Name)
			require.NoError(t, err)
			ready := condition(t, got, v1alpha1.ConditionReady)
			assert.Equal(t, tc.reason, ready.Reason, ready.Message)
			if tc.reason == v1alpha1.ReasonPolicyViolation {
				assert.Equal(t, `NameNotAllowed: URI "spiffe://example.org/ns/shop/sa/web" is not allowed by the issuer policy`, ready.Message)
				assert.Nil(t, f.secret(t, tc.cert.SecretNameOrDefault()), "nothing issued")
			}
		})
	}
}

// TestSecretKeys pins the Secret keys of the API, spelled out there so
// that api/v1alpha1 imports k8s.io/apimachinery only, to corev1's.
func TestSecretKeys(t *testing.T) {
	t.Parallel()
	assert.Equal(t, corev1.TLSCertKey, v1alpha1.SecretKeyCertificate)
	assert.Equal(t, corev1.TLSPrivateKeyKey, v1alpha1.SecretKeyPrivateKey)
	assert.Equal(t, corev1.ServiceAccountRootCAKey, v1alpha1.SecretKeyCA)
}

func TestRotationPolicyNever(t *testing.T) {
	ca := testauthority.New(t)
	cert := webCertificate()
	cert.Spec.PrivateKey = &v1alpha1.PrivateKeySpec{RotationPolicy: v1alpha1.RotationPolicyNever}
	f := newFixture(t, ca, readyIssuer(ca), enabledNamespace(), cert)

	_, err, cert := f.reconcile(t, certName)
	require.NoError(t, err)
	first, _ := parseLeaf(t, f.secret(t, certName))
	f.clock.SetTime(cert.Status.RenewalTime.Time.Add(time.Second))
	_, err, cert = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, int64(2), cert.Status.Revision)
	second, _ := parseLeaf(t, f.secret(t, certName))
	assert.True(t, samePublicKey(t, second.PublicKey, first.PublicKey), "rotationPolicy Never: same key")
	assert.NotEqual(t, first.SerialNumber, second.SerialNumber)
}

func TestDefaults(t *testing.T) {
	ca := testauthority.New(t)
	cert := webCertificate()
	cert.Spec.Profile = ""
	cert.Spec.Duration = nil
	cert.Spec.RenewBefore = nil
	cert.Spec.SecretName = "custom-secret"
	cert.Spec.PrivateKey = &v1alpha1.PrivateKeySpec{Algorithm: v1alpha1.KeyAlgorithmRSA}
	f := newFixture(t, ca, readyIssuer(ca), enabledNamespace(), cert)

	res, err, cert := f.reconcile(t, certName)
	require.NoError(t, err)
	assert.True(t, meta.IsStatusConditionTrue(cert.Status.Conditions, v1alpha1.ConditionReady))
	secret := f.secret(t, "custom-secret")
	require.NotNil(t, secret)
	assert.Equal(t, testauthority.ProfilePeer, secret.Annotations[v1alpha1.AnnotationProfile], "issuer default profile")
	// the expiration metric carries the profile that signed, not the empty
	// spec.profile (DeleteLabelValues reports whether such a series existed)
	assert.Equal(t, float64(cert.Status.NotAfter.Unix()),
		testutil.ToFloat64(metrics.CertificateExpiration.WithLabelValues(namespace, certName, issuerName, testauthority.ProfilePeer)))
	assert.False(t, metrics.CertificateExpiration.DeleteLabelValues(namespace, certName, issuerName, ""), "no series with an empty profile")
	leaf, _ := parseLeaf(t, secret)
	assert.Equal(t, x509.RSA, leaf.PublicKeyAlgorithm)
	assert.Equal(t, 24*time.Hour, leaf.NotAfter.Sub(leaf.NotBefore), "profile expiry")
	// renewBefore defaults to a third: renewal 8 h (± jitter) before expiry
	assert.Greater(t, res.RequeueAfter, 15*time.Hour)
	assert.Less(t, res.RequeueAfter, 16*time.Hour)
}

func TestMaxDurationBounds(t *testing.T) {
	ca := testauthority.New(t)
	ci := readyIssuer(ca)
	ci.Spec.Policy.MaxDuration = &metav1.Duration{Duration: 6 * time.Hour}
	cert := webCertificate()
	cert.Spec.RenewBefore = &metav1.Duration{Duration: 8 * time.Hour} // longer than the bounded 6h
	f := newFixture(t, ca, ci, enabledNamespace(), cert)

	res, err, cert := f.reconcile(t, certName)
	require.NoError(t, err)
	leaf, _ := parseLeaf(t, f.secret(t, certName))
	assert.Equal(t, 6*time.Hour, leaf.NotAfter.Sub(leaf.NotBefore))
	// renewBefore falls back to a third of the lifetime
	assert.InDelta(t, cert.Status.RenewalTime.Time.UTC().Sub(f.clock.Now()).Seconds(), res.RequeueAfter.Seconds(), 1)
	assert.Greater(t, res.RequeueAfter, 3*time.Hour+30*time.Minute)
}

// TestShortLifetime covers the re-issuance loop guard: a certificate is
// never renewed sooner than a minute after its issuance, and a duration
// that leaves less than two minutes after the backdate is rejected.
func TestShortLifetime(t *testing.T) {
	ca := testauthority.New(t)
	cert := webCertificate()
	// peer-24h has a 5m backdate: 6m leaves 1m of usable lifetime
	cert.Spec.Duration = &metav1.Duration{Duration: 6 * time.Minute}
	cert.Spec.RenewBefore = nil
	f := newFixture(t, ca, readyIssuer(ca), enabledNamespace(), cert)
	res, err, got := f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, res)
	ready := condition(t, got, v1alpha1.ConditionReady)
	assert.Equal(t, v1alpha1.ReasonPolicyViolation, ready.Reason)
	assert.Equal(t, `duration 6m0s minus the backdate 5m0s of profile "server-24h" leaves less than 2m0s of usable lifetime`, ready.Message)

	// 8m leaves 3m: renewBefore 2m50s would renew at once, so it falls
	// back to a third of the usable lifetime and the renewal is at least
	// a minute after the issuance
	cert = webCertificate()
	cert.Spec.Duration = &metav1.Duration{Duration: 8 * time.Minute}
	cert.Spec.RenewBefore = &metav1.Duration{Duration: 2*time.Minute + 50*time.Second}
	f = newFixture(t, ca, readyIssuer(ca), enabledNamespace(), cert)
	t0 := f.clock.Now()
	res, err, got = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.ReasonIssued, condition(t, got, v1alpha1.ConditionReady).Reason)
	assert.GreaterOrEqual(t, res.RequeueAfter, time.Minute)
	assert.GreaterOrEqual(t, got.Status.RenewalTime.Time.UTC().Sub(t0), time.Minute-time.Second)
	assert.True(t, got.Status.RenewalTime.Time.Before(got.Status.NotAfter.Time))

	// the Secret write re-triggers the reconcile at once: no re-issuance
	for range 3 {
		_, err, got = f.reconcile(t, certName)
		require.NoError(t, err)
		assert.Equal(t, int64(1), got.Status.Revision)
	}
	// a minute later still no renewal before the renewal time
	f.clock.Step(59 * time.Second)
	_, err, got = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, int64(1), got.Status.Revision)
	f.clock.SetTime(got.Status.RenewalTime.Time.Add(time.Second))
	_, err, got = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, int64(2), got.Status.Revision)
}

func TestKubernetesNames(t *testing.T) {
	ca := testauthority.New(t)
	cert := webCertificate()
	cert.Spec.DNSNames = nil
	cert.Spec.URIs = nil
	cert.Spec.CommonName = ""
	cert.Spec.KubernetesNames = &v1alpha1.KubernetesNames{Services: []string{"web"}, IncludeUnqualified: true, IncludeClusterIP: true}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: namespace},
		// dual-stack: both cluster addresses
		Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.10", ClusterIPs: []string{"10.96.0.10", "fd00::a"}},
	}
	f := newFixture(t, ca, readyIssuer(ca), enabledNamespace(), cert, svc)
	_, err, cert := f.reconcile(t, certName)
	require.NoError(t, err)
	require.True(t, meta.IsStatusConditionTrue(cert.Status.Conditions, v1alpha1.ConditionReady), cert.Status.Conditions)
	leaf, _ := parseLeaf(t, f.secret(t, certName))
	assert.Equal(t, []string{"web.shop.svc.cluster.local", "web.shop.svc"}, leaf.DNSNames)
	require.Len(t, leaf.IPAddresses, 2)
	assert.Equal(t, "10.96.0.10", leaf.IPAddresses[0].String())
	assert.Equal(t, "fd00::a", leaf.IPAddresses[1].String())

	// a missing Service is a policy violation until it appears
	cert.Spec.KubernetesNames.Services = []string{"missing"}
	require.NoError(t, f.client.Update(context.Background(), cert))
	res, err, cert := f.reconcile(t, certName)
	require.NoError(t, err)
	ready := condition(t, cert, v1alpha1.ConditionReady)
	assert.Equal(t, v1alpha1.ReasonPolicyViolation, ready.Reason)
	assert.Equal(t, `ServiceNotFound: Service "missing" not found in namespace "shop"`, ready.Message)
	assert.Equal(t, ctrl.Result{}, res)
}

func TestPolicyViolation(t *testing.T) {
	ca := testauthority.New(t)
	tcases := []struct {
		name    string
		mutate  func(*v1alpha1.Certificate, *corev1.Namespace)
		message string
	}{
		{
			name:    "namespace not selected",
			mutate:  func(_ *v1alpha1.Certificate, ns *corev1.Namespace) { ns.Labels = nil },
			message: `NamespaceNotAllowed: namespace "shop" is not selected by the issuer policy`,
		},
		{
			name:    "DNS name not allowed",
			mutate:  func(c *v1alpha1.Certificate, _ *corev1.Namespace) { c.Spec.DNSNames = []string{"web.other.svc"} },
			message: `NameNotAllowed: DNS name "web.other.svc" is not allowed by the issuer policy`,
		},
		{
			name:    "common name not allowed",
			mutate:  func(c *v1alpha1.Certificate, _ *corev1.Namespace) { c.Spec.CommonName = "system:admin" },
			message: `NameNotAllowed: common name "system:admin" is not allowed by the issuer policy`,
		},
		{
			name: "URI not allowed",
			mutate: func(c *v1alpha1.Certificate, _ *corev1.Namespace) {
				c.Spec.URIs = []string{"spiffe://example.org/ns/other/sa/web"}
			},
			message: `NameNotAllowed: URI "spiffe://example.org/ns/other/sa/web" is not allowed by the issuer policy`,
		},
		{
			name:    "profile not exposed",
			mutate:  func(c *v1alpha1.Certificate, _ *corev1.Namespace) { c.Spec.Profile = "webhook" },
			message: `profile "webhook" is not exposed by ClusterIssuer "kubeca"`,
		},
		{
			name:    "profile does not copy DNS names",
			mutate:  func(c *v1alpha1.Certificate, _ *corev1.Namespace) { c.Spec.Profile = testauthority.ProfileClient },
			message: `profile "client-24h" does not allow DNS names`,
		},
		{
			name:    "invalid name",
			mutate:  func(c *v1alpha1.Certificate, _ *corev1.Namespace) { c.Spec.DNSNames = []string{"-bad.shop.svc"} },
			message: `invalid names: invalid SAN "-bad.shop.svc": DNS label "-bad" starts or ends with a hyphen`,
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			cert, ns := webCertificate(), enabledNamespace()
			tc.mutate(cert, ns)
			f := newFixture(t, ca, readyIssuer(ca), ns, cert)
			res, err, got := f.reconcile(t, certName)
			require.NoError(t, err)
			assert.Equal(t, ctrl.Result{}, res)
			ready := condition(t, got, v1alpha1.ConditionReady)
			assert.Equal(t, metav1.ConditionFalse, ready.Status)
			assert.Equal(t, v1alpha1.ReasonPolicyViolation, ready.Reason)
			assert.Equal(t, tc.message, ready.Message)
			issuing := condition(t, got, v1alpha1.ConditionIssuing)
			assert.Equal(t, metav1.ConditionFalse, issuing.Status)
			assert.Equal(t, v1alpha1.ReasonFailed, issuing.Reason)
			assert.Nil(t, f.secret(t, certName))
			assert.Equal(t, int64(0), got.Status.Revision)
			assert.Equal(t, []string{"Warning PolicyViolation " + tc.message}, drain(f.recorder.Events))
		})
	}
}

// TestInvalidSecretTemplate: a secretTemplate the Secret API would reject
// is a PolicyViolation found before signing, for a new Certificate and for
// an issued one (whose Secret stays as it is), instead of a Secret write
// error retried with a new signature every time.
func TestInvalidSecretTemplate(t *testing.T) {
	ca := testauthority.New(t)
	// sorted: the annotation error first, the label error second
	const (
		annotationError = `invalid secretTemplate: spec.secretTemplate.annotations: Invalid value: "Team/Owner/x": `
		labelError      = `; spec.secretTemplate.labels: Invalid value: "front end": `
	)
	invalidate := func(cert *v1alpha1.Certificate) {
		cert.Spec.SecretTemplate.Labels["tier"] = "front end"
		cert.Spec.SecretTemplate.Annotations["Team/Owner/x"] = "shop"
		// a reserved key is dropped, not validated
		cert.Spec.SecretTemplate.Labels[v1alpha1.GroupName+"/bad key"] = "x"
	}
	rejected := func(t *testing.T, f *fixture, revision int64) {
		t.Helper()
		res, err, cert := f.reconcile(t, certName)
		require.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, res)
		ready := condition(t, cert, v1alpha1.ConditionReady)
		assert.Equal(t, metav1.ConditionFalse, ready.Status)
		assert.Equal(t, v1alpha1.ReasonPolicyViolation, ready.Reason)
		assert.True(t, strings.HasPrefix(ready.Message, annotationError), ready.Message)
		assert.Contains(t, ready.Message, labelError)
		assert.Equal(t, revision, cert.Status.Revision)
		assert.Equal(t, []string{"Warning PolicyViolation " + ready.Message}, drain(f.recorder.Events))
	}

	t.Run("new", func(t *testing.T) {
		cert := webCertificate()
		invalidate(cert)
		f := newFixture(t, ca, readyIssuer(ca), enabledNamespace(), cert)
		rejected(t, f, 0)
		assert.Nil(t, f.secret(t, certName))
	})

	t.Run("issued", func(t *testing.T) {
		f := newFixture(t, ca, readyIssuer(ca), enabledNamespace(), webCertificate())
		_, err, cert := f.reconcile(t, certName)
		require.NoError(t, err)
		drain(f.recorder.Events)
		secret := f.secret(t, certName)
		invalidate(cert)
		require.NoError(t, f.client.Update(context.Background(), cert))
		rejected(t, f, 1)
		assert.Equal(t, secret, f.secret(t, certName), "neither re-issued nor rewritten")
	})
}

func TestIssuerNotReady(t *testing.T) {
	ca := testauthority.New(t)
	notReady := readyIssuer(ca)
	notReady.Status.Conditions[0].Status = metav1.ConditionFalse
	notReady.Status.Conditions[0].Reason = v1alpha1.ReasonCAExpired
	notReady.Status.Conditions[0].Message = "expired"
	notLoaded := readyIssuer(ca)
	notLoaded.Spec.IssuerLabel = "other.svc"

	tcases := []struct {
		name    string
		issuer  client.Object
		message string
	}{
		{"missing", nil, `ClusterIssuer "kubeca" not found`},
		{"not ready", notReady, `ClusterIssuer "kubeca" is not ready: CAExpired: expired`},
		{"label not loaded", notLoaded, `issuer "other.svc" of ClusterIssuer "kubeca" is not loaded`},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			objs := []client.Object{enabledNamespace(), webCertificate()}
			if tc.issuer != nil {
				objs = append(objs, tc.issuer)
			}
			f := newFixture(t, ca, objs...)
			res, err, got := f.reconcile(t, certName)
			require.NoError(t, err)
			assert.Equal(t, ctrl.Result{RequeueAfter: time.Minute}, res)
			ready := condition(t, got, v1alpha1.ConditionReady)
			assert.Equal(t, v1alpha1.ReasonIssuerNotReady, ready.Reason)
			assert.Equal(t, tc.message, ready.Message)
			assert.Equal(t, []string{"Warning IssuerNotReady " + tc.message}, drain(f.recorder.Events))
		})
	}
}

// TestIssuerNotReadyKeepsReady: an issuer that goes away leaves a valid
// stored certificate Ready and only marks the issuance as failed.
func TestIssuerNotReadyKeepsReady(t *testing.T) {
	ca := testauthority.New(t)
	ci := readyIssuer(ca)
	f := newFixture(t, ca, ci, enabledNamespace(), webCertificate())
	_, err, cert := f.reconcile(t, certName)
	require.NoError(t, err)
	drain(f.recorder.Events)

	require.NoError(t, f.client.Delete(context.Background(), ci))
	f.clock.Step(time.Hour)
	res, err, cert := f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{RequeueAfter: time.Minute}, res)
	assert.Equal(t, metav1.ConditionTrue, condition(t, cert, v1alpha1.ConditionReady).Status)
	issuing := condition(t, cert, v1alpha1.ConditionIssuing)
	assert.Equal(t, metav1.ConditionFalse, issuing.Status)
	assert.Equal(t, v1alpha1.ReasonFailed, issuing.Reason)
	assert.Equal(t, `ClusterIssuer "kubeca" not found`, issuing.Message)
	assert.Equal(t, []string{`Warning IssuerNotReady ClusterIssuer "kubeca" not found`}, drain(f.recorder.Events))

	// once the certificate expired, Ready goes False
	f.clock.SetTime(cert.Status.NotAfter.Time.Add(time.Second))
	_, err, cert = f.reconcile(t, certName)
	require.NoError(t, err)
	ready := condition(t, cert, v1alpha1.ConditionReady)
	assert.Equal(t, metav1.ConditionFalse, ready.Status)
	assert.Equal(t, v1alpha1.ReasonIssuerNotReady, ready.Reason)
}

func TestSecretConflict(t *testing.T) {
	ca := testauthority.New(t)
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: certName, Namespace: namespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"other": []byte("x")},
	}
	f := newFixture(t, ca, readyIssuer(ca), enabledNamespace(), webCertificate(), foreign)

	res, err, cert := f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{RequeueAfter: 5 * time.Minute}, res)
	ready := condition(t, cert, v1alpha1.ConditionReady)
	assert.Equal(t, v1alpha1.ReasonSecretConflict, ready.Reason)
	assert.Equal(t, `Secret "web-tls" exists and is not managed by kubeca; delete it or label it kubeca.effectivesecurity/adopt=true`, ready.Message)
	assert.Equal(t, []string{"Warning SecretConflict " + ready.Message}, drain(f.recorder.Events))
	assert.Equal(t, corev1.SecretTypeOpaque, f.secret(t, certName).Type, "untouched")

	// labeled for adoption, but the type is wrong: a conflict before any
	// issuance decision
	secret := f.secret(t, certName)
	secret.Labels = map[string]string{v1alpha1.LabelAdopt: "true"}
	require.NoError(t, f.client.Update(context.Background(), secret))
	res, err, cert = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{RequeueAfter: 5 * time.Minute}, res)
	ready = condition(t, cert, v1alpha1.ConditionReady)
	assert.Equal(t, v1alpha1.ReasonSecretConflict, ready.Reason)
	assert.Equal(t, `Secret "web-tls" has type "Opaque", not kubernetes.io/tls; delete it`, ready.Message)
	assert.Equal(t, int32(0), cert.Status.FailedAttempts, "no issuance attempted")
	drain(f.recorder.Events)

	// a TLS Secret labeled for adoption is taken over
	require.NoError(t, f.client.Delete(context.Background(), secret))
	adoptable := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: certName, Namespace: namespace, Labels: map[string]string{v1alpha1.LabelAdopt: "true"}},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": []byte("stale"), "tls.key": []byte("stale")},
	}
	require.NoError(t, f.client.Create(context.Background(), adoptable))
	_, err, cert = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.ReasonIssued, condition(t, cert, v1alpha1.ConditionReady).Reason)
	assert.Equal(t, int32(0), cert.Status.FailedAttempts)
	secret = f.secret(t, certName)
	owner := metav1.GetControllerOf(secret)
	require.NotNil(t, owner)
	assert.Equal(t, types.UID("uid-web"), owner.UID)
	assert.Equal(t, "true", secret.Labels[v1alpha1.LabelManaged])
	parseLeaf(t, secret)
}

func TestIssuanceFailedPermanent(t *testing.T) {
	ca := testauthority.New(t)
	cert := webCertificate()
	cert.Spec.Profile = testauthority.ProfileClient
	cert.Spec.DNSNames = nil
	cert.Spec.CommonName = ""
	// the ClusterIssuer policy allows it, the xpki profile allowed_uri does not
	cert.Spec.URIs = []string{"spiffe://other.org/ns/shop/sa/web"}
	ci := readyIssuer(ca)
	ci.Spec.Policy = &v1alpha1.IssuerPolicy{}
	f := newFixture(t, ca, ci, enabledNamespace(), cert)

	res, err, got := f.reconcile(t, certName)
	require.NoError(t, err, "permanent: not retried")
	assert.Equal(t, ctrl.Result{}, res)
	ready := condition(t, got, v1alpha1.ConditionReady)
	assert.Equal(t, metav1.ConditionFalse, ready.Status)
	assert.Equal(t, v1alpha1.ReasonIssuanceFailed, ready.Reason)
	assert.Equal(t, "unable to sign: URI does not match allowed list: spiffe://other.org/ns/shop/sa/web", ready.Message)
	issuing := condition(t, got, v1alpha1.ConditionIssuing)
	assert.Equal(t, metav1.ConditionFalse, issuing.Status)
	assert.Equal(t, v1alpha1.ReasonFailed, issuing.Reason)
	assert.Equal(t, int32(1), got.Status.FailedAttempts)
	require.NotNil(t, got.Status.LastFailureTime)
	assert.Equal(t, f.clock.Now().Truncate(time.Second), got.Status.LastFailureTime.Time.UTC())
	assert.Nil(t, f.secret(t, certName))
	assert.Equal(t, []string{"Warning IssuanceFailed " + ready.Message}, drain(f.recorder.Events))
}

// TestStatusPatchFailure: the Secret is written before the status patch.
// When that patch fails, the retry takes the revision and the honoured
// renewal request from the Secret instead of issuing again.
func TestStatusPatchFailure(t *testing.T) {
	ca := testauthority.New(t)
	var failStatus bool
	b := fake.NewClientBuilder().
		WithObjects(readyIssuer(ca), enabledNamespace(), webCertificate()).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, c client.Client, subResource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				if failStatus {
					failStatus = false
					return errors.New("etcdserver: request timed out")
				}
				return c.SubResource(subResource).Patch(ctx, obj, patch, opts...)
			},
		})
	f := newFixtureWithBuilder(t, ca, b)
	_, err, cert := f.reconcile(t, certName)
	require.NoError(t, err)
	require.Equal(t, int64(1), cert.Status.Revision)
	drain(f.recorder.Events)

	// a renewal request: the Secret is written, the status patch fails
	cert.Annotations = map[string]string{v1alpha1.AnnotationRenewRequested: "r1"}
	require.NoError(t, f.client.Update(context.Background(), cert))
	failStatus = true
	_, err, cert = f.reconcile(t, certName)
	require.Error(t, err)
	assert.Equal(t, "unable to patch Certificate status: etcdserver: request timed out", err.Error())
	assert.Equal(t, int64(1), cert.Status.Revision, "the status was not written")
	assert.Empty(t, cert.Status.LastRenewRequest)
	secret := f.secret(t, certName)
	assert.Equal(t, "2", secret.Annotations[v1alpha1.AnnotationRevision])
	assert.Equal(t, "r1", secret.Annotations[v1alpha1.AnnotationRenewRequested])
	serial := secret.Annotations[v1alpha1.AnnotationSerial]
	drain(f.recorder.Events)

	// the retry: the status catches up with the Secret, nothing is issued
	_, err, cert = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, int64(2), cert.Status.Revision)
	assert.Equal(t, "r1", cert.Status.LastRenewRequest)
	assert.Equal(t, serial, cert.Status.SerialNumber)
	assert.Equal(t, serial, f.secret(t, certName).Annotations[v1alpha1.AnnotationSerial])
	assert.Empty(t, drain(f.recorder.Events))

	// the next issuance counts on from there and drops the honoured request
	// from the Secret once the Certificate no longer carries it
	cert.Annotations = nil
	require.NoError(t, f.client.Update(context.Background(), cert))
	_, err, cert = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, int64(3), cert.Status.Revision)
	assert.NotContains(t, f.secret(t, certName).Annotations, v1alpha1.AnnotationRenewRequested)
}

// TestStaleSecretCache: the retry after a failed status patch reads the
// Secret from a cache that still holds it as it was before the write. The
// decision to sign is taken again on the Secret the API server holds, so
// the status is restored from it and nothing is signed twice.
func TestStaleSecretCache(t *testing.T) {
	ca := testauthority.New(t)
	f := newFixture(t, ca, readyIssuer(ca), enabledNamespace(), webCertificate())
	_, err, cert := f.reconcile(t, certName)
	require.NoError(t, err)
	stale := f.secret(t, certName) // revision 1, as the cache will keep it

	// the reconciler reads through a "cache" that can serve the stale
	// Secret and whose status patches can fail; APIReader stays current
	var serveStale, failStatus bool
	f.r.Client = interceptor.NewClient(f.client.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if secret, ok := obj.(*corev1.Secret); ok && serveStale && key.Name == certName {
				stale.DeepCopyInto(secret)
				return nil
			}
			return c.Get(ctx, key, obj, opts...)
		},
		SubResourcePatch: func(ctx context.Context, c client.Client, subResource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			if failStatus {
				failStatus = false
				return errors.New("etcdserver: request timed out")
			}
			return c.SubResource(subResource).Patch(ctx, obj, patch, opts...)
		},
	})

	// a renewal request: the Secret becomes revision 2, the status patch fails
	cert.Annotations = map[string]string{v1alpha1.AnnotationRenewRequested: "r1"}
	require.NoError(t, f.client.Update(context.Background(), cert))
	failStatus = true
	_, err, cert = f.reconcile(t, certName)
	require.Error(t, err)
	assert.Equal(t, int64(1), cert.Status.Revision)
	written := f.secret(t, certName)
	require.Equal(t, "2", written.Annotations[v1alpha1.AnnotationRevision])
	drain(f.recorder.Events)

	// the retry sees the stale revision 1 in the cache
	serveStale = true
	_, err, cert = f.reconcile(t, certName)
	require.NoError(t, err, "no second signature (it would conflict on the stale resourceVersion)")
	assert.Equal(t, int64(2), cert.Status.Revision)
	assert.Equal(t, "r1", cert.Status.LastRenewRequest)
	assert.Equal(t, written.Annotations[v1alpha1.AnnotationSerial], cert.Status.SerialNumber)
	assert.Equal(t, written.ResourceVersion, f.secret(t, certName).ResourceVersion, "the Secret is not written again")
	assert.Empty(t, drain(f.recorder.Events))
}

func TestTransientError(t *testing.T) {
	ca := testauthority.New(t)
	var fail bool
	b := fake.NewClientBuilder().
		WithObjects(readyIssuer(ca), enabledNamespace(), webCertificate()).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*corev1.Secret); ok && fail {
					return errors.New("etcdserver: request timed out")
				}
				return c.Create(ctx, obj, opts...)
			},
		})
	f := newFixtureWithBuilder(t, ca, b)

	fail = true
	res, err, cert := f.reconcile(t, certName)
	require.Error(t, err)
	assert.Equal(t, "issuance failed: unable to create Secret shop/web-tls: etcdserver: request timed out", err.Error())
	assert.Equal(t, ctrl.Result{}, res)
	ready := condition(t, cert, v1alpha1.ConditionReady)
	assert.Equal(t, metav1.ConditionFalse, ready.Status)
	assert.Equal(t, v1alpha1.ReasonIssuanceFailed, ready.Reason)
	issuing := condition(t, cert, v1alpha1.ConditionIssuing)
	assert.Equal(t, metav1.ConditionTrue, issuing.Status, "still issuing")
	assert.Equal(t, v1alpha1.ReasonInitial, issuing.Reason)
	assert.Equal(t, int32(1), cert.Status.FailedAttempts)
	assert.Equal(t, []string{"Warning IssuanceFailed unable to create Secret shop/web-tls: etcdserver: request timed out"}, drain(f.recorder.Events))

	fail = false
	_, err, cert = f.reconcile(t, certName)
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.ReasonIssued, condition(t, cert, v1alpha1.ConditionReady).Reason)
	assert.Equal(t, int32(0), cert.Status.FailedAttempts)
	assert.Nil(t, cert.Status.LastFailureTime)
	assert.Equal(t, int64(1), cert.Status.Revision)
}

func TestRenewalFailureKeepsReady(t *testing.T) {
	ca := testauthority.New(t)
	var fail bool
	b := fake.NewClientBuilder().
		WithObjects(readyIssuer(ca), enabledNamespace(), webCertificate()).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if _, ok := obj.(*corev1.Secret); ok && fail {
					return errors.New("etcdserver: request timed out")
				}
				return c.Update(ctx, obj, opts...)
			},
		})
	f := newFixtureWithBuilder(t, ca, b)
	_, err, cert := f.reconcile(t, certName)
	require.NoError(t, err)
	drain(f.recorder.Events)

	fail = true
	f.clock.SetTime(cert.Status.RenewalTime.Time.Add(time.Second))
	_, err, cert = f.reconcile(t, certName)
	require.Error(t, err)
	assert.Equal(t, metav1.ConditionTrue, condition(t, cert, v1alpha1.ConditionReady).Status, "the stored certificate is still valid")
	issuing := condition(t, cert, v1alpha1.ConditionIssuing)
	assert.Equal(t, metav1.ConditionTrue, issuing.Status)
	assert.Equal(t, v1alpha1.ReasonRenewal, issuing.Reason)
	assert.Equal(t, int32(1), cert.Status.FailedAttempts)
}

func TestDeleted(t *testing.T) {
	ca := testauthority.New(t)
	f := newFixture(t, ca)
	res, err, cert := f.reconcile(t, "nope")
	require.NoError(t, err)
	assert.Nil(t, cert)
	assert.Equal(t, ctrl.Result{}, res)
}

// TestConcurrentReconciles issues several Certificates at once, as the
// controller does with MaxConcurrentReconciles > 1 (run with -race).
func TestConcurrentReconciles(t *testing.T) {
	ca := testauthority.New(t)
	const n = 8
	objs := []client.Object{readyIssuer(ca), enabledNamespace()}
	for i := range n {
		cert := webCertificate()
		cert.Name = fmt.Sprintf("web-%d", i)
		cert.UID = types.UID(cert.Name)
		objs = append(objs, cert)
	}
	f := newFixture(t, ca, objs...)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err, cert := f.reconcile(t, fmt.Sprintf("web-%d", i))
			assert.NoError(t, err)
			assert.Equal(t, int64(1), cert.Status.Revision)
		}()
	}
	wg.Wait()
	events := drain(f.recorder.Events)
	assert.Len(t, events, n)
	for _, e := range events {
		assert.Regexp(t, regexp.MustCompile(`^Normal Issued`), e)
	}
}
