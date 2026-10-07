package issuer_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"slices"
	"testing"
	"time"

	"github.com/effective-security/kubeca/api/v1alpha1"
	"github.com/effective-security/kubeca/internal/operator/index"
	"github.com/effective-security/kubeca/internal/operator/issuer"
	"github.com/effective-security/kubeca/internal/testauthority"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/testca"
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
)

const issuerName = "kubeca"

func ptr[T any](v T) *T { return &v }

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, v1alpha1.AddToScheme(s))
	return s
}

func newClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithStatusSubresource(&v1alpha1.ClusterIssuer{}, &v1alpha1.Certificate{}).
		WithIndex(&v1alpha1.Certificate{}, index.CertificateIssuer, index.CertificateIssuerValue).
		WithObjects(objs...).
		Build()
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
	r        *issuer.Reconciler
}

func newFixture(t *testing.T, ca *testauthority.CA, objs ...client.Object) *fixture {
	t.Helper()
	c := newClient(t, objs...)
	recorder := record.NewFakeRecorder(20)
	clk := clocktesting.NewFakeClock(time.Date(2026, 10, 6, 10, 0, 30, 0, time.UTC))
	return &fixture{
		ca:       ca,
		client:   c,
		recorder: recorder,
		clock:    clk,
		r: &issuer.Reconciler{
			Client:    c,
			APIReader: c,
			Scheme:    c.Scheme(),
			Authority: ca.Authority,
			Recorder:  recorder,
			Clock:     clk,
		},
	}
}

func (f *fixture) reconcile(t *testing.T, name string) (ctrl.Result, *v1alpha1.ClusterIssuer) {
	t.Helper()
	res, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}})
	require.NoError(t, err)
	var ci v1alpha1.ClusterIssuer
	require.NoError(t, f.client.Get(context.Background(), client.ObjectKey{Name: name}, &ci))
	return res, &ci
}

func exampleIssuer() *v1alpha1.ClusterIssuer {
	return &v1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: issuerName, Generation: 1},
		Spec: v1alpha1.ClusterIssuerSpec{
			IssuerLabel:    testauthority.IssuerLabel,
			Profiles:       []string{testauthority.ProfilePeer, testauthority.ProfileServer, testauthority.ProfileClient},
			DefaultProfile: testauthority.ProfilePeer,
			SPIFFE:         &v1alpha1.SPIFFESpec{TrustDomain: "example.org"},
			Policy: &v1alpha1.IssuerPolicy{
				MaxDuration:     &metav1.Duration{Duration: 24 * time.Hour},
				AllowedDNSNames: ptr([]string{`^[a-z0-9-]+\.${NAMESPACE}\.svc(\.cluster\.local)?$`}),
			},
		},
	}
}

func TestReconcileLoaded(t *testing.T) {
	ca := testauthority.New(t)
	f := newFixture(t, ca, exampleIssuer())

	res, ci := f.reconcile(t, issuerName)
	ready := meta.FindStatusCondition(ci.Status.Conditions, v1alpha1.ConditionReady)
	require.NotNil(t, ready)
	assert.Equal(t, metav1.ConditionTrue, ready.Status)
	assert.Equal(t, v1alpha1.ReasonLoaded, ready.Reason)
	assert.Equal(t, "issuer kubeca.svc, 3 profiles", ready.Message)
	assert.Equal(t, int64(1), ready.ObservedGeneration)
	assert.Equal(t, f.clock.Now(), ready.LastTransitionTime.Time.UTC())
	assert.Equal(t, certutil.GetSubjectKeyID(ca.Issuer.Certificate), ci.Status.IssuerKeyID)
	assert.Equal(t, ca.RootPEM(), ci.Status.RootCertificate)
	assert.Equal(t, string(testca.ToPEM(ca.Issuer.Certificate)), ci.Status.CACertificate)
	require.NotNil(t, ci.Status.CANotAfter)
	assert.Equal(t, ca.Issuer.Certificate.NotAfter.Truncate(time.Second), ci.Status.CANotAfter.Time.UTC())
	// sorted by name (the API contract), not in the order of spec.profiles
	assert.Equal(t, []v1alpha1.ProfileStatus{
		{Name: "client-24h", Expiry: metav1.Duration{Duration: 24 * time.Hour}, Backdate: metav1.Duration{Duration: 5 * time.Minute}, Usages: []string{"signing", "key encipherment", "client auth"}},
		{Name: "peer-24h", Expiry: metav1.Duration{Duration: 24 * time.Hour}, Backdate: metav1.Duration{Duration: 5 * time.Minute}, Usages: []string{"signing", "key encipherment", "server auth", "client auth"}},
		{Name: "server-24h", Expiry: metav1.Duration{Duration: 24 * time.Hour}, Backdate: metav1.Duration{Duration: 5 * time.Minute}, Usages: []string{"signing", "key encipherment", "server auth"}},
	}, ci.Status.Profiles)
	assert.Equal(t, []string{"peer-24h", "server-24h", "client-24h"}, ci.Spec.Profiles, "spec untouched")
	// the CA is valid for years: re-evaluated every hour at most
	assert.Equal(t, time.Hour, res.RequeueAfter)
	assert.Equal(t, []string{"Normal Ready issuer kubeca.svc, 3 profiles"}, drain(f.recorder.Events))

	// a second reconcile changes nothing and emits no event
	before := ci.ResourceVersion
	_, ci = f.reconcile(t, issuerName)
	assert.Equal(t, before, ci.ResourceVersion)
	assert.Empty(t, drain(f.recorder.Events))
}

func TestReconcileAllProfiles(t *testing.T) {
	ca := testauthority.New(t)
	ci := exampleIssuer()
	ci.Spec.Profiles = nil
	ci.Spec.DefaultProfile = ""
	ci.Spec.Policy = nil
	f := newFixture(t, ca, ci)

	_, got := f.reconcile(t, issuerName)
	assert.True(t, meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionReady))
	names := make([]string, 0, len(got.Status.Profiles))
	for _, p := range got.Status.Profiles {
		names = append(names, p.Name)
	}
	assert.Equal(t, []string{"client-24h", "peer-24h", "server-24h", "webhook"}, names)
}

func TestReconcileNotReady(t *testing.T) {
	ca := testauthority.New(t)
	tcases := []struct {
		name    string
		mutate  func(*v1alpha1.ClusterIssuer)
		reason  string
		message string
	}{
		{
			name:    "issuer not found",
			mutate:  func(ci *v1alpha1.ClusterIssuer) { ci.Spec.IssuerLabel = "other.svc" },
			reason:  v1alpha1.ReasonIssuerNotFound,
			message: `issuer "other.svc" is not loaded in the CA configuration`,
		},
		{
			name:    "profile not found",
			mutate:  func(ci *v1alpha1.ClusterIssuer) { ci.Spec.Profiles = []string{"peer-24h", "nope"} },
			reason:  v1alpha1.ReasonProfileNotFound,
			message: `profile "nope" is not served by issuer "kubeca.svc"`,
		},
		{
			name: "default profile not served",
			mutate: func(ci *v1alpha1.ClusterIssuer) {
				ci.Spec.Profiles = nil
				ci.Spec.DefaultProfile = "nope"
			},
			reason:  v1alpha1.ReasonProfileNotFound,
			message: `default profile "nope" is not served by issuer "kubeca.svc"`,
		},
		{
			name: "invalid policy",
			mutate: func(ci *v1alpha1.ClusterIssuer) {
				ci.Spec.Policy.AllowedURIs = ptr([]string{"^("})
			},
			reason:  v1alpha1.ReasonInvalidPolicy,
			message: "policy: allowedURIs: \"^(\": error parsing regexp: missing closing ): `^(`",
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			ci := exampleIssuer()
			tc.mutate(ci)
			f := newFixture(t, ca, ci)
			res, got := f.reconcile(t, issuerName)
			ready := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionReady)
			require.NotNil(t, ready)
			assert.Equal(t, metav1.ConditionFalse, ready.Status)
			assert.Equal(t, tc.reason, ready.Reason)
			assert.Equal(t, tc.message, ready.Message)
			assert.Empty(t, got.Status.IssuerKeyID)
			assert.Empty(t, got.Status.RootCertificate)
			assert.Nil(t, got.Status.CANotAfter)
			assert.Nil(t, got.Status.Profiles)
			assert.Equal(t, ctrl.Result{}, res)
			assert.Equal(t, []string{"Warning " + tc.reason + " " + tc.message}, drain(f.recorder.Events))
		})
	}
}

// TestReconcileCAExpiring drives the CA through the expiring and expired
// transitions with the fake clock.
func TestReconcileCAExpiring(t *testing.T) {
	// the real time: building the Authority verifies the issuing CA against
	// the real clock, so a fixed date fails once it is two days old (the
	// evaluation itself runs on the fake clock); seconds, as in x509
	now := time.Now().UTC().Truncate(time.Second)
	caExpiry := now.Add(48 * time.Hour).Format(time.RFC3339)
	root := testca.NewEntity(
		testca.Authority,
		testca.Subject(pkix.Name{CommonName: "[TEST] root"}),
		testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign),
		testca.NotAfter(now.Add(10*365*24*time.Hour)),
	)
	// the issuing CA expires in 2 days
	issuing := root.Issue(
		testca.Authority,
		testca.Subject(pkix.Name{CommonName: "[TEST] issuing"}),
		testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature),
		testca.NotAfter(now.Add(48*time.Hour)),
	)
	ca := testauthority.FromEntities(t, root, issuing)
	f := newFixture(t, ca, exampleIssuer())
	f.clock.SetTime(now)

	res, ci := f.reconcile(t, issuerName)
	ready := meta.FindStatusCondition(ci.Status.Conditions, v1alpha1.ConditionReady)
	assert.Equal(t, v1alpha1.ReasonLoaded, ready.Reason)
	assert.Equal(t, time.Hour, res.RequeueAfter)
	drain(f.recorder.Events)

	// 23h before expiry, within the 24h maxDuration: Ready stays True
	f.clock.SetTime(now.Add(25 * time.Hour))
	res, ci = f.reconcile(t, issuerName)
	ready = meta.FindStatusCondition(ci.Status.Conditions, v1alpha1.ConditionReady)
	assert.Equal(t, metav1.ConditionTrue, ready.Status)
	assert.Equal(t, v1alpha1.ReasonCAExpiring, ready.Reason)
	assert.Equal(t, `issuing certificate of "kubeca.svc" expires at `+caExpiry+`, within the maximum lifetime 24h0m0s; issued certificates are clipped`, ready.Message)
	assert.Equal(t, time.Hour, res.RequeueAfter)
	assert.Equal(t, []string{"Warning CAExpiring " + ready.Message}, drain(f.recorder.Events))

	// 30 minutes before expiry: requeue at the expiry
	f.clock.SetTime(now.Add(48*time.Hour - 30*time.Minute))
	res, _ = f.reconcile(t, issuerName)
	assert.Equal(t, 30*time.Minute, res.RequeueAfter)

	// expired
	f.clock.SetTime(now.Add(48 * time.Hour))
	res, ci = f.reconcile(t, issuerName)
	ready = meta.FindStatusCondition(ci.Status.Conditions, v1alpha1.ConditionReady)
	assert.Equal(t, metav1.ConditionFalse, ready.Status)
	assert.Equal(t, v1alpha1.ReasonCAExpired, ready.Reason)
	assert.Equal(t, `issuing certificate of "kubeca.svc" expired at `+caExpiry, ready.Message)
	assert.Equal(t, ctrl.Result{}, res)

	// a maxDuration above every profile expiry does not move the warning:
	// no certificate outlives its 24h profile
	long := exampleIssuer()
	long.Spec.Policy.MaxDuration = &metav1.Duration{Duration: 72 * time.Hour}
	f = newFixture(t, ca, long)
	f.clock.SetTime(now)
	_, ci = f.reconcile(t, issuerName)
	assert.Equal(t, v1alpha1.ReasonLoaded, meta.FindStatusCondition(ci.Status.Conditions, v1alpha1.ConditionReady).Reason, "48h left, 24h profiles")
	f.clock.SetTime(now.Add(25 * time.Hour))
	_, ci = f.reconcile(t, issuerName)
	ready = meta.FindStatusCondition(ci.Status.Conditions, v1alpha1.ConditionReady)
	assert.Equal(t, v1alpha1.ReasonCAExpiring, ready.Reason)
	assert.Contains(t, ready.Message, "within the maximum lifetime 24h0m0s")
}

func TestReconcileCABundle(t *testing.T) {
	ca := testauthority.New(t)
	ci := exampleIssuer()
	ci.UID = "uid-kubeca"
	ci.Spec.CABundle = &v1alpha1.CABundleSpec{ConfigMapName: "kubeca-ca"}
	certs := []client.Object{
		&v1alpha1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "shop"},
			Spec:       v1alpha1.CertificateSpec{IssuerRef: v1alpha1.IssuerReference{Name: issuerName}},
		},
		&v1alpha1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "shop"},
			Spec:       v1alpha1.CertificateSpec{IssuerRef: v1alpha1.IssuerReference{Name: issuerName}},
		},
		&v1alpha1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: "ops"},
			Spec:       v1alpha1.CertificateSpec{IssuerRef: v1alpha1.IssuerReference{Name: issuerName}},
		},
		&v1alpha1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: "d", Namespace: "other"},
			Spec:       v1alpha1.CertificateSpec{IssuerRef: v1alpha1.IssuerReference{Name: "another-issuer"}},
		},
	}
	f := newFixture(t, ca, append(certs, ci)...)
	_, got := f.reconcile(t, issuerName)
	require.True(t, meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionReady))

	var list corev1.ConfigMapList
	require.NoError(t, f.client.List(context.Background(), &list))
	require.Len(t, list.Items, 2)
	for _, cm := range list.Items {
		assert.Equal(t, "kubeca-ca", cm.Name)
		assert.Contains(t, []string{"shop", "ops"}, cm.Namespace)
		assert.Equal(t, map[string]string{"ca.crt": ca.RootPEM()}, cm.Data)
		assert.Equal(t, v1alpha1.TrueValue, cm.Labels[v1alpha1.LabelManaged])
		assert.Equal(t, issuerName, cm.Annotations[v1alpha1.AnnotationIssuer])
		owner := metav1.GetControllerOf(&cm)
		require.NotNil(t, owner)
		assert.Equal(t, v1alpha1.KindClusterIssuer, owner.Kind)
		assert.Equal(t, issuerName, owner.Name)
	}

	// a ConfigMap of that name that is not ours is left alone and reported
	foreign := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "kubeca-ca", Namespace: "other"}, Data: map[string]string{"x": "y"}}
	require.NoError(t, f.client.Create(context.Background(), foreign))
	require.NoError(t, f.client.Create(context.Background(), &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "e", Namespace: "other"},
		Spec:       v1alpha1.CertificateSpec{IssuerRef: v1alpha1.IssuerReference{Name: issuerName}},
	}))
	drain(f.recorder.Events)
	f.reconcile(t, issuerName)
	require.NoError(t, f.client.Get(context.Background(), client.ObjectKey{Namespace: "other", Name: "kubeca-ca"}, foreign))
	assert.Equal(t, map[string]string{"x": "y"}, foreign.Data)
	assert.Equal(t, []string{"Warning ConfigMapConflict ConfigMap other/kubeca-ca exists and is not managed by kubeca; delete it or change spec.caBundle.configMapName"}, drain(f.recorder.Events))

	// one controlled by another ClusterIssuer publishing into the same name
	// is a conflict too, not a retry: it carries the managed label as well
	taken := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubeca-ca",
			Namespace: "taken",
			Labels:    map[string]string{v1alpha1.LabelManaged: v1alpha1.TrueValue},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: v1alpha1.GroupVersion.String(),
				Kind:       v1alpha1.KindClusterIssuer,
				Name:       "another-issuer",
				UID:        "uid-another",
				Controller: ptr(true),
			}},
		},
		Data: map[string]string{"ca.crt": "another root"},
	}
	require.NoError(t, f.client.Create(context.Background(), taken))
	require.NoError(t, f.client.Create(context.Background(), &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "f", Namespace: "taken"},
		Spec:       v1alpha1.CertificateSpec{IssuerRef: v1alpha1.IssuerReference{Name: issuerName}},
	}))
	drain(f.recorder.Events)
	f.reconcile(t, issuerName) // no error: not retried
	require.NoError(t, f.client.Get(context.Background(), client.ObjectKeyFromObject(taken), taken))
	assert.Equal(t, map[string]string{"ca.crt": "another root"}, taken.Data)
	assert.Equal(t, "another-issuer", metav1.GetControllerOf(taken).Name)
	assert.Equal(t, []string{
		"Warning ConfigMapConflict ConfigMap other/kubeca-ca exists and is not managed by kubeca; delete it or change spec.caBundle.configMapName",
		`Warning ConfigMapConflict ConfigMap taken/kubeca-ca is controlled by ClusterIssuer "another-issuer"; use another spec.caBundle.configMapName`,
	}, drain(f.recorder.Events))

	// a stale controller reference of a deleted ClusterIssuer of this name
	// is replaced
	stale := taken.DeepCopy()
	stale.Namespace, stale.ResourceVersion = "stale", ""
	stale.OwnerReferences[0].Name, stale.OwnerReferences[0].UID = issuerName, "uid-deleted"
	require.NoError(t, f.client.Create(context.Background(), stale))
	require.NoError(t, f.client.Create(context.Background(), &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "g", Namespace: "stale"},
		Spec:       v1alpha1.CertificateSpec{IssuerRef: v1alpha1.IssuerReference{Name: issuerName}},
	}))
	f.reconcile(t, issuerName)
	require.NoError(t, f.client.Get(context.Background(), client.ObjectKeyFromObject(stale), stale))
	assert.Equal(t, ca.RootPEM(), stale.Data["ca.crt"])
	assert.Equal(t, types.UID("uid-kubeca"), metav1.GetControllerOf(stale).UID)
	drain(f.recorder.Events)

	// the ConfigMap is restored when edited
	var cm corev1.ConfigMap
	require.NoError(t, f.client.Get(context.Background(), client.ObjectKey{Namespace: "shop", Name: "kubeca-ca"}, &cm))
	cm.Data["ca.crt"] = "garbage"
	require.NoError(t, f.client.Update(context.Background(), &cm))
	f.reconcile(t, issuerName)
	require.NoError(t, f.client.Get(context.Background(), client.ObjectKey{Namespace: "shop", Name: "kubeca-ca"}, &cm))
	assert.Equal(t, ca.RootPEM(), cm.Data["ca.crt"])

	// pruning: the bundles this issuer controls follow the namespaces that
	// hold one of its Certificates, its configMapName and spec.caBundle;
	// others' ConfigMaps are never touched
	bundles := func() []string {
		t.Helper()
		var list corev1.ConfigMapList
		require.NoError(t, f.client.List(context.Background(), &list))
		var names []string
		for _, cm := range list.Items {
			names = append(names, cm.Namespace+"/"+cm.Name)
		}
		slices.Sort(names)
		return names
	}
	var certC v1alpha1.Certificate
	require.NoError(t, f.client.Get(context.Background(), client.ObjectKey{Namespace: "ops", Name: "c"}, &certC))
	require.NoError(t, f.client.Delete(context.Background(), &certC))
	f.reconcile(t, issuerName)
	assert.Equal(t, []string{"other/kubeca-ca", "shop/kubeca-ca", "stale/kubeca-ca", "taken/kubeca-ca"}, bundles(), "ops has no Certificate left")

	require.NoError(t, f.client.Get(context.Background(), client.ObjectKey{Name: issuerName}, got))
	got.Spec.CABundle.ConfigMapName = "kubeca-root"
	require.NoError(t, f.client.Update(context.Background(), got))
	f.reconcile(t, issuerName)
	assert.Equal(t, []string{"other/kubeca-ca", "other/kubeca-root", "shop/kubeca-root", "stale/kubeca-root", "taken/kubeca-ca", "taken/kubeca-root"}, bundles(), "renamed")

	require.NoError(t, f.client.Get(context.Background(), client.ObjectKey{Name: issuerName}, got))
	got.Spec.CABundle = nil
	require.NoError(t, f.client.Update(context.Background(), got))
	f.reconcile(t, issuerName)
	assert.Equal(t, []string{"other/kubeca-ca", "taken/kubeca-ca"}, bundles(), "disabled: only others' ConfigMaps remain")
	drain(f.recorder.Events)
}

func TestReconcileMissing(t *testing.T) {
	ca := testauthority.New(t)
	f := newFixture(t, ca)
	res, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "nope"}})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, res)
}

func TestBackdateAndRootPEM(t *testing.T) {
	ca := testauthority.New(t)
	xi, err := ca.GetIssuerByLabel(testauthority.IssuerLabel)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, issuer.Backdate(xi.Profile(testauthority.ProfilePeer)))
	assert.Equal(t, ca.RootPEM(), issuer.RootPEM(ca.Authority, xi))
}
