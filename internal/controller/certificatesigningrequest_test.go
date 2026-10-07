package controller_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/url"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/kubeca/internal/controller"
	"github.com/effective-security/kubeca/internal/testauthority"
	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	capi "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	csrName   = "web-abc12"
	namespace = "shop"
	username  = "system:serviceaccount:shop:web"
)

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
	r        *controller.CertificateSigningRequestSigningReconciler
}

func newFixture(t *testing.T, ca *testauthority.CA, mode controller.ApproveMode, objs ...client.Object) *fixture {
	t.Helper()
	return newFixtureWithBuilder(t, ca, mode, fake.NewClientBuilder().WithObjects(objs...))
}

func newFixtureWithBuilder(t *testing.T, ca *testauthority.CA, mode controller.ApproveMode, b *fake.ClientBuilder) *fixture {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, capi.AddToScheme(s))
	c := b.WithScheme(s).
		WithStatusSubresource(&capi.CertificateSigningRequest{}).
		WithIndex(&corev1.Pod{}, "spec.serviceAccountName", func(o client.Object) []string {
			return []string{o.(*corev1.Pod).Spec.ServiceAccountName}
		}).
		Build()
	recorder := record.NewFakeRecorder(20)
	return &fixture{
		ca:       ca,
		client:   c,
		recorder: recorder,
		r: &controller.CertificateSigningRequestSigningReconciler{
			Client:        c,
			APIReader:     c,
			Scheme:        s,
			Authority:     ca.Authority,
			EventRecorder: recorder,
			ApproveMode:   mode,
			AllowedNames:  []string{"localhost", "127.0.0.1", "spiffe://example.org/ns/shop/sa/Admin"},
			ClusterDomain: "cluster.local",
		},
	}
}

func (f *fixture) reconcile(t *testing.T, name string) (ctrl.Result, error, *capi.CertificateSigningRequest) {
	t.Helper()
	res, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}})
	var csr capi.CertificateSigningRequest
	if gerr := f.client.Get(context.Background(), client.ObjectKey{Name: name}, &csr); gerr != nil {
		return res, err, nil
	}
	return res, err, &csr
}

// csrPEM builds a CSR with the names.
func csrPEM(t *testing.T, commonName string, names ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	for _, name := range names {
		switch {
		case net.ParseIP(name) != nil:
			template.IPAddresses = append(template.IPAddresses, net.ParseIP(name))
		case len(name) > 0 && (name[0:1] == "s" && len(name) > 8 && name[:9] == "spiffe://"):
			u, err := url.Parse(name)
			require.NoError(t, err)
			template.URIs = append(template.URIs, u)
		default:
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func newCSR(t *testing.T, signer string, names ...string) *capi.CertificateSigningRequest {
	t.Helper()
	return &capi.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: csrName},
		Spec: capi.CertificateSigningRequestSpec{
			Request:    csrPEM(t, "", names...),
			SignerName: signer,
			Username:   username,
			Usages:     []capi.KeyUsage{capi.UsageDigitalSignature, capi.UsageServerAuth},
		},
	}
}

// webPods are the Pods of the requesting ServiceAccount and a Service
// selecting them.
func webPods() []client.Object {
	return []client.Object{
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: namespace, Labels: map[string]string{"app": "web"}},
			Spec:       corev1.PodSpec{ServiceAccountName: "web"},
			Status:     corev1.PodStatus{PodIP: "10.1.2.3"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "other-1", Namespace: namespace, Labels: map[string]string{"app": "other"}},
			Spec:       corev1.PodSpec{ServiceAccountName: "other"},
			Status:     corev1.PodStatus{PodIP: "10.1.2.9"},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: namespace},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "web"}, ClusterIP: "10.96.0.7"},
		},
	}
}

func allowedNames() []string {
	return []string{
		"10-1-2-3.shop.pod.cluster.local", "web.shop.svc.cluster.local", "web.shop.svc",
		"10.1.2.3", "10.96.0.7", "localhost", "127.0.0.1", "spiffe://example.org/ns/shop/sa/web",
	}
}

func TestSignOff(t *testing.T) {
	ca := testauthority.New(t)
	f := newFixture(t, ca, controller.ApproveOff, newCSR(t, "kubeca.svc/"+testauthority.ProfileServer, "web.shop.svc", "10.1.2.3"))

	res, err, csr := f.reconcile(t, csrName)
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, res)
	require.NotEmpty(t, csr.Status.Certificate)
	chain, err := certutil.ParseChainFromPEM(csr.Status.Certificate)
	require.NoError(t, err)
	require.Len(t, chain, 2, "leaf and issuing certificate")
	assert.Equal(t, []string{"web.shop.svc"}, chain[0].DNSNames)
	assert.Equal(t, "10.1.2.3", chain[0].IPAddresses[0].String())
	assert.Equal(t, ca.Issuer.Certificate.Raw, chain[1].Raw)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, chain[0].ExtKeyUsage, "profile usages, not spec.usages")
	assert.Empty(t, csr.Status.Conditions, "no Approved condition with -approve=off")
	assert.Equal(t, []string{"Normal Signed The CSR has been signed"}, drain(f.recorder.Events))

	// already signed: nothing happens
	_, err, csr = f.reconcile(t, csrName)
	require.NoError(t, err)
	assert.Empty(t, drain(f.recorder.Events))
}

func TestSkips(t *testing.T) {
	ca := testauthority.New(t)
	denied := newCSR(t, "kubeca.svc/peer-24h", "web.shop.svc")
	denied.Status.Conditions = []capi.CertificateSigningRequestCondition{{Type: capi.CertificateDenied, Status: corev1.ConditionTrue}}
	failed := newCSR(t, "kubeca.svc/peer-24h", "web.shop.svc")
	failed.Status.Conditions = []capi.CertificateSigningRequestCondition{{Type: capi.CertificateFailed, Status: corev1.ConditionTrue}}
	noSigner := newCSR(t, "", "web.shop.svc")
	for name, csr := range map[string]*capi.CertificateSigningRequest{
		"denied":          denied,
		"failed":          failed,
		"no signer":       noSigner,
		"unknown label":   newCSR(t, "other.svc/peer-24h", "web.shop.svc"),
		"unknown profile": newCSR(t, "kubeca.svc/nope", "web.shop.svc"),
		"bad signer":      newCSR(t, "kubeca.svc/peer-24h/x", "web.shop.svc"),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, ca, controller.ApproveOff, csr)
			res, err, got := f.reconcile(t, csrName)
			require.NoError(t, err)
			assert.Equal(t, ctrl.Result{}, res)
			assert.Empty(t, got.Status.Certificate)
			assert.Empty(t, drain(f.recorder.Events))
		})
	}
	t.Run("missing", func(t *testing.T) {
		f := newFixture(t, ca, controller.ApproveOff)
		res, err, got := f.reconcile(t, csrName)
		require.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, res)
		assert.Nil(t, got)
	})
}

// TestSignFailed covers KUBECA-013: a request the profile rejects gets the
// Failed condition and is not retried.
func TestSignFailed(t *testing.T) {
	ca := testauthority.New(t)
	// client-24h copies URIs only and pins the trust domain
	f := newFixture(t, ca, controller.ApproveOff, newCSR(t, "kubeca.svc/"+testauthority.ProfileClient, "spiffe://other.org/ns/shop/sa/web"))

	res, err, csr := f.reconcile(t, csrName)
	require.NoError(t, err, "permanent: not retried")
	assert.Equal(t, ctrl.Result{}, res)
	assert.Empty(t, csr.Status.Certificate)
	require.Len(t, csr.Status.Conditions, 1)
	cond := csr.Status.Conditions[0]
	assert.Equal(t, capi.CertificateFailed, cond.Type)
	assert.Equal(t, corev1.ConditionTrue, cond.Status)
	assert.Equal(t, "SigningFailed", cond.Reason)
	assert.Equal(t, "URI does not match allowed list: spiffe://other.org/ns/shop/sa/web", cond.Message)
	assert.Equal(t, []string{"Warning SigningFailed URI does not match allowed list: spiffe://other.org/ns/shop/sa/web"}, drain(f.recorder.Events))

	// garbage request: parse error, Failed as well
	bad := newCSR(t, "kubeca.svc/peer-24h")
	bad.Spec.Request = []byte("not a csr")
	f = newFixture(t, ca, controller.ApproveOff, bad)
	_, err, csr = f.reconcile(t, csrName)
	require.NoError(t, err)
	require.Len(t, csr.Status.Conditions, 1)
	assert.Equal(t, capi.CertificateFailed, csr.Status.Conditions[0].Type)
	assert.Contains(t, csr.Status.Conditions[0].Message, "failed to parse CSR")
}

func TestSignTransientError(t *testing.T) {
	ca := testauthority.New(t)
	b := fake.NewClientBuilder().
		WithObjects(newCSR(t, "kubeca.svc/peer-24h", "web.shop.svc")).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, c client.Client, subResourceName string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				return errors.New("etcdserver: request timed out")
			},
		})
	f := newFixtureWithBuilder(t, ca, controller.ApproveOff, b)
	_, err, csr := f.reconcile(t, csrName)
	require.Error(t, err)
	assert.Equal(t, "error patching CSR: etcdserver: request timed out", err.Error())
	assert.Empty(t, csr.Status.Certificate)
}

func TestApproveEnforce(t *testing.T) {
	ca := testauthority.New(t)
	csr := newCSR(t, "kubeca.svc/peer-24h", allowedNames()...)
	f := newFixture(t, ca, controller.ApproveEnforce, append(webPods(), csr)...)

	// first reconcile: approved, not signed yet
	_, err, got := f.reconcile(t, csrName)
	require.NoError(t, err)
	assert.Empty(t, got.Status.Certificate)
	require.Len(t, got.Status.Conditions, 1)
	cond := got.Status.Conditions[0]
	assert.Equal(t, capi.CertificateApproved, cond.Type)
	assert.Equal(t, corev1.ConditionTrue, cond.Status)
	assert.Equal(t, "KubeCAApproved", cond.Reason)
	assert.Equal(t, "names match the Pods and Services of "+username, cond.Message)
	assert.Equal(t, []string{"Normal Approved names match the Pods and Services of " + username}, drain(f.recorder.Events))

	// the approval update triggers the second reconcile, which signs
	_, err, got = f.reconcile(t, csrName)
	require.NoError(t, err)
	assert.NotEmpty(t, got.Status.Certificate)
	assert.Equal(t, []string{"Normal Signed The CSR has been signed"}, drain(f.recorder.Events))

	// a URI of -approve-allowed-names in its exact form is approved
	f = newFixture(t, ca, controller.ApproveEnforce, append(webPods(), newCSR(t, "kubeca.svc/peer-24h", "web.shop.svc", "spiffe://example.org/ns/shop/sa/Admin"))...)
	_, err, got = f.reconcile(t, csrName)
	require.NoError(t, err)
	require.Len(t, got.Status.Conditions, 1)
	assert.Equal(t, capi.CertificateApproved, got.Status.Conditions[0].Type)
}

func TestApproveDenied(t *testing.T) {
	ca := testauthority.New(t)
	tcases := []struct {
		name    string
		csr     *capi.CertificateSigningRequest
		message string
	}{
		{
			name:    "foreign names",
			csr:     newCSR(t, "kubeca.svc/peer-24h", "web.shop.svc", "api.shop.svc", "10.1.2.9", "spiffe://example.org/ns/shop/sa/other"),
			message: username + " may not have: DNS name api.shop.svc, IP address 10.1.2.9, URI spiffe://example.org/ns/shop/sa/other",
		},
		{
			name: "common name",
			csr: func() *capi.CertificateSigningRequest {
				c := newCSR(t, "kubeca.svc/peer-24h", "web.shop.svc")
				c.Spec.Request = csrPEM(t, "evil.example.org", "web.shop.svc")
				return c
			}(),
			message: username + " may not have: common name evil.example.org",
		},
		{
			// the decoded path of each is /ns/shop/sa/web, the identity is not
			name: "non-canonical SPIFFE IDs",
			csr: newCSR(t, "kubeca.svc/peer-24h", "web.shop.svc",
				"spiffe://example.org:443/ns/shop/sa/web", "spiffe://user@example.org/ns/shop/sa/web",
				"spiffe://example.org/ns/shop/sa/web?x=1", "spiffe://example.org/ns/shop/sa/web#f",
				"spiffe://example.org/ns/shop/sa/%77eb", "spiffe://Example.org/ns/shop/sa/web"),
			message: username + " may not have: URI spiffe://example.org:443/ns/shop/sa/web, URI spiffe://user@example.org/ns/shop/sa/web, " +
				"URI spiffe://example.org/ns/shop/sa/web?x=1, URI spiffe://example.org/ns/shop/sa/web#f, " +
				"URI spiffe://example.org/ns/shop/sa/%77eb, URI spiffe://Example.org/ns/shop/sa/web",
		},
		{
			// an allowed URI matches exactly; DNS names ignore the case
			name:    "URI in another case",
			csr:     newCSR(t, "kubeca.svc/peer-24h", "WEB.shop.svc", "spiffe://example.org/ns/shop/sa/admin"),
			message: username + " may not have: URI spiffe://example.org/ns/shop/sa/admin",
		},
		{
			name: "not a ServiceAccount",
			csr: func() *capi.CertificateSigningRequest {
				c := newCSR(t, "kubeca.svc/peer-24h", "web.shop.svc")
				c.Spec.Username = "kubernetes-admin"
				return c
			}(),
			message: `requester "kubernetes-admin" is not a ServiceAccount`,
		},
		{
			name: "garbage request",
			csr: func() *capi.CertificateSigningRequest {
				c := newCSR(t, "kubeca.svc/peer-24h")
				c.Spec.Request = []byte("junk")
				return c
			}(),
			message: "unable to parse the CSR: ",
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, ca, controller.ApproveEnforce, append(webPods(), tc.csr)...)
			_, err, got := f.reconcile(t, csrName)
			require.NoError(t, err)
			assert.Empty(t, got.Status.Certificate)
			require.Len(t, got.Status.Conditions, 1)
			cond := got.Status.Conditions[0]
			assert.Equal(t, capi.CertificateDenied, cond.Type)
			assert.Equal(t, corev1.ConditionTrue, cond.Status)
			assert.Equal(t, "NamesNotAllowed", cond.Reason)
			assert.Contains(t, cond.Message, tc.message)
			events := drain(f.recorder.Events)
			require.Len(t, events, 1)
			assert.Contains(t, events[0], "Warning Denied "+tc.message)

			// a denied CSR is never signed
			_, err, got = f.reconcile(t, csrName)
			require.NoError(t, err)
			assert.Empty(t, got.Status.Certificate)
			assert.Empty(t, drain(f.recorder.Events))
		})
	}
}

func TestApproveEnforceExternalApproval(t *testing.T) {
	ca := testauthority.New(t)
	// approved by kubectl certificate approve: signed without evaluation
	// (api.shop.svc is not a name of the requester's Pods)
	csr := newCSR(t, "kubeca.svc/peer-24h", "api.shop.svc")
	csr.Status.Conditions = []capi.CertificateSigningRequestCondition{{Type: capi.CertificateApproved, Status: corev1.ConditionTrue, Reason: "KubectlApprove"}}
	f := newFixture(t, ca, controller.ApproveEnforce, csr)
	_, err, got := f.reconcile(t, csrName)
	require.NoError(t, err)
	assert.NotEmpty(t, got.Status.Certificate)
	assert.Equal(t, []string{"Normal Signed The CSR has been signed"}, drain(f.recorder.Events))

	// only a True condition is a decision (the API server admits no other
	// status for Approved, Denied and Failed): Approved=Unknown is
	// evaluated, and the foreign name is denied, not signed
	for _, status := range []corev1.ConditionStatus{corev1.ConditionUnknown, corev1.ConditionFalse} {
		csr = newCSR(t, "kubeca.svc/peer-24h", "api.shop.svc")
		csr.Status.Conditions = []capi.CertificateSigningRequestCondition{{Type: capi.CertificateApproved, Status: status, Reason: "Other"}}
		f = newFixture(t, ca, controller.ApproveEnforce, append(webPods(), csr)...)
		_, err, got = f.reconcile(t, csrName)
		require.NoError(t, err)
		assert.Empty(t, got.Status.Certificate, status)
		require.Len(t, got.Status.Conditions, 2, status)
		assert.Equal(t, capi.CertificateDenied, got.Status.Conditions[1].Type, status)
		assert.Equal(t, corev1.ConditionTrue, got.Status.Conditions[1].Status, status)
	}
}

func TestApproveAudit(t *testing.T) {
	ca := testauthority.New(t)
	// would be denied: logged and signed
	csr := newCSR(t, "kubeca.svc/peer-24h", "web.shop.svc", "api.shop.svc")
	f := newFixture(t, ca, controller.ApproveAudit, append(webPods(), csr)...)
	_, err, got := f.reconcile(t, csrName)
	require.NoError(t, err)
	assert.NotEmpty(t, got.Status.Certificate)
	assert.Empty(t, got.Status.Conditions)
	assert.Equal(t, []string{
		"Warning ApprovalAudit would be denied with -approve=enforce: " + username + " may not have: DNS name api.shop.svc",
		"Normal Signed The CSR has been signed",
	}, drain(f.recorder.Events))

	// allowed names: no audit event
	csr = newCSR(t, "kubeca.svc/peer-24h", allowedNames()...)
	f = newFixture(t, ca, controller.ApproveAudit, append(webPods(), csr)...)
	_, err, got = f.reconcile(t, csrName)
	require.NoError(t, err)
	assert.NotEmpty(t, got.Status.Certificate)
	assert.Equal(t, []string{"Normal Signed The CSR has been signed"}, drain(f.recorder.Events))
}

func TestApproveListError(t *testing.T) {
	ca := testauthority.New(t)
	b := fake.NewClientBuilder().
		WithObjects(newCSR(t, "kubeca.svc/peer-24h", "web.shop.svc")).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*corev1.PodList); ok {
					return errors.New("etcdserver: request timed out")
				}
				return c.List(ctx, list, opts...)
			},
		})
	f := newFixtureWithBuilder(t, ca, controller.ApproveEnforce, b)
	_, err, got := f.reconcile(t, csrName)
	require.Error(t, err)
	assert.Equal(t, "unable to list the Pods of "+username+": etcdserver: request timed out", err.Error())
	assert.Empty(t, got.Status.Conditions)
}

func TestParseApproveMode(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"off", "audit", "enforce"} {
		mode, err := controller.ParseApproveMode(s)
		require.NoError(t, err)
		assert.Equal(t, controller.ApproveMode(s), mode)
	}
	_, err := controller.ParseApproveMode("yes")
	require.Error(t, err)
	assert.Equal(t, `invalid approve mode "yes": use off, audit or enforce`, err.Error())
}

func TestLoadAuthority(t *testing.T) {
	t.Parallel()
	_, err := controller.LoadAuthority("missing.yaml", "missing.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to load HSM config missing.yaml")
}
