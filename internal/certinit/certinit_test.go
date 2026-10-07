package certinit_test

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/effective-security/kubeca/internal/certinit"
	"github.com/effective-security/xpki/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	capi "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

const (
	testNamespace = "test"
	testPodName   = "pod-1"
	testPodIP     = "10.1.2.3"
	testSigner    = "kubeca.svc/peer"
)

func TestCreateFail(t *testing.T) {
	tcases := []struct {
		r   *certinit.Request
		err string
	}{
		{
			r:   &certinit.Request{},
			err: "missing required namespace parameter",
		},
		{
			r:   &certinit.Request{Namespace: "ns"},
			err: "missing required pod name parameter",
		},
		{
			r:   &certinit.Request{Namespace: "ns", PodName: "podname"},
			err: "missing required signer name parameter",
		},
	}

	for _, tc := range tcases {
		err := tc.r.Create(context.Background(), nil)
		require.Error(t, err)
		assert.Equal(t, tc.err, err.Error())
	}
}

// TestCreate drives the full init-container flow against mocked Kubernetes
// clients: names discovered with -query-k8s, -service-names and explicit
// -san values are validated and deduplicated by xpki (XPKI-059) before the
// CSR is created, and the key, CSR and certificate land in CertDir.
func TestCreate(t *testing.T) {
	missingDir := filepath.Join(t.TempDir(), "missing")
	r := &certinit.Request{
		Namespace:     testNamespace,
		PodName:       testPodName,
		CertDir:       missingDir,
		ClusterDomain: "cluster.local",
		Labels:        "key=value,novalue,=empty, spaced = v ,bad=a=b",
		QueryK8s:      true,
		// test.com is repeated on purpose: duplicates are dropped.
		SAN: "email@test.com,test.com,127.0.0.1,spiffe://test/service, test.com",
		// service1 also selects the Pod: the names it adds are duplicates.
		ServiceNames:       "svc-extra, service1",
		IncludeUnqualified: true,
		SignerName:         testSigner,
	}

	p := mockedPods{}
	s := mockedServices{}
	mocked := &certinit.CertClient{
		Pods:     &p,
		Services: &s,
	}

	pod := &v1.Pod{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      testPodName,
			Namespace: testNamespace,
			Labels: map[string]string{
				"app": "svc1",
			},
		},
		Spec: v1.PodSpec{
			Hostname:  "pod1",
			Subdomain: "headless",
		},
		Status: v1.PodStatus{
			PodIP: testPodIP,
		},
	}
	p.On("Get", mock.Anything, testPodName, mock.Anything).Return(pod, nil)

	list := v1.ServiceList{
		Items: []v1.Service{
			{
				// selects the pod: service DNS names, ClusterIP and external IPs are added
				ObjectMeta: metaV1.ObjectMeta{Name: "service1", Namespace: testNamespace},
				Spec: v1.ServiceSpec{
					Selector: map[string]string{
						"app": "svc1",
					},
					ClusterIP:   "10.0.0.1",
					ExternalIPs: []string{"192.0.2.10"},
				},
			},
			{
				// headless and selecting the pod: DNS names only, no "None" (KUBECA-007)
				ObjectMeta: metaV1.ObjectMeta{Name: "headless", Namespace: testNamespace},
				Spec: v1.ServiceSpec{
					Selector: map[string]string{
						"app": "svc1",
					},
					ClusterIP: v1.ClusterIPNone,
				},
			},
			{
				// selector does not match the pod: ignored
				ObjectMeta: metaV1.ObjectMeta{Name: "other", Namespace: testNamespace},
				Spec: v1.ServiceSpec{
					Selector: map[string]string{
						"app": "other",
					},
					ClusterIP: "10.0.0.2",
				},
			},
			{
				// no selector: ignored
				ObjectMeta: metaV1.ObjectMeta{Name: "external", Namespace: testNamespace},
				Spec:       v1.ServiceSpec{ClusterIP: "10.0.0.3"},
			},
		},
	}
	s.On("List", mock.Anything, mock.Anything).Return(&list, nil)

	// the key is written before any CSR call, so a missing CertDir fails
	// without touching the certificates mock
	untouched := mockedCertificates{}
	mocked.Certificates = &untouched
	err := r.Create(context.Background(), mocked)
	require.Error(t, err)
	assert.Equal(t, "unable to save key: open "+filepath.Join(missingDir, "tls.key")+": no such file or directory", err.Error())
	untouched.AssertNotCalled(t, "Get", mock.Anything, mock.Anything, mock.Anything)
	untouched.AssertNotCalled(t, "Create", mock.Anything, mock.Anything, mock.Anything)

	r.CertDir = t.TempDir()
	c, created := issuingCertificates()
	mocked.Certificates = c
	err = r.Create(context.Background(), mocked)
	require.NoError(t, err)
	c.AssertExpectations(t)

	require.NotNil(t, *created)
	assert.Equal(t, testSigner, (*created).Spec.SignerName)
	assert.Equal(t, map[string]string{
		"key":    "value",
		"spaced": "v",
	}, (*created).Labels)
	assert.Nil(t, (*created).Spec.Extra, "KUBECA-005: Extra is set by the API server")
	assert.Equal(t, []capi.KeyUsage{
		capi.UsageDigitalSignature,
		capi.UsageKeyEncipherment,
		capi.UsageServerAuth,
		capi.UsageClientAuth,
	}, (*created).Spec.Usages)
	assert.Regexp(t, "^pod-1-test-[0-9a-z]{5}$", (*created).Name)

	parsed, err := csr.ParsePEM((*created).Spec.Request)
	require.NoError(t, err)
	assert.Equal(t, []string{
		"10-1-2-3.test.pod.cluster.local",
		"pod1.headless.test.svc.cluster.local",
		"pod1.headless.test.svc",
		"service1.test.svc.cluster.local",
		"service1.test.svc",
		"headless.test.svc.cluster.local",
		"headless.test.svc",
		"svc-extra.test.svc.cluster.local",
		"svc-extra.test.svc",
		"test.com",
	}, parsed.DNSNames)
	assert.Equal(t, []net.IP{
		net.ParseIP("10.0.0.1").To4(),
		net.ParseIP("192.0.2.10").To4(),
		net.ParseIP("127.0.0.1").To4(),
	}, parsed.IPAddresses)
	assert.Equal(t, []string{"email@test.com"}, parsed.EmailAddresses)
	require.Len(t, parsed.URIs, 1)
	assert.Equal(t, &url.URL{Scheme: "spiffe", Host: "test", Path: "/service"}, parsed.URIs[0])

	for _, name := range []string{"tls.key", "tls.csr", "tls.crt"} {
		_, err := os.Stat(filepath.Join(r.CertDir, name))
		require.NoError(t, err, name)
	}
	crt, err := os.ReadFile(filepath.Join(r.CertDir, "tls.crt"))
	require.NoError(t, err)
	assert.Equal(t, "cert", string(crt))

	r.SignerName = "kubeca.svc/unsupported"
	err = r.Create(context.Background(), mocked)
	require.Error(t, err)
	assert.Equal(t, "unsupported profile: kubeca.svc/unsupported; set usages for a profile other than peer, server or client", err.Error())

	r.SignerName = "nosigner"
	err = r.Create(context.Background(), mocked)
	require.Error(t, err)
	assert.Equal(t, "unsupported signer: nosigner", err.Error())
}

// TestCreatePodIPv6 checks the Pod DNS name of an IPv6 Pod: colons become
// dashes, as CoreDNS expects, instead of a name xpki v1.0 rejects.
func TestCreatePodIPv6(t *testing.T) {
	r := &certinit.Request{
		Namespace:     testNamespace,
		PodName:       testPodName,
		CertDir:       t.TempDir(),
		ClusterDomain: "cluster.local",
		QueryK8s:      true,
		SignerName:    testSigner,
	}
	p := mockedPods{}
	s := mockedServices{}
	p.On("Get", mock.Anything, testPodName, mock.Anything).Return(&v1.Pod{
		ObjectMeta: metaV1.ObjectMeta{Name: testPodName, Namespace: testNamespace},
		Status:     v1.PodStatus{PodIP: "fd00::1"},
	}, nil)
	s.On("List", mock.Anything, mock.Anything).Return(&v1.ServiceList{}, nil)
	c, created := issuingCertificates()

	err := r.Create(context.Background(), &certinit.CertClient{Pods: &p, Services: &s, Certificates: c})
	require.NoError(t, err)
	parsed, err := csr.ParsePEM((*created).Spec.Request)
	require.NoError(t, err)
	assert.Equal(t, []string{"fd00--1.test.pod.cluster.local"}, parsed.DNSNames)
	assert.Empty(t, parsed.IPAddresses)
}

// TestCreatePodWithoutIP checks that a Pod whose status has no IP yet gets
// no Pod DNS name (an empty label would fail the request) and still carries
// the explicit names.
func TestCreatePodWithoutIP(t *testing.T) {
	r := &certinit.Request{
		Namespace:     testNamespace,
		PodName:       testPodName,
		CertDir:       t.TempDir(),
		ClusterDomain: "cluster.local",
		QueryK8s:      true,
		SAN:           "svc.test.svc.cluster.local",
		SignerName:    testSigner,
	}
	p := mockedPods{}
	s := mockedServices{}
	p.On("Get", mock.Anything, testPodName, mock.Anything).Return(&v1.Pod{
		ObjectMeta: metaV1.ObjectMeta{Name: testPodName, Namespace: testNamespace},
	}, nil)
	s.On("List", mock.Anything, mock.Anything).Return(&v1.ServiceList{}, nil)
	c, created := issuingCertificates()

	err := r.Create(context.Background(), &certinit.CertClient{Pods: &p, Services: &s, Certificates: c})
	require.NoError(t, err)
	parsed, err := csr.ParsePEM((*created).Spec.Request)
	require.NoError(t, err)
	assert.Equal(t, []string{"svc.test.svc.cluster.local"}, parsed.DNSNames)
}

// TestCreateUsages checks that Usages lets a profile outside the built-in
// table be requested (KUBECA-008) and overrides the table otherwise.
func TestCreateUsages(t *testing.T) {
	r := &certinit.Request{
		Namespace:  testNamespace,
		PodName:    testPodName,
		CertDir:    t.TempDir(),
		SAN:        "svc.test.svc.cluster.local",
		SignerName: "kubeca.svc/custom",
		Usages:     "digital signature, client auth",
	}
	c, created := issuingCertificates()
	mocked := &certinit.CertClient{Certificates: c}

	err := r.Create(context.Background(), mocked)
	require.NoError(t, err)
	c.AssertExpectations(t)
	assert.Equal(t, []capi.KeyUsage{
		capi.UsageDigitalSignature,
		capi.UsageClientAuth,
	}, (*created).Spec.Usages)

	r.Usages = " , "
	err = r.Create(context.Background(), mocked)
	require.Error(t, err)
	assert.Equal(t, "invalid usages:  , ", err.Error())
}

// TestCreateDeniedCSR checks that a Denied condition stops the wait.
func TestCreateDeniedCSR(t *testing.T) {
	r := &certinit.Request{
		Namespace:  testNamespace,
		PodName:    testPodName,
		CertDir:    t.TempDir(),
		SAN:        "svc.test.svc.cluster.local",
		SignerName: "kubeca.svc/server",
	}

	c := mockedCertificates{}
	mocked := &certinit.CertClient{Certificates: &c}

	denied := capi.CertificateSigningRequest{
		Status: capi.CertificateSigningRequestStatus{
			Conditions: []capi.CertificateSigningRequestCondition{
				{
					Type:    capi.CertificateDenied,
					Reason:  "Policy",
					Message: "name not allowed",
				},
			},
		},
	}
	c.On("Get", mock.Anything, mock.Anything, mock.Anything).Once().Return(&capi.CertificateSigningRequest{}, nil)
	c.On("Get", mock.Anything, mock.Anything, mock.Anything).Once().Return(&denied, nil)

	err := r.Create(context.Background(), mocked)
	require.Error(t, err)
	assert.Regexp(t, `^certificate signing request \(pod-1-test-[0-9a-z]{5}\) denied for "Policy": "name not allowed"$`, err.Error())
	c.AssertExpectations(t)
}

// TestCreateFailedCSR checks that a Failed condition set by the signer stops
// the wait (KUBECA-006).
func TestCreateFailedCSR(t *testing.T) {
	r := &certinit.Request{
		Namespace:  testNamespace,
		PodName:    testPodName,
		CertDir:    t.TempDir(),
		SAN:        "svc.test.svc.cluster.local",
		SignerName: "kubeca.svc/server",
	}

	c := mockedCertificates{}
	mocked := &certinit.CertClient{Certificates: &c}

	failed := capi.CertificateSigningRequest{
		Status: capi.CertificateSigningRequestStatus{
			Conditions: []capi.CertificateSigningRequestCondition{
				{
					Type:    capi.CertificateFailed,
					Reason:  "SigningFailed",
					Message: "invalid SAN",
				},
			},
		},
	}
	c.On("Get", mock.Anything, mock.Anything, mock.Anything).Once().Return(&capi.CertificateSigningRequest{}, nil)
	c.On("Get", mock.Anything, mock.Anything, mock.Anything).Once().Return(&failed, nil)

	err := r.Create(context.Background(), mocked)
	require.Error(t, err)
	assert.Regexp(t, `^certificate signing request \(pod-1-test-[0-9a-z]{5}\) failed for "SigningFailed": "invalid SAN"$`, err.Error())
	c.AssertExpectations(t)
}

// TestCreateDeletedCSR checks that a CSR deleted while waiting is an error
// instead of an endless poll.
func TestCreateDeletedCSR(t *testing.T) {
	r := &certinit.Request{
		Namespace:  testNamespace,
		PodName:    testPodName,
		CertDir:    t.TempDir(),
		SAN:        "svc.test.svc.cluster.local",
		SignerName: "kubeca.svc/client",
	}

	c := mockedCertificates{}
	mocked := &certinit.CertClient{Certificates: &c}
	notFound := apierrors.NewNotFound(capi.Resource("certificatesigningrequests"), testPodName)

	c.On("Get", mock.Anything, mock.Anything, mock.Anything).Once().Return(&capi.CertificateSigningRequest{}, nil)
	c.On("Get", mock.Anything, mock.Anything, mock.Anything).Once().Return(nil, notFound)

	err := r.Create(context.Background(), mocked)
	require.Error(t, err)
	assert.Regexp(t, `^certificate signing request not found: pod-1-test-[0-9a-z]{5}$`, err.Error())
	c.AssertExpectations(t)
}

// TestCreateContextDone checks that the wait stops when the context ends
// (the -timeout flag), instead of polling for ever (KUBECA-006).
func TestCreateContextDone(t *testing.T) {
	r := &certinit.Request{
		Namespace:  testNamespace,
		PodName:    testPodName,
		CertDir:    t.TempDir(),
		SAN:        "svc.test.svc.cluster.local",
		SignerName: "kubeca.svc/client",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := mockedCertificates{}
	mocked := &certinit.CertClient{Certificates: &c}
	c.On("Get", mock.Anything, mock.Anything, mock.Anything).Once().Return(&capi.CertificateSigningRequest{}, nil)
	// still pending; the watch is unavailable and the context ends before
	// the next poll
	c.On("Get", mock.Anything, mock.Anything, mock.Anything).Once().
		Run(func(mock.Arguments) { cancel() }).
		Return(&capi.CertificateSigningRequest{}, nil)
	c.On("Watch", mock.Anything, mock.Anything).Once().Return(nil, errors.New("watch unavailable"))

	err := r.Create(ctx, mocked)
	require.Error(t, err)
	assert.Regexp(t, `^gave up waiting for certificate signing request pod-1-test-[0-9a-z]{5}: context canceled$`, err.Error())
	assert.ErrorIs(t, err, context.Canceled)
	c.AssertExpectations(t)
}

// TestCreateWatch covers the watch after the CSR is created (KUBECA-006):
// the certificate arrives as a Modified event, after a watch that ended
// without a decision (reopened after a second) and one that reported an
// error event (reopened after the five-second poll interval).
func TestCreateWatch(t *testing.T) {
	r := &certinit.Request{
		Namespace:  testNamespace,
		PodName:    testPodName,
		CertDir:    t.TempDir(),
		SAN:        "svc.test.svc.cluster.local",
		SignerName: "kubeca.svc/client",
	}
	c := mockedCertificates{}
	mocked := &certinit.CertClient{Certificates: &c}
	notFound := apierrors.NewNotFound(capi.Resource("certificatesigningrequests"), testPodName)
	pending := &capi.CertificateSigningRequest{ObjectMeta: metaV1.ObjectMeta{ResourceVersion: "7"}}
	c.On("Get", mock.Anything, mock.Anything, mock.Anything).Once().Return(nil, notFound)
	c.On("Create", mock.Anything, mock.Anything, mock.Anything).Once().Return(pending, nil)
	// pending on every read; the watches decide
	c.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(pending, nil)

	// 1: the watch ends without an event
	closed := watch.NewFake()
	closed.Stop()
	// 2: an error event, then nothing
	errored := watch.NewFake()
	// 3: a Modified event without the certificate, then the certificate
	issued := watch.NewFake()
	c.On("Watch", mock.Anything, mock.MatchedBy(func(opts metaV1.ListOptions) bool {
		return opts.ResourceVersion == "7" && opts.FieldSelector != ""
	})).Once().Return(closed, nil)
	c.On("Watch", mock.Anything, mock.Anything).Once().Run(func(mock.Arguments) {
		go errored.Error(&metaV1.Status{Message: "too old resource version"})
	}).Return(errored, nil)
	c.On("Watch", mock.Anything, mock.Anything).Once().Run(func(mock.Arguments) {
		go func() {
			issued.Modify(&capi.CertificateSigningRequest{})
			issued.Modify(&capi.CertificateSigningRequest{Status: capi.CertificateSigningRequestStatus{Certificate: []byte("cert")}})
		}()
	}).Return(issued, nil)

	started := time.Now()
	err := r.Create(context.Background(), mocked)
	require.NoError(t, err)
	// one second after the closed watch, five after the error event
	assert.GreaterOrEqual(t, time.Since(started), 6*time.Second)
	c.AssertExpectations(t)
	crt, err := os.ReadFile(filepath.Join(r.CertDir, "tls.crt"))
	require.NoError(t, err)
	assert.Equal(t, "cert", string(crt))
}

// TestCreateWatchDenied checks the Denied condition and the deletion seen
// through the watch.
func TestCreateWatchDenied(t *testing.T) {
	for name, tc := range map[string]struct {
		send func(*watch.FakeWatcher)
		err  string
	}{
		"denied": {
			send: func(w *watch.FakeWatcher) {
				w.Modify(&capi.CertificateSigningRequest{Status: capi.CertificateSigningRequestStatus{
					Conditions: []capi.CertificateSigningRequestCondition{{Type: capi.CertificateDenied, Reason: "NamesNotAllowed", Message: "api.test.svc"}},
				}})
			},
			err: `^certificate signing request \(pod-1-test-[0-9a-z]{5}\) denied for "NamesNotAllowed": "api.test.svc"$`,
		},
		"failed": {
			send: func(w *watch.FakeWatcher) {
				w.Modify(&capi.CertificateSigningRequest{Status: capi.CertificateSigningRequestStatus{
					Conditions: []capi.CertificateSigningRequestCondition{{Type: capi.CertificateFailed, Reason: "SigningFailed", Message: "invalid SAN"}},
				}})
			},
			err: `^certificate signing request \(pod-1-test-[0-9a-z]{5}\) failed for "SigningFailed": "invalid SAN"$`,
		},
		"deleted": {
			send: func(w *watch.FakeWatcher) { w.Delete(&capi.CertificateSigningRequest{}) },
			err:  `^certificate signing request not found: pod-1-test-[0-9a-z]{5}$`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := &certinit.Request{
				Namespace:  testNamespace,
				PodName:    testPodName,
				CertDir:    t.TempDir(),
				SAN:        "svc.test.svc.cluster.local",
				SignerName: "kubeca.svc/client",
			}
			c := mockedCertificates{}
			w := watch.NewFake()
			c.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&capi.CertificateSigningRequest{}, nil)
			c.On("Watch", mock.Anything, mock.Anything).Once().Run(func(mock.Arguments) { go tc.send(w) }).Return(w, nil)

			err := r.Create(context.Background(), &certinit.CertClient{Certificates: &c})
			require.Error(t, err)
			assert.Regexp(t, tc.err, err.Error())
			c.AssertExpectations(t)
		})
	}
}

// issuingCertificates returns a certificates mock that reports the CSR as
// missing, accepts its creation (captured into the returned pointer) and
// then returns it issued.
func issuingCertificates() (*mockedCertificates, **capi.CertificateSigningRequest) {
	c := &mockedCertificates{}
	created := new(*capi.CertificateSigningRequest)
	notFound := apierrors.NewNotFound(capi.Resource("certificatesigningrequests"), testPodName)
	issued := &capi.CertificateSigningRequest{
		Status: capi.CertificateSigningRequestStatus{
			Certificate: []byte("cert"),
		},
	}
	c.On("Get", mock.Anything, mock.Anything, mock.Anything).Once().Return(nil, notFound)
	c.On("Create", mock.Anything, mock.Anything, mock.Anything).Once().
		Run(func(args mock.Arguments) {
			*created = args.Get(1).(*capi.CertificateSigningRequest)
		}).
		Return(&capi.CertificateSigningRequest{}, nil)
	c.On("Get", mock.Anything, mock.Anything, mock.Anything).Once().Return(issued, nil)
	return c, created
}

type mockedPods struct {
	mock.Mock
}

func (m *mockedPods) Get(ctx context.Context, name string, opts metaV1.GetOptions) (*v1.Pod, error) {
	args := m.Called(ctx, name, opts)
	pod, _ := args.Get(0).(*v1.Pod)
	return pod, args.Error(1)
}

type mockedServices struct {
	mock.Mock
}

func (m *mockedServices) List(ctx context.Context, opts metaV1.ListOptions) (*v1.ServiceList, error) {
	args := m.Called(ctx, opts)
	list, _ := args.Get(0).(*v1.ServiceList)
	return list, args.Error(1)
}

type mockedCertificates struct {
	mock.Mock
}

func (m *mockedCertificates) Create(ctx context.Context, certificateSigningRequest *capi.CertificateSigningRequest, opts metaV1.CreateOptions) (*capi.CertificateSigningRequest, error) {
	args := m.Called(ctx, certificateSigningRequest, opts)
	csr, _ := args.Get(0).(*capi.CertificateSigningRequest)
	return csr, args.Error(1)
}

func (m *mockedCertificates) Get(ctx context.Context, name string, opts metaV1.GetOptions) (*capi.CertificateSigningRequest, error) {
	args := m.Called(ctx, name, opts)
	csr, _ := args.Get(0).(*capi.CertificateSigningRequest)
	return csr, args.Error(1)
}

func (m *mockedCertificates) Watch(ctx context.Context, opts metaV1.ListOptions) (watch.Interface, error) {
	args := m.Called(ctx, opts)
	w, _ := args.Get(0).(watch.Interface)
	return w, args.Error(1)
}
