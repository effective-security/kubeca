package operator_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/effective-security/kubeca/api/v1alpha1"
	"github.com/effective-security/kubeca/internal/operator"
	"github.com/effective-security/kubeca/internal/testauthority"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

const (
	managerNamespace = "review"
	// quietPeriod is how long a count must stay unchanged to show that
	// nothing re-enqueues the Certificate; the loop of KUBECA-015 made 16
	// attempts in about 50 ms.
	quietPeriod = 3 * time.Second
)

// managerSuite runs the operator manager (operator.Setup with the test
// Authority, no webhook) against its own envtest API server, to observe
// what the informers and the watches do, which the fake-client tests of
// the controllers cannot. It needs KUBEBUILDER_ASSETS and skips without it.
type managerSuite struct {
	suite.Suite
	env    *envtest.Environment
	client client.Client
	cancel context.CancelFunc
	done   chan error
}

func TestManager(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS is not set: run make envtest")
	}
	suite.Run(t, new(managerSuite))
}

func (s *managerSuite) SetupSuite() {
	s.env = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := s.env.Start()
	s.Require().NoError(err)
	scheme, err := operator.Scheme()
	s.Require().NoError(err)
	s.client, err = client.New(cfg, client.Options{Scheme: scheme})
	s.Require().NoError(err)

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Cache:                  operator.CacheOptions(),
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		Logger:                 logr.Discard(),
	})
	s.Require().NoError(err)
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.Require().NoError(operator.Setup(ctx, mgr, testauthority.New(s.T()).Authority, operator.Options{}))
	s.done = make(chan error, 1)
	go func() { s.done <- mgr.Start(ctx) }()

	s.Require().NoError(s.client.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: managerNamespace}}))
	issuer := &v1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "kubeca"},
		Spec: v1alpha1.ClusterIssuerSpec{
			IssuerLabel:    testauthority.IssuerLabel,
			Profiles:       []string{testauthority.ProfileClient},
			DefaultProfile: testauthority.ProfileClient,
			// no policy: the xpki profile is the only gate
		},
	}
	s.Require().NoError(s.client.Create(ctx, issuer))
	s.Require().Eventually(func() bool {
		var got v1alpha1.ClusterIssuer
		return s.client.Get(ctx, client.ObjectKeyFromObject(issuer), &got) == nil &&
			meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionReady)
	}, 30*time.Second, 100*time.Millisecond, "the ClusterIssuer controller marks the issuer Ready")
}

func (s *managerSuite) TearDownSuite() {
	if s.cancel != nil {
		s.cancel()
		s.NoError(<-s.done)
	}
	if s.env != nil {
		s.Require().NoError(s.env.Stop())
	}
}

// failedAttempts reads the Certificate's status.failedAttempts.
func (s *managerSuite) failedAttempts(key client.ObjectKey) int32 {
	var cert v1alpha1.Certificate
	s.Require().NoError(s.client.Get(context.Background(), key, &cert))
	return cert.Status.FailedAttempts
}

// TestPermanentFailureIsNotRetried (KUBECA-015): a Certificate that xpki
// rejects is attempted once; the status patch that records the failure
// does not enqueue it again. A renewal request is a relevant change and
// is attempted once more.
func (s *managerSuite) TestPermanentFailureIsNotRetried() {
	ctx := context.Background()
	cert := &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "rejected", Namespace: managerNamespace},
		Spec: v1alpha1.CertificateSpec{
			IssuerRef: v1alpha1.IssuerReference{Name: "kubeca"},
			// client-24h pins the trust domain of its URIs
			URIs: []string{"spiffe://other.org/ns/review/sa/web"},
		},
	}
	s.Require().NoError(s.client.Create(ctx, cert))
	key := client.ObjectKeyFromObject(cert)

	s.Require().Eventually(func() bool { return s.failedAttempts(key) > 0 }, 30*time.Second, 50*time.Millisecond)
	s.Never(func() bool { return s.failedAttempts(key) > 1 }, quietPeriod, 50*time.Millisecond, "no retry through the status update")
	var got v1alpha1.Certificate
	s.Require().NoError(s.client.Get(ctx, key, &got))
	ready := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionReady)
	s.Require().NotNil(ready)
	s.Equal(v1alpha1.ReasonIssuanceFailed, ready.Reason)
	s.Equal("unable to sign: URI does not match allowed list: spiffe://other.org/ns/review/sa/web", ready.Message)

	s.Require().NoError(retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := s.client.Get(ctx, key, &got); err != nil {
			return err
		}
		got.Annotations = map[string]string{v1alpha1.AnnotationRenewRequested: "1"}
		return s.client.Update(ctx, &got)
	}))
	s.Require().Eventually(func() bool { return s.failedAttempts(key) == 2 }, 30*time.Second, 50*time.Millisecond)
	s.Never(func() bool { return s.failedAttempts(key) > 2 }, quietPeriod, 50*time.Millisecond)
}

// TestCABundleFollowsIssuerRef: moving a Certificate to another
// ClusterIssuer publishes that issuer's CA bundle into the namespace, and
// moving it back prunes it. The issuer controller passes Certificate
// updates that change spec.issuerRef.name, and the map handler enqueues
// the issuers of both the old and the new object.
func (s *managerSuite) TestCABundleFollowsIssuerRef() {
	ctx := context.Background()
	moved := &v1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "moved"},
		Spec: v1alpha1.ClusterIssuerSpec{
			IssuerLabel:    testauthority.IssuerLabel,
			Profiles:       []string{testauthority.ProfileClient},
			DefaultProfile: testauthority.ProfileClient,
			CABundle:       &v1alpha1.CABundleSpec{ConfigMapName: "moved-ca"},
		},
	}
	s.Require().NoError(s.client.Create(ctx, moved))
	s.Require().Eventually(func() bool {
		var got v1alpha1.ClusterIssuer
		return s.client.Get(ctx, client.ObjectKeyFromObject(moved), &got) == nil &&
			meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionReady)
	}, 30*time.Second, 100*time.Millisecond)

	cert := &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "mover", Namespace: managerNamespace},
		Spec: v1alpha1.CertificateSpec{
			IssuerRef: v1alpha1.IssuerReference{Name: "kubeca"},
			URIs:      []string{"spiffe://other.org/ns/review/sa/web"},
		},
	}
	s.Require().NoError(s.client.Create(ctx, cert))
	bundle := client.ObjectKey{Namespace: managerNamespace, Name: "moved-ca"}
	exists := func() bool {
		var cm corev1.ConfigMap
		return s.client.Get(ctx, bundle, &cm) == nil
	}
	setIssuer := func(name string) {
		s.Require().NoError(retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := s.client.Get(ctx, client.ObjectKeyFromObject(cert), cert); err != nil {
				return err
			}
			cert.Spec.IssuerRef.Name = name
			return s.client.Update(ctx, cert)
		}))
	}

	s.False(exists(), "no Certificate of moved in the namespace yet")
	setIssuer("moved")
	s.Require().Eventually(exists, 30*time.Second, 50*time.Millisecond, "published for the new issuer")
	setIssuer("kubeca")
	s.Require().Eventually(func() bool { return !exists() }, 30*time.Second, 50*time.Millisecond, "pruned when the last Certificate left")
}
