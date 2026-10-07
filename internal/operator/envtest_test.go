package operator_test

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/kubeca/api/v1alpha1"
	"github.com/effective-security/kubeca/internal/operator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

const (
	// admissionPolicyTemplate is the chart's ValidatingAdmissionPolicy.
	admissionPolicyTemplate = "../../examples/kubeca/templates/admission-policy.yaml"
	// operatorUser is the operator's ServiceAccount for release kubeca in
	// namespace kubeca, as the chart renders it.
	operatorUser = "system:serviceaccount:kubeca:kubeca"
	// admissionPolicyMessage is the denial message of the policy.
	admissionPolicyMessage = "only the kubeca operator may create a Certificate controlled by a Pod or change its spec or owner references"
)

func ptr[T any](v T) *T { return &v }

// documentSeparator splits a multi-document YAML file.
var documentSeparator = regexp.MustCompile(`(?m)^---\s*$`)

// crdSuite validates the generated CRDs against a real API server
// (envtest): the CEL rules, the immutability rules, the defaults and the
// status subresource. It needs KUBEBUILDER_ASSETS (make envtest) and skips
// without it.
type crdSuite struct {
	suite.Suite
	env    *envtest.Environment
	cfg    *rest.Config
	client client.Client
}

func TestCRDs(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS is not set: run make envtest")
	}
	suite.Run(t, new(crdSuite))
}

func (s *crdSuite) SetupSuite() {
	s.env = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := s.env.Start()
	s.Require().NoError(err)
	s.cfg = cfg
	scheme, err := operator.Scheme()
	s.Require().NoError(err)
	s.client, err = client.New(cfg, client.Options{Scheme: scheme})
	s.Require().NoError(err)
	s.Require().NoError(s.client.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "shop"}}))
}

func (s *crdSuite) TearDownSuite() {
	if s.env != nil {
		s.Require().NoError(s.env.Stop())
	}
}

func (s *crdSuite) certificate(name string) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "shop"},
		Spec: v1alpha1.CertificateSpec{
			IssuerRef: v1alpha1.IssuerReference{Name: "kubeca"},
			DNSNames:  []string{"web.shop.svc"},
		},
	}
}

func (s *crdSuite) assertInvalid(obj client.Object, message string) {
	s.T().Helper()
	err := s.client.Create(context.Background(), obj)
	s.Require().Error(err)
	s.True(apierrors.IsInvalid(err), err.Error())
	s.Contains(err.Error(), message)
}

func (s *crdSuite) TestCertificateValidation() {
	ctx := context.Background()

	cert := s.certificate("valid")
	cert.Spec.Duration = &metav1.Duration{Duration: 24 * time.Hour}
	cert.Spec.RenewBefore = &metav1.Duration{Duration: 8 * time.Hour}
	cert.Spec.PrivateKey = &v1alpha1.PrivateKeySpec{Size: 384}
	s.Require().NoError(s.client.Create(ctx, cert))
	s.Equal(v1alpha1.KeyAlgorithmECDSA, cert.Spec.PrivateKey.Algorithm, "defaulted")
	s.Equal(v1alpha1.RotationPolicyAlways, cert.Spec.PrivateKey.RotationPolicy, "defaulted")

	// status is a subresource: a spec update does not carry it and a
	// status update does not touch the spec
	cert.Status.Revision = 3
	s.Require().NoError(s.client.Update(ctx, cert))
	var got v1alpha1.Certificate
	s.Require().NoError(s.client.Get(ctx, client.ObjectKeyFromObject(cert), &got))
	s.Equal(int64(0), got.Status.Revision)
	got.Status.Revision = 3
	got.Status.Conditions = []metav1.Condition{{Type: v1alpha1.ConditionReady, Status: metav1.ConditionTrue, Reason: v1alpha1.ReasonIssued, LastTransitionTime: metav1.Now()}}
	s.Require().NoError(s.client.Status().Update(ctx, &got))
	s.Require().NoError(s.client.Get(ctx, client.ObjectKeyFromObject(cert), &got))
	s.Equal(int64(3), got.Status.Revision)
	s.Len(got.Status.Conditions, 1)

	// secretName is immutable once set
	s.Require().NoError(s.client.Get(ctx, client.ObjectKeyFromObject(cert), cert))
	cert.Spec.SecretName = "a"
	s.Require().NoError(s.client.Update(ctx, cert))
	cert.Spec.SecretName = "b"
	err := s.client.Update(ctx, cert)
	s.Require().Error(err)
	s.Contains(err.Error(), "secretName is immutable")
	// and cannot be removed to be set again later
	cert.Spec.SecretName = ""
	err = s.client.Update(ctx, cert)
	s.Require().Error(err)
	s.Contains(err.Error(), "secretName cannot be removed once set")

	noNames := s.certificate("no-names")
	noNames.Spec.DNSNames = nil
	s.assertInvalid(noNames, "at least one name is required")

	servicesOnly := s.certificate("services-only")
	servicesOnly.Spec.DNSNames = nil
	servicesOnly.Spec.KubernetesNames = &v1alpha1.KubernetesNames{Services: []string{"web"}}
	s.Require().NoError(s.client.Create(ctx, servicesOnly))

	renew := s.certificate("renew-before")
	renew.Spec.Duration = &metav1.Duration{Duration: time.Hour}
	renew.Spec.RenewBefore = &metav1.Duration{Duration: time.Hour}
	s.assertInvalid(renew, "renewBefore must be shorter than duration")

	short := s.certificate("short")
	short.Spec.Duration = &metav1.Duration{Duration: 30 * time.Second}
	s.assertInvalid(short, "duration must be at least 1m")

	shortRenew := s.certificate("short-renew")
	shortRenew.Spec.RenewBefore = &metav1.Duration{Duration: 10 * time.Second}
	s.assertInvalid(shortRenew, "renewBefore must be at least 30s")

	badSize := s.certificate("bad-size")
	badSize.Spec.PrivateKey = &v1alpha1.PrivateKeySpec{Algorithm: v1alpha1.KeyAlgorithmRSA, Size: 256}
	s.assertInvalid(badSize, "size must be 256, 384 or 521 for ECDSA and 2048, 3072 or 4096 for RSA")

	badAlgo := s.certificate("bad-algo")
	badAlgo.Spec.PrivateKey = &v1alpha1.PrivateKeySpec{Algorithm: "DSA"}
	s.assertInvalid(badAlgo, `Unsupported value: "DSA"`)

	noIssuer := s.certificate("no-issuer")
	noIssuer.Spec.IssuerRef.Name = ""
	s.assertInvalid(noIssuer, "spec.issuerRef.name")

	badSecret := s.certificate("bad-secret")
	badSecret.Spec.SecretName = "Not_Valid"
	s.assertInvalid(badSecret, "spec.secretName")

	badService := s.certificate("bad-service")
	badService.Spec.KubernetesNames = &v1alpha1.KubernetesNames{Services: []string{"Web"}}
	s.assertInvalid(badService, "spec.kubernetesNames.services")
}

func (s *crdSuite) TestClusterIssuerValidation() {
	ctx := context.Background()
	ci := &v1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "kubeca"},
		Spec: v1alpha1.ClusterIssuerSpec{
			IssuerLabel:    "kubeca.svc",
			Profiles:       []string{"peer-24h"},
			DefaultProfile: "peer-24h",
			SPIFFE:         &v1alpha1.SPIFFESpec{TrustDomain: "example.org"},
			Policy: &v1alpha1.IssuerPolicy{
				MaxDuration:           &metav1.Duration{Duration: 24 * time.Hour},
				AllowedEmailAddresses: &[]string{},
			},
			CABundle: &v1alpha1.CABundleSpec{ConfigMapName: "kubeca-ca"},
		},
	}
	s.Require().NoError(s.client.Create(ctx, ci))
	var got v1alpha1.ClusterIssuer
	s.Require().NoError(s.client.Get(ctx, client.ObjectKeyFromObject(ci), &got))
	s.Require().NotNil(got.Spec.Policy.AllowedEmailAddresses, "an explicit empty list survives the round trip")
	s.Empty(*got.Spec.Policy.AllowedEmailAddresses)
	s.Nil(got.Spec.Policy.AllowedDNSNames, "an absent list stays absent")

	ci.Spec.IssuerLabel = "other"
	err := s.client.Update(ctx, ci)
	s.Require().Error(err)
	s.Contains(err.Error(), "issuerLabel is immutable")

	got.Status.IssuerKeyID = "abcd"
	s.Require().NoError(s.client.Status().Update(ctx, &got))
	s.Require().NoError(s.client.Get(ctx, client.ObjectKeyFromObject(ci), &got))
	s.Equal("abcd", got.Status.IssuerKeyID)

	badDefault := &v1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-default"},
		Spec:       v1alpha1.ClusterIssuerSpec{IssuerLabel: "kubeca.svc", Profiles: []string{"a"}, DefaultProfile: "b"},
	}
	s.assertInvalid(badDefault, "defaultProfile must be listed in profiles")

	noLabel := &v1alpha1.ClusterIssuer{ObjectMeta: metav1.ObjectMeta{Name: "no-label"}}
	s.assertInvalid(noLabel, "spec.issuerLabel")

	badDomain := &v1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-domain"},
		Spec:       v1alpha1.ClusterIssuerSpec{IssuerLabel: "kubeca.svc", SPIFFE: &v1alpha1.SPIFFESpec{TrustDomain: "Example.org"}},
	}
	s.assertInvalid(badDomain, "spec.spiffe.trustDomain")

	shortMax := &v1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "short-max"},
		Spec:       v1alpha1.ClusterIssuerSpec{IssuerLabel: "kubeca.svc", Policy: &v1alpha1.IssuerPolicy{MaxDuration: &metav1.Duration{Duration: time.Second}}},
	}
	s.assertInvalid(shortMax, "maxDuration must be at least 1m")
}

// userClient is a client authenticated as name; system:masters spares the
// RBAC setup, admission still applies.
func (s *crdSuite) userClient(name string) client.Client {
	s.T().Helper()
	user, err := s.env.AddUser(envtest.User{Name: name, Groups: []string{"system:masters"}}, s.cfg)
	s.Require().NoError(err)
	c, err := client.New(user.Config(), client.Options{Scheme: s.client.Scheme()})
	s.Require().NoError(err)
	return c
}

// renderAdmissionPolicy renders the chart's admission policy as Helm does
// for release kubeca in namespace kubeca: the template has a guard, the
// labels include and three values; any other template action fails the
// test, so that a change to the template is rendered here too.
func (s *crdSuite) renderAdmissionPolicy() []client.Object {
	s.T().Helper()
	raw, err := os.ReadFile(admissionPolicyTemplate)
	s.Require().NoError(err)
	text := strings.NewReplacer(
		`{{ include "kubeca.fullname" $ }}`, "kubeca",
		`{{ include "kubeca.serviceAccountName" $ }}`, "kubeca",
		`{{ $.Release.Namespace }}`, "kubeca",
	).Replace(string(raw))
	var kept strings.Builder
	for line := range strings.Lines(text) {
		if !strings.HasPrefix(strings.TrimSpace(line), "{{") {
			kept.WriteString(line)
		}
	}
	s.Require().NotContains(kept.String(), "{{", "a template action the test does not render")

	decoder := serializer.NewCodecFactory(s.client.Scheme()).UniversalDeserializer()
	var objs []client.Object
	for _, doc := range documentSeparator.Split(kept.String(), -1) {
		if strings.TrimSpace(regexp.MustCompile(`(?m)^\s*#.*$`).ReplaceAllString(doc, "")) == "" {
			continue
		}
		obj, _, err := decoder.Decode([]byte(doc), nil, nil)
		s.Require().NoError(err)
		objs = append(objs, obj.(client.Object))
	}
	s.Require().Len(objs, 2, "the policy and its binding")
	return objs
}

// TestPodCertificatePolicy applies the chart's ValidatingAdmissionPolicy
// (KUBECA-014): only the operator's ServiceAccount creates a Certificate
// controlled by a Pod or changes its spec or owner references; others may
// still annotate it, drop the Pod as controller (keeping the spec in that
// update), and create Certificates that no Pod controls.
func (s *crdSuite) TestPodCertificatePolicy() {
	ctx := context.Background()
	objs := s.renderAdmissionPolicy()
	for _, obj := range objs {
		s.Require().NoError(s.client.Create(ctx, obj))
	}
	defer func() {
		for _, obj := range objs {
			s.NoError(s.client.Delete(ctx, obj))
		}
	}()

	// (the type-checking status is written by kube-controller-manager,
	// which envtest does not run; scripts/minikube_test.sh checks it)
	_, isPolicy := objs[0].(*admissionv1.ValidatingAdmissionPolicy)
	s.Require().True(isPolicy)

	operatorClient := s.userClient(operatorUser)
	author := s.userClient("alice")
	podOwned := func(name string, controller bool) *v1alpha1.Certificate {
		cert := s.certificate(name)
		cert.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: "web-0", UID: "uid-web-0", Controller: ptr(controller)}}
		return cert
	}
	denied := func(err error) {
		s.T().Helper()
		s.Require().Error(err)
		s.True(apierrors.IsForbidden(err), err.Error())
		s.Contains(err.Error(), admissionPolicyMessage)
	}

	// enforced once the API server has loaded the binding
	s.Require().Eventually(func() bool {
		probe := podOwned("probe", true)
		if err := author.Create(ctx, probe); err == nil {
			s.Require().NoError(s.client.Delete(ctx, probe))
			return false
		}
		return true
	}, 30*time.Second, 200*time.Millisecond)

	// a forged Pod controller is rejected, the operator's is not
	denied(author.Create(ctx, podOwned("forged", true)))
	cert := podOwned("web-0", true)
	s.Require().NoError(operatorClient.Create(ctx, cert))

	// others may annotate it (renew-requested), not change its spec or owner
	cert.Annotations = map[string]string{v1alpha1.AnnotationRenewRequested: "1"}
	s.Require().NoError(author.Update(ctx, cert))
	changed := cert.DeepCopy()
	changed.Spec.DNSNames = append(changed.Spec.DNSNames, "api.shop.svc")
	denied(author.Update(ctx, changed))
	changed = cert.DeepCopy()
	changed.OwnerReferences[0].UID = "uid-other"
	denied(author.Update(ctx, changed))
	changed = cert.DeepCopy()
	changed.OwnerReferences[0].Name = "web-1"
	denied(author.Update(ctx, changed))
	// the operator may
	changed = cert.DeepCopy()
	changed.Spec.DNSNames = append(changed.Spec.DNSNames, "api.shop.svc")
	s.Require().NoError(operatorClient.Update(ctx, changed))
	cert = changed

	// dropping the Pod as controller keeps the spec: not in the same
	// update as a spec change, nor by demoting the reference
	changed = cert.DeepCopy()
	changed.OwnerReferences = nil
	changed.Spec.DNSNames = []string{"evil.shop.svc"}
	denied(author.Update(ctx, changed))
	changed = cert.DeepCopy()
	changed.OwnerReferences[0].Controller = ptr(false)
	changed.Spec.DNSNames = []string{"evil.shop.svc"}
	denied(author.Update(ctx, changed))

	// dropping it alone makes a plain Certificate (${SERVICE_ACCOUNT} no
	// longer expands for it), whose spec is then its author's and which
	// cannot be handed back to the Pod
	cert.OwnerReferences = nil
	s.Require().NoError(author.Update(ctx, cert))
	cert.Spec.DNSNames = []string{"evil.shop.svc"}
	s.Require().NoError(author.Update(ctx, cert))
	cert.OwnerReferences = podOwned("", true).OwnerReferences
	denied(author.Update(ctx, cert))

	// Certificates no Pod controls are not the policy's business
	s.Require().NoError(author.Create(ctx, s.certificate("direct")))
	s.Require().NoError(author.Create(ctx, podOwned("gc-only", false)))
}

func (s *crdSuite) TestList() {
	var list v1alpha1.CertificateList
	s.Require().NoError(s.client.List(context.Background(), &list, client.InNamespace("shop")))
	assert.NotEmpty(s.T(), list.Items)
}
