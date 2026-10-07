package operator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/kubeca/api/v1alpha1"
	"github.com/effective-security/kubeca/internal/k8snames"
	"github.com/effective-security/kubeca/internal/operator/certificate"
	"github.com/effective-security/kubeca/internal/operator/index"
	"github.com/effective-security/kubeca/internal/operator/issuer"
	"github.com/effective-security/kubeca/internal/operator/pod"
	"github.com/effective-security/kubeca/internal/operator/webhook"
	"github.com/effective-security/xpki/authority"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	// DefaultWebhookPort is the port the webhook server listens on.
	DefaultWebhookPort = 9443
	// DefaultWebhookProfile is the profile of the serving certificate.
	DefaultWebhookProfile = "webhook"
	// DefaultWebhookConfigName is the MutatingWebhookConfiguration whose
	// caBundle the operator maintains.
	DefaultWebhookConfigName = "kubeca-pod-injector"

	// Names of the controllers' event recorders.
	issuerRecorder      = "kubeca-clusterissuer"
	certificateRecorder = "kubeca-certificate"
	podRecorder         = "kubeca-pod"
)

// Options of the operator.
type Options struct {
	// ClusterDomain is the cluster DNS suffix of the derived names.
	ClusterDomain string
	// MaxConcurrentReconciles of the Certificate controller; 0 is the
	// package default (4).
	MaxConcurrentReconciles int
	// Webhook enables the Pod mutating webhook when set.
	Webhook *WebhookOptions
}

// WebhookOptions of the Pod mutating webhook.
type WebhookOptions struct {
	// Port of the HTTPS server; DefaultWebhookPort when 0.
	Port int
	// CertDir receives the serving certificate; the controller-runtime
	// default when empty.
	CertDir string
	// ServiceName and ServiceNamespace of the webhook Service: the DNS
	// names of the serving certificate.
	ServiceName      string
	ServiceNamespace string
	// IssuerLabel and Profile sign the serving certificate.
	IssuerLabel string
	Profile     string
	// ConfigName is the MutatingWebhookConfiguration to patch; "" skips
	// the patch.
	ConfigName string
}

// Scheme returns a scheme with core/v1, admissionregistration/v1 and the
// operator API.
func Scheme() (*runtime.Scheme, error) {
	s := runtime.NewScheme()
	if err := AddToScheme(s); err != nil {
		return nil, err
	}
	return s, nil
}

// AddToScheme adds the operator's kinds to an existing scheme.
func AddToScheme(s *runtime.Scheme) error {
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, admissionv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(s); err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

// CacheOptions restricts the informer caches: Secrets and ConfigMaps to
// those labeled managed=true, Pods to those labeled inject=true; every
// object is stored without managedFields. Certificates, ClusterIssuers,
// Namespaces and Services are cached fully.
func CacheOptions() cache.Options {
	managed := labels.SelectorFromSet(labels.Set{v1alpha1.LabelManaged: v1alpha1.TrueValue})
	injected := labels.SelectorFromSet(labels.Set{v1alpha1.LabelInject: v1alpha1.TrueValue})
	return cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Secret{}:    {Label: managed},
			&corev1.ConfigMap{}: {Label: managed},
			&corev1.Pod{}:       {Label: injected},
		},
		DefaultTransform: cache.TransformStripManagedFields(),
	}
}

// WebhookServer returns the webhook server for the manager options, or
// nil when the webhook is disabled.
func WebhookServer(opts *WebhookOptions) ctrlwebhook.Server {
	if opts == nil {
		return nil
	}
	port := opts.Port
	if port == 0 {
		port = DefaultWebhookPort
	}
	return ctrlwebhook.NewServer(ctrlwebhook.Options{
		Port:    port,
		CertDir: opts.certDir(),
	})
}

// certDir is CertDir, or controller-runtime's default directory.
func (o *WebhookOptions) certDir() string {
	if o.CertDir != "" {
		return o.CertDir
	}
	return filepath.Join(os.TempDir(), "k8s-webhook-server", "serving-certs")
}

// Setup registers the indexes, the controllers and the webhook with the
// manager. With a webhook, the serving certificate is issued before Setup
// returns so that the server finds its files at start.
func Setup(ctx context.Context, mgr ctrl.Manager, ca *authority.Authority, opts Options) error {
	if err := index.Register(ctx, mgr.GetFieldIndexer()); err != nil {
		return errors.WithMessage(err, "unable to register field indexes")
	}
	domain := opts.ClusterDomain
	if domain == "" {
		domain = k8snames.DefaultClusterDomain
	}
	realClock := clock.RealClock{}
	if err := (&issuer.Reconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Scheme:    mgr.GetScheme(),
		Authority: ca,
		Recorder:  mgr.GetEventRecorderFor(issuerRecorder), // nolint:staticcheck
		Clock:     realClock,
	}).SetupWithManager(mgr); err != nil {
		return errors.WithMessage(err, "unable to set up the ClusterIssuer controller")
	}
	if err := (&certificate.Reconciler{
		Client:                  mgr.GetClient(),
		APIReader:               mgr.GetAPIReader(),
		Scheme:                  mgr.GetScheme(),
		Authority:               ca,
		Recorder:                mgr.GetEventRecorderFor(certificateRecorder), // nolint:staticcheck
		Clock:                   realClock,
		ClusterDomain:           domain,
		MaxConcurrentReconciles: opts.MaxConcurrentReconciles,
	}).SetupWithManager(mgr); err != nil {
		return errors.WithMessage(err, "unable to set up the Certificate controller")
	}
	if err := (&pod.Reconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Recorder:      mgr.GetEventRecorderFor(podRecorder), // nolint:staticcheck
		ClusterDomain: domain,
	}).SetupWithManager(mgr); err != nil {
		return errors.WithMessage(err, "unable to set up the Pod controller")
	}
	if opts.Webhook == nil {
		return nil
	}
	return setupWebhook(ctx, mgr, ca, opts.Webhook, domain)
}

func setupWebhook(ctx context.Context, mgr ctrl.Manager, ca *authority.Authority, opts *WebhookOptions, domain string) error {
	if opts.ServiceName == "" || opts.ServiceNamespace == "" {
		return errors.New("webhook: the Service name and namespace are required")
	}
	if opts.IssuerLabel == "" {
		return errors.New("webhook: the issuer label is required")
	}
	profile := opts.Profile
	if profile == "" {
		profile = DefaultWebhookProfile
	}
	serving := &webhook.ServingCertificate{
		Authority:   ca,
		Client:      mgr.GetClient(),
		Reader:      mgr.GetAPIReader(),
		IssuerLabel: opts.IssuerLabel,
		Profile:     profile,
		DNSNames: []string{
			fmt.Sprintf("%s.%s.svc", opts.ServiceName, opts.ServiceNamespace),
			fmt.Sprintf("%s.%s.svc.%s", opts.ServiceName, opts.ServiceNamespace, domain),
		},
		CertDir:    opts.certDir(),
		ConfigName: opts.ConfigName,
		Clock:      clock.RealClock{},
	}
	if err := serving.Issue(ctx); err != nil {
		return errors.WithMessage(err, "unable to issue the webhook serving certificate")
	}
	if err := mgr.Add(serving); err != nil {
		return errors.WithMessage(err, "unable to add the webhook certificate renewer")
	}
	mgr.GetWebhookServer().Register(webhook.Path, &admission.Webhook{Handler: webhook.NewPodMutator(mgr.GetScheme())})
	return nil
}
