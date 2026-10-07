package certinit

import (
	"context"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/kubeca/internal/k8snames"
	"github.com/effective-security/xlog"
	capi "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/kubeca", "certinit")

const (
	labelSeparator = "="
)

// Request parameters
type Request struct {
	// Namespace as defined by pod.metadata.namespace
	Namespace string
	// PodName name as defined by pod.metadata.name
	PodName string
	// CertDir is directory where the TLS certs should be written
	CertDir string
	// ClusterDomain specifies kubernetes cluster domain
	ClusterDomain string
	// Labels to include in CertificateSigningRequest object; comma separated list of key=value
	Labels string
	// QueryK8s specifies to query kubernetes for names appropriate to this Pod
	QueryK8s bool
	// SAN is additional comma separated DNS, IP, URI or Emails to include in SAN
	SAN string
	// ServiceNames lists Services in the Pod's namespace that resolve to this
	// Pod; comma separated. Each name is added to the SAN as
	// <name>.<namespace>.svc.<cluster-domain> and, with IncludeUnqualified,
	// <name>.<namespace>.svc.
	ServiceNames string
	// IncludeUnqualified specifies to include unqualified .svc domains in names from --query-k8s
	IncludeUnqualified bool
	// SignerName specifies the signer name
	SignerName string
	// Usages overrides the Kubernetes key usages requested in the CSR; comma
	// separated certificates.k8s.io KeyUsage values. Required for a profile
	// other than peer, server or client. The CA ignores them and applies the
	// profile's usages.
	Usages string

	san       []string
	labelsMap map[string]string
}

// CertClient provides minimum interfaces to create a CSR
type CertClient struct {
	Pods         MinPods
	Services     MinServices
	Certificates MinCertificates
}

// MinPods is minimum Pods interface
type MinPods interface {
	Get(ctx context.Context, name string, opts metaV1.GetOptions) (*v1.Pod, error)
}

// MinServices is minimum Services interface
type MinServices interface {
	List(ctx context.Context, opts metaV1.ListOptions) (*v1.ServiceList, error)
}

// MinCertificates is minimum Certificates interface. Watch follows the
// CSR after it is created (KUBECA-006); a Watch error falls back to
// polling with Get.
type MinCertificates interface {
	Create(ctx context.Context, certificateSigningRequest *capi.CertificateSigningRequest, opts metaV1.CreateOptions) (*capi.CertificateSigningRequest, error)
	Get(ctx context.Context, name string, opts metaV1.GetOptions) (*capi.CertificateSigningRequest, error)
	Watch(ctx context.Context, opts metaV1.ListOptions) (watch.Interface, error)
}

// Create certificate request and wait for issuance. The wait ends when ctx
// is done; pass a context with a timeout to bound it.
func (r *Request) Create(ctx context.Context, client *CertClient) error {
	if r.Namespace == "" {
		return errors.New("missing required namespace parameter")
	}
	if r.PodName == "" {
		return errors.New("missing required pod name parameter")
	}
	if r.SignerName == "" {
		return errors.New("missing required signer name parameter")
	}

	logger.ContextKV(ctx, xlog.INFO,
		"ns", r.Namespace,
		"pod", r.PodName,
		"signer", r.SignerName,
		"san", r.SAN)

	// Gather the list of labels that will be added to the CreateCertificateSigningRequest object
	r.labelsMap = make(map[string]string)
	for n := range k8snames.SplitList(r.Labels) {
		label, value, found := strings.Cut(n, labelSeparator)
		label, value = strings.TrimSpace(label), strings.TrimSpace(value)
		if !found || label == "" || strings.Contains(value, labelSeparator) {
			continue
		}
		r.labelsMap[label] = value
	}

	r.san = nil
	opts := k8snames.Options{ClusterDomain: r.ClusterDomain, IncludeUnqualified: r.IncludeUnqualified}
	if r.QueryK8s {
		pod, err := client.Pods.Get(ctx, r.PodName, metaV1.GetOptions{})
		if err != nil {
			return errors.WithMessagef(err, "failed to query pod %q in namespace %q", r.PodName, r.Namespace)
		}
		serviceList, err := client.Services.List(ctx, metaV1.ListOptions{})
		if err != nil {
			return errors.WithMessagef(err, "failed to query names for pod %q in namespace %q", r.PodName, r.Namespace)
		}
		r.san = k8snames.ForPod(pod, serviceList.Items, opts).All()
	}

	for name := range k8snames.SplitList(r.ServiceNames) {
		r.san = append(r.san, k8snames.ServiceNames(name, r.Namespace, opts)...)
	}

	for s := range k8snames.SplitList(r.SAN) {
		r.san = append(r.san, s)
	}

	err := r.requestCertificate(ctx, client.Certificates)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// NewClient returns new client
func NewClient(kubeconfig, namespace string) (*CertClient, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	c, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &CertClient{
		Pods:         c.CoreV1().Pods(namespace),
		Services:     c.CoreV1().Services(namespace),
		Certificates: c.CertificatesV1().CertificateSigningRequests(),
	}, nil
}
