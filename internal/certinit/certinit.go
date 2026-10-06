package certinit

import (
	"context"
	"fmt"
	"iter"
	"strings"

	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
	capi "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/kubeca", "certinit")

const (
	listSeparator  = ","
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

// MinCertificates is minimum Certificates interface
type MinCertificates interface {
	Create(ctx context.Context, certificateSigningRequest *capi.CertificateSigningRequest, opts metaV1.CreateOptions) (*capi.CertificateSigningRequest, error)
	Get(ctx context.Context, name string, opts metaV1.GetOptions) (*capi.CertificateSigningRequest, error)
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
	for n := range splitList(r.Labels) {
		label, value, found := strings.Cut(n, labelSeparator)
		label, value = strings.TrimSpace(label), strings.TrimSpace(value)
		if !found || label == "" || strings.Contains(value, labelSeparator) {
			continue
		}
		r.labelsMap[label] = value
	}

	r.san = nil
	if r.QueryK8s {
		pod, err := client.Pods.Get(ctx, r.PodName, metaV1.GetOptions{})
		if err != nil {
			return errors.WithMessagef(err, "failed to query pod %q in namespace %q", r.PodName, r.Namespace)
		}

		r.san, err = getNamesForPod(ctx, client.Services, *pod, r.ClusterDomain, r.IncludeUnqualified)
		if err != nil {
			return errors.WithMessagef(err, "failed to query names for pod %q in namespace %q", r.PodName, r.Namespace)
		}
	}

	for name := range splitList(r.ServiceNames) {
		r.san = append(r.san, serviceNames(name, r.Namespace, r.ClusterDomain, r.IncludeUnqualified)...)
	}

	for s := range splitList(r.SAN) {
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

// splitList yields the non-empty, trimmed items of a comma-separated list.
func splitList(list string) iter.Seq[string] {
	return func(yield func(string) bool) {
		for item := range strings.SplitSeq(list, listSeparator) {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if !yield(item) {
				return
			}
		}
	}
}

// serviceNames returns the DNS names of a Service: the cluster-qualified
// name and, when allowUnqualified is set, the .svc name.
func serviceNames(name, namespace, clusterDomain string, allowUnqualified bool) []string {
	names := []string{fmt.Sprintf("%s.%s.svc.%s", name, namespace, clusterDomain)}
	if allowUnqualified {
		names = append(names, fmt.Sprintf("%s.%s.svc", name, namespace))
	}
	return names
}

// getNamesForPod returns the DNS names and IPs that a given POD is permitted to have,
// either in its own right or by dint of matching services.
// Does not currently pay attention to static Endpoints.
func getNamesForPod(ctx context.Context, client MinServices, pod v1.Pod, clusterDomain string, allowUnqualified bool) (san []string, err error) {
	// The Pod DNS name needs the IP; the status may not carry it yet.
	if ip := pod.Status.PodIP; ip != "" {
		san = append(san, fmt.Sprintf("%s.%s.pod.%s", ipToName(ip), pod.Namespace, clusterDomain))
	}
	if pod.Spec.Hostname != "" && pod.Spec.Subdomain != "" {
		san = append(san, fmt.Sprintf("%s.%s.%s.svc.%s", pod.Spec.Hostname, pod.Spec.Subdomain, pod.Namespace, clusterDomain))
		if allowUnqualified {
			san = append(san, fmt.Sprintf("%s.%s.%s.svc", pod.Spec.Hostname, pod.Spec.Subdomain, pod.Namespace))
		}
	}

	podLabels := labels.Set(pod.Labels)

	serviceList, err := client.List(ctx, metaV1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, service := range serviceList.Items {
		if service.Spec.Selector == nil {
			continue
		}
		selector := labels.Set(service.Spec.Selector).AsSelectorPreValidated()
		if selector.Matches(podLabels) {
			san = append(san, serviceNames(service.Name, service.Namespace, clusterDomain, allowUnqualified)...)

			if service.Spec.Type == v1.ServiceTypeExternalName {
				if service.Spec.ExternalName != "" {
					san = append(san, service.Spec.ExternalName)
				}
			} else if ip := service.Spec.ClusterIP; ip != "" && ip != v1.ClusterIPNone {
				// a headless Service has no address
				san = append(san, ip)
			}

			if len(service.Spec.ExternalIPs) > 0 {
				san = append(san, service.Spec.ExternalIPs...)
			}
		}
	}

	return
}

// ipToName returns the label of a Pod's DNS record (`<ip>.<ns>.pod.<domain>`):
// every dot of an IPv4 address and every colon of an IPv6 address becomes
// a dash, which is what CoreDNS resolves back to the address.
func ipToName(ip string) string {
	return podNameReplacer.Replace(ip)
}

var podNameReplacer = strings.NewReplacer(".", "-", ":", "-")
