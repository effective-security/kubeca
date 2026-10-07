package k8snames

import (
	"fmt"
	"iter"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	// DefaultClusterDomain is the cluster DNS suffix when none is given.
	DefaultClusterDomain = "cluster.local"
	// ListSeparator separates the items of the comma-separated lists the
	// flags and annotations carry.
	ListSeparator = ","
	// DefaultServiceAccount is the ServiceAccount of a Pod that names none.
	DefaultServiceAccount = "default"
)

// Options of the name derivation.
type Options struct {
	// ClusterDomain is the cluster DNS suffix; DefaultClusterDomain when
	// empty.
	ClusterDomain string
	// IncludeUnqualified also returns the `.svc` names without the cluster
	// domain.
	IncludeUnqualified bool
}

func (o Options) domain() string {
	if o.ClusterDomain == "" {
		return DefaultClusterDomain
	}
	return o.ClusterDomain
}

// Names are the DNS names and IP addresses derived for a Pod, in
// derivation order, with no deduplication (xpki's csr.ParseSAN drops
// duplicates).
type Names struct {
	DNS []string
	IPs []string
}

// All returns the DNS names followed by the IPs, as one SAN list.
func (n Names) All() []string {
	return append(append([]string{}, n.DNS...), n.IPs...)
}

// SplitList yields the non-empty, trimmed items of a comma-separated list.
func SplitList(list string) iter.Seq[string] {
	return func(yield func(string) bool) {
		for item := range strings.SplitSeq(list, ListSeparator) {
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

// ServiceNames returns the DNS names of a Service: the cluster-qualified
// name and, with IncludeUnqualified, the `.svc` name.
func ServiceNames(name, namespace string, opts Options) []string {
	names := []string{fmt.Sprintf("%s.%s.svc.%s", name, namespace, opts.domain())}
	if opts.IncludeUnqualified {
		names = append(names, fmt.Sprintf("%s.%s.svc", name, namespace))
	}
	return names
}

// PodIPs returns the addresses of a Pod: status.podIPs (both families of
// a dual-stack Pod), or status.podIP when the list is empty; nil when the
// Pod has no address yet.
func PodIPs(pod *corev1.Pod) []string {
	var ips []string
	for _, ip := range pod.Status.PodIPs {
		if ip.IP != "" {
			ips = append(ips, ip.IP)
		}
	}
	if len(ips) == 0 && pod.Status.PodIP != "" {
		ips = append(ips, pod.Status.PodIP)
	}
	return ips
}

// PodDNSName returns the Pod DNS record `<ip-dashed>.<ns>.pod.<domain>`;
// "" when the Pod has no IP yet.
func PodDNSName(podIP, namespace string, opts Options) string {
	if podIP == "" {
		return ""
	}
	return fmt.Sprintf("%s.%s.pod.%s", IPToLabel(podIP), namespace, opts.domain())
}

// SPIFFEID returns `spiffe://<trustDomain>/ns/<namespace>/sa/<serviceAccount>`,
// or "" when the trust domain is empty.
func SPIFFEID(trustDomain, namespace, serviceAccount string) string {
	if trustDomain == "" {
		return ""
	}
	if serviceAccount == "" {
		serviceAccount = DefaultServiceAccount
	}
	return fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", trustDomain, namespace, serviceAccount)
}

// SelectingServices returns the Services whose selector matches the Pod's
// labels. Services without a selector, nil or empty (Kubernetes treats
// both as externally managed endpoints, and an empty selector would
// otherwise match every Pod), are ignored; Endpoints are not consulted.
func SelectingServices(pod *corev1.Pod, services []corev1.Service) []corev1.Service {
	podLabels := labels.Set(pod.Labels)
	var selecting []corev1.Service
	for _, service := range services {
		if len(service.Spec.Selector) == 0 || service.Namespace != pod.Namespace {
			continue
		}
		selector := labels.Set(service.Spec.Selector).AsSelectorPreValidated()
		if selector.Matches(podLabels) {
			selecting = append(selecting, service)
		}
	}
	return selecting
}

// ForPod returns the DNS names and IPs a Pod is permitted to have, in its
// own right or through the Services that select it: one Pod DNS name per
// Pod address (PodIPs), `<hostname>.<subdomain>.<ns>.svc.<domain>` when
// both are set, and for every selecting Service its names, its
// ExternalName or cluster addresses (ClusterIPs: both families of a
// dual-stack Service; a headless `None` and an empty ClusterIP are
// skipped) and its ExternalIPs. The Pod addresses themselves are not
// returned; callers that want them as IP SANs add PodIPs.
func ForPod(pod *corev1.Pod, services []corev1.Service, opts Options) Names {
	var names Names
	for _, ip := range PodIPs(pod) {
		names.DNS = append(names.DNS, PodDNSName(ip, pod.Namespace, opts))
	}
	if pod.Spec.Hostname != "" && pod.Spec.Subdomain != "" {
		names.DNS = append(names.DNS, fmt.Sprintf("%s.%s.%s.svc.%s", pod.Spec.Hostname, pod.Spec.Subdomain, pod.Namespace, opts.domain()))
		if opts.IncludeUnqualified {
			names.DNS = append(names.DNS, fmt.Sprintf("%s.%s.%s.svc", pod.Spec.Hostname, pod.Spec.Subdomain, pod.Namespace))
		}
	}
	for _, service := range SelectingServices(pod, services) {
		serviceNames := ServiceNamesOf(&service, opts)
		names.DNS = append(names.DNS, serviceNames.DNS...)
		names.IPs = append(names.IPs, serviceNames.IPs...)
	}
	return names
}

// ServiceNamesOf returns the names of one Service: its DNS names, its
// ExternalName (as a DNS name) or ClusterIPs, and its ExternalIPs.
func ServiceNamesOf(service *corev1.Service, opts Options) Names {
	names := Names{DNS: ServiceNames(service.Name, service.Namespace, opts)}
	if service.Spec.Type == corev1.ServiceTypeExternalName {
		if service.Spec.ExternalName != "" {
			names.DNS = append(names.DNS, service.Spec.ExternalName)
		}
	} else {
		names.IPs = append(names.IPs, ClusterIPs(service)...)
	}
	names.IPs = append(names.IPs, service.Spec.ExternalIPs...)
	return names
}

// ClusterIPs returns the cluster addresses of a Service: spec.clusterIPs
// (both families of a dual-stack Service), or spec.clusterIP when the
// list is empty (objects created before dual-stack); nil for a headless
// Service (`None`) and for one with no address.
func ClusterIPs(service *corev1.Service) []string {
	var ips []string
	for _, ip := range service.Spec.ClusterIPs {
		if ip != "" && ip != corev1.ClusterIPNone {
			ips = append(ips, ip)
		}
	}
	if ip := service.Spec.ClusterIP; len(ips) == 0 && ip != "" && ip != corev1.ClusterIPNone {
		ips = append(ips, ip)
	}
	return ips
}

// IPToLabel returns the label of a Pod's DNS record: every dot of an IPv4
// address and every colon of an IPv6 address becomes a dash, which is what
// CoreDNS resolves back to the address.
func IPToLabel(ip string) string {
	return podNameReplacer.Replace(ip)
}

var podNameReplacer = strings.NewReplacer(".", "-", ":", "-")
