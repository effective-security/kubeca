package controller

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/kubeca/internal/k8snames"
	csrapi "github.com/effective-security/xpki/csr"
	capi "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// serviceAccountPrefix starts the username of a ServiceAccount token.
	serviceAccountPrefix = "system:serviceaccount:"
	// podServiceAccountField is the Pod field selector of the API server.
	podServiceAccountField = "spec.serviceAccountName"
	spiffeScheme           = "spiffe"
)

// trustDomainRegexp matches the trust-domain label boundaries enforced by
// ClusterIssuer.spec.spiffe.trustDomain: lower-case DNS labels with no leading
// or trailing dash or dot, and no empty labels.
var trustDomainRegexp = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

// evaluateNames returns "" when every name of the CSR is one the
// requesting ServiceAccount may carry, else a message naming the first
// offending names (ROADMAP, "CSR approval policy"): the requester must be
// a ServiceAccount; allowed are the names of the Pods of that
// ServiceAccount in its namespace (internal/k8snames: Pod IP and DNS name,
// hostname/subdomain, selecting Services and their IPs), the canonical
// SPIFFE ID spiffe://<any trust domain>/ns/<ns>/sa/<sa>, and AllowedNames.
// An error is returned only for API failures.
func (r *CertificateSigningRequestSigningReconciler) evaluateNames(ctx context.Context, csr *capi.CertificateSigningRequest) (string, error) {
	namespace, serviceAccount, ok := parseServiceAccount(csr.Spec.Username)
	if !ok {
		return fmt.Sprintf("requester %q is not a ServiceAccount", csr.Spec.Username), nil
	}
	request, err := csrapi.ParsePEM(csr.Spec.Request)
	if err != nil {
		return "unable to parse the CSR: " + err.Error(), nil
	}

	var pods corev1.PodList
	if err := r.APIReader.List(ctx, &pods, client.InNamespace(namespace), client.MatchingFields{podServiceAccountField: serviceAccount}); err != nil {
		return "", errors.WithMessagef(err, "unable to list the Pods of %s", csr.Spec.Username)
	}
	var services corev1.ServiceList
	if err := r.List(ctx, &services, client.InNamespace(namespace)); err != nil {
		return "", errors.WithMessagef(err, "unable to list the Services of namespace %q", namespace)
	}
	// DNS names and emails compare case-insensitively, addresses by value,
	// URIs exactly: a URI path is case-sensitive, so another case is
	// another identity
	allowed, allowedIPs, allowedURIs := sets.New[string](), sets.New[string](), sets.New[string]()
	insert := func(name string) {
		if ip := net.ParseIP(name); ip != nil {
			allowedIPs.Insert(ip.String())
			return
		}
		allowed.Insert(strings.ToLower(name))
	}
	for _, name := range r.AllowedNames {
		insert(name)
		allowedURIs.Insert(name)
	}
	opts := k8snames.Options{ClusterDomain: r.ClusterDomain, IncludeUnqualified: true}
	for i := range pods.Items {
		pod := &pods.Items[i]
		for _, ip := range k8snames.PodIPs(pod) {
			insert(ip)
		}
		for _, name := range k8snames.ForPod(pod, services.Items, opts).All() {
			insert(name)
		}
	}

	var offending []string
	if cn := request.Subject.CommonName; cn != "" && !allowed.Has(strings.ToLower(cn)) {
		offending = append(offending, "common name "+cn)
	}
	for _, name := range request.DNSNames {
		if !allowed.Has(strings.ToLower(name)) {
			offending = append(offending, "DNS name "+name)
		}
	}
	for _, ip := range request.IPAddresses {
		if !allowedIPs.Has(ip.String()) {
			offending = append(offending, "IP address "+ip.String())
		}
	}
	for _, u := range request.URIs {
		if !isSPIFFEID(u, namespace, serviceAccount) && !allowedURIs.Has(u.String()) {
			offending = append(offending, "URI "+u.String())
		}
	}
	for _, email := range request.EmailAddresses {
		if !allowed.Has(strings.ToLower(email)) {
			offending = append(offending, "email address "+email)
		}
	}
	if len(offending) == 0 {
		return "", nil
	}
	return fmt.Sprintf("%s may not have: %s", csr.Spec.Username, strings.Join(offending, ", ")), nil
}

// parseServiceAccount splits system:serviceaccount:<ns>:<name>.
func parseServiceAccount(username string) (namespace, name string, ok bool) {
	rest, found := strings.CutPrefix(username, serviceAccountPrefix)
	if !found {
		return "", "", false
	}
	namespace, name, found = strings.Cut(rest, ":")
	return namespace, name, found && namespace != "" && name != ""
}

// isSPIFFEID reports whether u is exactly the canonical
// spiffe://<trust domain>/ns/<ns>/sa/<sa> of the ServiceAccount: a
// well-formed trust domain and nothing else, no user info, port, query,
// fragment or percent-encoding, which would be a different identity to a
// verifier that compares strings (SPIFFE forbids them).
func isSPIFFEID(u *url.URL, namespace, serviceAccount string) bool {
	return u.Scheme == spiffeScheme && trustDomainRegexp.MatchString(u.Host) &&
		u.String() == k8snames.SPIFFEID(u.Host, namespace, serviceAccount)
}
