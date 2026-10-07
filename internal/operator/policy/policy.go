package policy

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/kubeca/api/v1alpha1"
	"github.com/effective-security/kubeca/internal/k8snames"
	"github.com/effective-security/xpki/csr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Placeholders substituted, regex-quoted, in the allowed-name expressions.
const (
	PlaceholderNamespace      = "${NAMESPACE}"
	PlaceholderName           = "${NAME}"
	PlaceholderServiceAccount = "${SERVICE_ACCOUNT}"
	PlaceholderClusterDomain  = "${CLUSTER_DOMAIN}"
)

// Name types reported in a Violation.
const (
	TypeCommonName = "common name"
	TypeDNS        = "DNS name"
	TypeURI        = "URI"
	TypeEmail      = "email address"
	TypeIP         = "IP address"
)

// Request is what the policy is evaluated against.
type Request struct {
	// Namespace and NamespaceLabels of the Certificate.
	Namespace       string
	NamespaceLabels map[string]string
	// Name of the Certificate (${NAME}).
	Name string
	// ServiceAccount of the Pod the Certificate belongs to
	// (${SERVICE_ACCOUNT}); empty for a direct Certificate.
	ServiceAccount string
	// ClusterDomain is the cluster DNS suffix the operator derives names
	// with (${CLUSTER_DOMAIN}).
	ClusterDomain string
	// CommonName of the subject; checked against allowedDNSNames, since
	// the CA signs it as given and a profile rarely constrains it.
	CommonName string
	// SAN are the parsed, deduplicated names.
	SAN *csr.SAN
}

// Violation is a denied request: the Reason is a CamelCase word for the
// condition, the Message names what was denied.
type Violation struct {
	Reason  string
	Message string
}

// Violation reasons.
const (
	ReasonNamespaceNotAllowed = "NamespaceNotAllowed"
	ReasonNameNotAllowed      = "NameNotAllowed"
	ReasonInvalidPolicy       = "InvalidPolicy"
)

// Error implements error; a *Violation is never a transient error.
func (v *Violation) Error() string {
	return v.Reason + ": " + v.Message
}

// Evaluate returns nil when the request satisfies the policy, else the
// first Violation found. A nil policy allows everything. A policy whose
// selector or regexes do not compile is reported as InvalidPolicy. The
// common name is checked like a DNS name (allowedDNSNames) because it is
// an identity to clients that still read it, while the SAN lists are the
// names a verifier matches.
func Evaluate(p *v1alpha1.IssuerPolicy, req Request) *Violation {
	if p == nil {
		return nil
	}
	if p.NamespaceSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(p.NamespaceSelector)
		if err != nil {
			return &Violation{Reason: ReasonInvalidPolicy, Message: "namespaceSelector: " + err.Error()}
		}
		if !selector.Matches(labels.Set(req.NamespaceLabels)) {
			return &Violation{Reason: ReasonNamespaceNotAllowed, Message: fmt.Sprintf("namespace %q is not selected by the issuer policy", req.Namespace)}
		}
	}
	vars := substitutions(req)
	if req.CommonName != "" {
		if v := checkNames(TypeCommonName, p.AllowedDNSNames, []string{req.CommonName}, vars); v != nil {
			return v
		}
	}
	if req.SAN == nil {
		return nil
	}
	if v := checkNames(TypeDNS, p.AllowedDNSNames, req.SAN.DNSNames, vars); v != nil {
		return v
	}
	uris := make([]string, 0, len(req.SAN.URIs))
	for _, u := range req.SAN.URIs {
		uris = append(uris, u.String())
	}
	if v := checkNames(TypeURI, p.AllowedURIs, uris, vars); v != nil {
		return v
	}
	if v := checkNames(TypeEmail, p.AllowedEmailAddresses, req.SAN.EmailAddresses, vars); v != nil {
		return v
	}
	if len(req.SAN.IPAddresses) > 0 && !p.AllowIPAddresses {
		return &Violation{Reason: ReasonNameNotAllowed, Message: fmt.Sprintf("%s %s is not allowed by the issuer policy", TypeIP, req.SAN.IPAddresses[0])}
	}
	return nil
}

// Compile checks that every expression of the policy is a valid RE2 regex
// after substitution and that the namespace selector is valid; it returns
// the first error. Used by the ClusterIssuer controller.
func Compile(p *v1alpha1.IssuerPolicy) error {
	if p == nil {
		return nil
	}
	if p.NamespaceSelector != nil {
		if _, err := metav1.LabelSelectorAsSelector(p.NamespaceSelector); err != nil {
			return errors.WithMessage(err, "namespaceSelector")
		}
	}
	vars := substitutions(Request{Namespace: "ns", Name: "name", ServiceAccount: "sa", ClusterDomain: k8snames.DefaultClusterDomain})
	// a fixed order: the first error is the same on every call, so the
	// ClusterIssuer condition message does not change between reconciles
	for _, field := range []struct {
		name string
		list *[]string
	}{
		{name: "allowedDNSNames", list: p.AllowedDNSNames},
		{name: "allowedURIs", list: p.AllowedURIs},
		{name: "allowedEmailAddresses", list: p.AllowedEmailAddresses},
	} {
		if field.list == nil {
			continue
		}
		for _, expr := range *field.list {
			if _, err := regexp.Compile(vars.Replace(expr)); err != nil {
				return errors.WithMessagef(err, "%s: %q", field.name, expr)
			}
		}
	}
	return nil
}

// BoundDuration returns the certificate lifetime: the requested duration
// (the profile expiry when zero) bounded by the profile expiry and by the
// policy's maxDuration (ignored when zero).
func BoundDuration(requested, profileExpiry, maxDuration time.Duration) time.Duration {
	lifetime := requested
	if lifetime <= 0 || (profileExpiry > 0 && lifetime > profileExpiry) {
		lifetime = profileExpiry
	}
	if maxDuration > 0 && lifetime > maxDuration {
		lifetime = maxDuration
	}
	return lifetime
}

// MaxDuration returns the policy's maxDuration or 0.
func MaxDuration(p *v1alpha1.IssuerPolicy) time.Duration {
	if p == nil || p.MaxDuration == nil {
		return 0
	}
	return p.MaxDuration.Duration
}

func substitutions(req Request) *strings.Replacer {
	return strings.NewReplacer(
		PlaceholderNamespace, regexp.QuoteMeta(req.Namespace),
		PlaceholderName, regexp.QuoteMeta(req.Name),
		PlaceholderServiceAccount, regexp.QuoteMeta(req.ServiceAccount),
		PlaceholderClusterDomain, regexp.QuoteMeta(req.ClusterDomain),
	)
}

// checkNames returns a Violation for the first name that no expression
// of the allowed list matches. A nil list allows every name; an empty
// list denies every name of the type.
func checkNames(nameType string, allowed *[]string, names []string, vars *strings.Replacer) *Violation {
	if allowed == nil || len(names) == 0 {
		return nil
	}
	expressions := make([]*regexp.Regexp, 0, len(*allowed))
	for _, expr := range *allowed {
		re, err := regexp.Compile(vars.Replace(expr))
		if err != nil {
			return &Violation{Reason: ReasonInvalidPolicy, Message: fmt.Sprintf("%s expression %q: %s", nameType, expr, err.Error())}
		}
		expressions = append(expressions, re)
	}
	for _, name := range names {
		if !matchesAny(expressions, name) {
			return &Violation{Reason: ReasonNameNotAllowed, Message: fmt.Sprintf("%s %q is not allowed by the issuer policy", nameType, name)}
		}
	}
	return nil
}

func matchesAny(expressions []*regexp.Regexp, name string) bool {
	for _, re := range expressions {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}
