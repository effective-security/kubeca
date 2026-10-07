package policy_test

import (
	"testing"
	"time"

	"github.com/effective-security/kubeca/api/v1alpha1"
	"github.com/effective-security/kubeca/internal/operator/policy"
	"github.com/effective-security/xpki/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ptr[T any](v T) *T { return &v }

func examplePolicy() *v1alpha1.IssuerPolicy {
	return &v1alpha1.IssuerPolicy{
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				v1alpha1.LabelEnabled: v1alpha1.TrueValue,
			},
		},
		MaxDuration: &metav1.Duration{Duration: 24 * time.Hour},
		AllowedDNSNames: ptr([]string{
			`^[a-z0-9-]+\.${NAMESPACE}\.svc(\.${CLUSTER_DOMAIN})?$`,
			`^[a-z0-9-]+\.[a-z0-9-]+\.${NAMESPACE}\.svc(\.${CLUSTER_DOMAIN})?$`,
			`^\*\.[a-z0-9-]+\.${NAMESPACE}\.svc(\.${CLUSTER_DOMAIN})?$`,
			`^[0-9a-f-]+\.${NAMESPACE}\.pod\.${CLUSTER_DOMAIN}$`,
			`^localhost$`,
		}),
		AllowedURIs: ptr([]string{
			`^spiffe://example\.org/ns/${NAMESPACE}/sa/${SERVICE_ACCOUNT}$`,
		}),
		AllowedEmailAddresses: ptr([]string{}),
		AllowIPAddresses:      true,
	}
}

func parseSAN(t *testing.T, names ...string) *csr.SAN {
	t.Helper()
	san, err := csr.ParseSAN(names)
	require.NoError(t, err)
	return san
}

func TestEvaluate(t *testing.T) {
	t.Parallel()
	enabled := map[string]string{v1alpha1.LabelEnabled: v1alpha1.TrueValue}

	tcases := []struct {
		name   string
		policy *v1alpha1.IssuerPolicy
		req    policy.Request
		want   *policy.Violation
	}{
		{
			name:   "nil policy allows everything",
			policy: nil,
			req:    policy.Request{Namespace: "shop", SAN: parseSAN(t, "anything.example.com", "10.0.0.1")},
		},
		{
			name:   "namespace not selected",
			policy: examplePolicy(),
			req:    policy.Request{Namespace: "shop", SAN: parseSAN(t, "web.shop.svc")},
			want:   &policy.Violation{Reason: policy.ReasonNamespaceNotAllowed, Message: `namespace "shop" is not selected by the issuer policy`},
		},
		{
			name:   "all names allowed",
			policy: examplePolicy(),
			req: policy.Request{
				Namespace:       "shop",
				NamespaceLabels: enabled,
				Name:            "web-tls",
				ServiceAccount:  "web",
				ClusterDomain:   "cluster.local",
				SAN: parseSAN(t,
					"web.shop.svc.cluster.local", "web.shop.svc", "pod-1.web.shop.svc", "*.db.shop.svc.cluster.local",
					"10-1-2-3.shop.pod.cluster.local", "fd00-10-244--2.shop.pod.cluster.local", "localhost",
					"spiffe://example.org/ns/shop/sa/web", "10.1.2.3"),
			},
		},
		{
			name:   "namespace placeholder is quoted and substituted",
			policy: examplePolicy(),
			req:    policy.Request{Namespace: "shop", NamespaceLabels: enabled, SAN: parseSAN(t, "web.other.svc")},
			want:   &policy.Violation{Reason: policy.ReasonNameNotAllowed, Message: `DNS name "web.other.svc" is not allowed by the issuer policy`},
		},
		{
			name:   "cluster domain placeholder",
			policy: examplePolicy(),
			req: policy.Request{
				Namespace:       "shop",
				NamespaceLabels: enabled,
				ClusterDomain:   "corp.internal",
				SAN:             parseSAN(t, "web.shop.svc.corp.internal", "10-1-2-3.shop.pod.corp.internal", "web.shop.svc.cluster.local"),
			},
			want: &policy.Violation{Reason: policy.ReasonNameNotAllowed, Message: `DNS name "web.shop.svc.cluster.local" is not allowed by the issuer policy`},
		},
		{
			name:   "cluster domain placeholder is quoted",
			policy: examplePolicy(),
			req:    policy.Request{Namespace: "shop", NamespaceLabels: enabled, ClusterDomain: "corp.internal", SAN: parseSAN(t, "web.shop.svc.corpxinternal")},
			want:   &policy.Violation{Reason: policy.ReasonNameNotAllowed, Message: `DNS name "web.shop.svc.corpxinternal" is not allowed by the issuer policy`},
		},
		{
			name:   "wildcard needs an expression that matches the leading *.",
			policy: examplePolicy(),
			req:    policy.Request{Namespace: "shop", NamespaceLabels: enabled, SAN: parseSAN(t, "*.shop.svc")},
			want:   &policy.Violation{Reason: policy.ReasonNameNotAllowed, Message: `DNS name "*.shop.svc" is not allowed by the issuer policy`},
		},
		{
			name:   "service account placeholder",
			policy: examplePolicy(),
			req:    policy.Request{Namespace: "shop", NamespaceLabels: enabled, ServiceAccount: "web", SAN: parseSAN(t, "spiffe://example.org/ns/shop/sa/other")},
			want:   &policy.Violation{Reason: policy.ReasonNameNotAllowed, Message: `URI "spiffe://example.org/ns/shop/sa/other" is not allowed by the issuer policy`},
		},
		{
			name:   "common name checked against allowedDNSNames",
			policy: examplePolicy(),
			req:    policy.Request{Namespace: "shop", NamespaceLabels: enabled, ClusterDomain: "cluster.local", CommonName: "web.shop.svc.cluster.local", SAN: parseSAN(t, "web.shop.svc")},
		},
		{
			name:   "common name not allowed",
			policy: examplePolicy(),
			req:    policy.Request{Namespace: "shop", NamespaceLabels: enabled, CommonName: "evil.example.org", SAN: parseSAN(t, "web.shop.svc")},
			want:   &policy.Violation{Reason: policy.ReasonNameNotAllowed, Message: `common name "evil.example.org" is not allowed by the issuer policy`},
		},
		{
			name:   "common name checked without names",
			policy: examplePolicy(),
			req:    policy.Request{Namespace: "shop", NamespaceLabels: enabled, CommonName: "evil.example.org"},
			want:   &policy.Violation{Reason: policy.ReasonNameNotAllowed, Message: `common name "evil.example.org" is not allowed by the issuer policy`},
		},
		{
			name:   "absent DNS list allows any common name",
			policy: &v1alpha1.IssuerPolicy{},
			req:    policy.Request{Namespace: "shop", CommonName: "shop api"},
		},
		{
			name:   "empty DNS list denies the common name",
			policy: &v1alpha1.IssuerPolicy{AllowedDNSNames: ptr([]string{})},
			req:    policy.Request{Namespace: "shop", CommonName: "web.shop.svc"},
			want:   &policy.Violation{Reason: policy.ReasonNameNotAllowed, Message: `common name "web.shop.svc" is not allowed by the issuer policy`},
		},
		{
			name:   "empty list denies the type",
			policy: examplePolicy(),
			req:    policy.Request{Namespace: "shop", NamespaceLabels: enabled, SAN: parseSAN(t, "ops@example.org")},
			want:   &policy.Violation{Reason: policy.ReasonNameNotAllowed, Message: `email address "ops@example.org" is not allowed by the issuer policy`},
		},
		{
			name:   "absent list allows the type",
			policy: &v1alpha1.IssuerPolicy{AllowIPAddresses: false},
			req:    policy.Request{Namespace: "shop", SAN: parseSAN(t, "ops@example.org", "anything.example.com", "spiffe://x/y")},
		},
		{
			name:   "IP addresses denied by default",
			policy: &v1alpha1.IssuerPolicy{},
			req:    policy.Request{Namespace: "shop", SAN: parseSAN(t, "web.shop.svc", "10.1.2.3")},
			want:   &policy.Violation{Reason: policy.ReasonNameNotAllowed, Message: `IP address 10.1.2.3 is not allowed by the issuer policy`},
		},
		{
			name:   "no names",
			policy: examplePolicy(),
			req:    policy.Request{Namespace: "shop", NamespaceLabels: enabled},
		},
		{
			name:   "bad regex",
			policy: &v1alpha1.IssuerPolicy{AllowedDNSNames: ptr([]string{`^(`})},
			req:    policy.Request{Namespace: "shop", SAN: parseSAN(t, "web.shop.svc")},
			want:   &policy.Violation{Reason: policy.ReasonInvalidPolicy, Message: "DNS name expression \"^(\": error parsing regexp: missing closing ): `^(`"},
		},
		{
			name: "bad selector",
			policy: &v1alpha1.IssuerPolicy{NamespaceSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "k", Operator: "Bogus"}},
			}},
			req:  policy.Request{Namespace: "shop"},
			want: &policy.Violation{Reason: policy.ReasonInvalidPolicy, Message: `namespaceSelector: "Bogus" is not a valid label selector operator`},
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := policy.Evaluate(tc.policy, tc.req)
			assert.Equal(t, tc.want, got)
			if tc.want != nil {
				assert.Equal(t, tc.want.Reason+": "+tc.want.Message, got.Error())
			}
		})
	}
}

func TestCompile(t *testing.T) {
	t.Parallel()
	require.NoError(t, policy.Compile(nil))
	require.NoError(t, policy.Compile(examplePolicy()))

	err := policy.Compile(&v1alpha1.IssuerPolicy{AllowedURIs: ptr([]string{`^spiffe://${NAMESPACE}/(`})})
	require.Error(t, err)
	assert.Equal(t, "allowedURIs: \"^spiffe://${NAMESPACE}/(\": error parsing regexp: missing closing ): `^spiffe://ns/(`", err.Error())

	// several invalid lists: always the first in field order, so the
	// ClusterIssuer condition message is stable across reconciles
	broken := &v1alpha1.IssuerPolicy{
		AllowedDNSNames:       ptr([]string{`^(`}),
		AllowedURIs:           ptr([]string{`^[`}),
		AllowedEmailAddresses: ptr([]string{`^*`}),
	}
	for range 50 {
		err = policy.Compile(broken)
		require.Error(t, err)
		assert.Equal(t, "allowedDNSNames: \"^(\": error parsing regexp: missing closing ): `^(`", err.Error())
	}

	err = policy.Compile(&v1alpha1.IssuerPolicy{NamespaceSelector: &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "k", Operator: "Bogus"}},
	}})
	require.Error(t, err)
	assert.Equal(t, `namespaceSelector: "Bogus" is not a valid label selector operator`, err.Error())
}

func TestBoundDuration(t *testing.T) {
	t.Parallel()
	tcases := []struct {
		requested, expiry, maxDuration, want time.Duration
	}{
		{0, 24 * time.Hour, 0, 24 * time.Hour},
		{12 * time.Hour, 24 * time.Hour, 0, 12 * time.Hour},
		{48 * time.Hour, 24 * time.Hour, 0, 24 * time.Hour},
		{24 * time.Hour, 24 * time.Hour, 12 * time.Hour, 12 * time.Hour},
		{0, 24 * time.Hour, 8 * time.Hour, 8 * time.Hour},
		{6 * time.Hour, 24 * time.Hour, 8 * time.Hour, 6 * time.Hour},
		{6 * time.Hour, 0, 0, 6 * time.Hour},
	}
	for _, tc := range tcases {
		assert.Equal(t, tc.want, policy.BoundDuration(tc.requested, tc.expiry, tc.maxDuration), "%v", tc)
	}
	assert.Equal(t, time.Duration(0), policy.MaxDuration(nil))
	assert.Equal(t, time.Duration(0), policy.MaxDuration(&v1alpha1.IssuerPolicy{}))
	assert.Equal(t, time.Hour, policy.MaxDuration(&v1alpha1.IssuerPolicy{MaxDuration: &metav1.Duration{Duration: time.Hour}}))
}
