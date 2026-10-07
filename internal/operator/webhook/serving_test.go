package webhook_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/effective-security/kubeca/internal/operator/webhook"
	"github.com/effective-security/kubeca/internal/testauthority"
	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clocktesting "k8s.io/utils/clock/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestServingCertificate(t *testing.T) {
	ca := testauthority.New(t)
	scheme := runtime.NewScheme()
	require.NoError(t, admissionv1.AddToScheme(scheme))
	cfg := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "kubeca-pod-injector"},
		Webhooks: []admissionv1.MutatingWebhook{
			{Name: "pods.kubeca.effectivesecurity", ClientConfig: admissionv1.WebhookClientConfig{CABundle: []byte("old")}},
			{Name: "other.kubeca.effectivesecurity"},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cfg).Build()
	dir := filepath.Join(t.TempDir(), "certs")
	clk := clocktesting.NewFakeClock(time.Now())
	s := &webhook.ServingCertificate{
		Authority:   ca.Authority,
		Client:      c,
		Reader:      c,
		IssuerLabel: testauthority.IssuerLabel,
		Profile:     testauthority.ProfileWebhook,
		DNSNames:    []string{"kubeca-webhook.kubeca.svc", "kubeca-webhook.kubeca.svc.cluster.local"},
		CertDir:     dir,
		ConfigName:  "kubeca-pod-injector",
		Clock:       clk,
	}
	require.NoError(t, s.Issue(context.Background()))

	keyInfo, err := os.Stat(filepath.Join(dir, "tls.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm())
	certPEM, err := os.ReadFile(filepath.Join(dir, "tls.crt"))
	require.NoError(t, err)
	chain, err := certutil.ParseChainFromPEM(certPEM)
	require.NoError(t, err)
	require.Len(t, chain, 2)
	assert.Equal(t, "kubeca-webhook.kubeca.svc", chain[0].Subject.CommonName)
	assert.Equal(t, s.DNSNames, chain[0].DNSNames)
	assert.Equal(t, 168*time.Hour, chain[0].NotAfter.Sub(chain[0].NotBefore), "webhook profile expiry")
	keyPEM, err := os.ReadFile(filepath.Join(dir, "tls.key"))
	require.NoError(t, err)
	_, err = certutil.ParsePrivateKeyPEM(keyPEM)
	require.NoError(t, err)

	var got admissionv1.MutatingWebhookConfiguration
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: "kubeca-pod-injector"}, &got))
	for _, w := range got.Webhooks {
		assert.Equal(t, ca.RootPEM(), string(w.ClientConfig.CABundle), w.Name)
	}

	// a second issuance replaces the files and leaves the configuration alone
	version := got.ResourceVersion
	require.NoError(t, s.Issue(context.Background()))
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: "kubeca-pod-injector"}, &got))
	assert.Equal(t, version, got.ResourceVersion)
	require.NoError(t, s.EnsureCABundle(context.Background()))
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: "kubeca-pod-injector"}, &got))
	assert.Equal(t, version, got.ResourceVersion)

	// a helm upgrade re-renders the configuration without the caBundle:
	// the check restores it
	got.Webhooks[0].ClientConfig.CABundle = nil
	require.NoError(t, c.Update(context.Background(), &got))
	require.NoError(t, s.EnsureCABundle(context.Background()))
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: "kubeca-pod-injector"}, &got))
	assert.Equal(t, ca.RootPEM(), string(got.Webhooks[0].ClientConfig.CABundle))
	renewedPEM, err := os.ReadFile(filepath.Join(dir, "tls.crt"))
	require.NoError(t, err)
	assert.NotEqual(t, string(certPEM), string(renewedPEM))

	// Start renews after two thirds of the lifetime and stops with the context
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	require.Eventually(t, func() bool { return clk.HasWaiters() }, 5*time.Second, 10*time.Millisecond)
	clk.Step(112*time.Hour + time.Minute)
	require.Eventually(t, func() bool {
		pem, err := os.ReadFile(filepath.Join(dir, "tls.crt"))
		return err == nil && string(pem) != string(renewedPEM)
	}, 5*time.Second, 10*time.Millisecond)
	cancel()
	require.NoError(t, <-done)
	assert.False(t, s.NeedLeaderElection())

	// errors
	noNames := &webhook.ServingCertificate{Authority: ca.Authority, IssuerLabel: testauthority.IssuerLabel, Profile: "webhook", CertDir: dir, Clock: clk}
	err = noNames.Issue(context.Background())
	require.Error(t, err)
	assert.Equal(t, "webhook: no DNS name for the serving certificate", err.Error())
	bad := &webhook.ServingCertificate{Authority: ca.Authority, IssuerLabel: "nope", Profile: "webhook", DNSNames: []string{"x"}, CertDir: dir, Clock: clk}
	err = bad.Issue(context.Background())
	require.Error(t, err)
	assert.Equal(t, `webhook issuer "nope": issuer not found: nope`, err.Error())
	bad = &webhook.ServingCertificate{Authority: ca.Authority, IssuerLabel: testauthority.IssuerLabel, Profile: "webhook", DNSNames: []string{"evil.example.org"}, CertDir: dir, Clock: clk}
	err = bad.Issue(context.Background())
	require.Error(t, err)
	assert.Equal(t, "unable to sign the webhook certificate with kubeca.svc/webhook: DNS Name does not match allowed list: evil.example.org", err.Error())
	missing := &webhook.ServingCertificate{Authority: ca.Authority, Client: c, Reader: c, IssuerLabel: testauthority.IssuerLabel, Profile: "webhook", DNSNames: s.DNSNames, CertDir: dir, ConfigName: "missing", Clock: clk}
	err = missing.Issue(context.Background())
	require.Error(t, err)
	assert.Equal(t, `unable to get MutatingWebhookConfiguration "missing": mutatingwebhookconfigurations.admissionregistration.k8s.io "missing" not found`, err.Error())
}

// TestServingCertificateCABundleFailure: a renewal whose caBundle patch
// fails keeps the renewed certificate and its normal schedule; the patch
// is retried by the minute check, not by issuing a certificate every
// minute.
func TestServingCertificateCABundleFailure(t *testing.T) {
	ca := testauthority.New(t)
	scheme := runtime.NewScheme()
	require.NoError(t, admissionv1.AddToScheme(scheme))
	cfg := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "kubeca-pod-injector"},
		Webhooks:   []admissionv1.MutatingWebhook{{Name: "pods.kubeca.effectivesecurity"}},
	}
	var patchFails atomic.Bool
	patches := atomic.Int32{}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cfg).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				patches.Add(1)
				if patchFails.Load() {
					return errors.New("admission API unavailable")
				}
				return c.Patch(ctx, obj, patch, opts...)
			},
		}).Build()
	dir := filepath.Join(t.TempDir(), "certs")
	clk := clocktesting.NewFakeClock(time.Now())
	s := &webhook.ServingCertificate{
		Authority:   ca.Authority,
		Client:      c,
		Reader:      c,
		IssuerLabel: testauthority.IssuerLabel,
		Profile:     testauthority.ProfileWebhook,
		DNSNames:    []string{"kubeca-webhook.kubeca.svc"},
		CertDir:     dir,
		ConfigName:  "kubeca-pod-injector",
		Clock:       clk,
	}
	require.NoError(t, s.Issue(context.Background()))
	readCert := func() string {
		t.Helper()
		pem, err := os.ReadFile(filepath.Join(dir, "tls.crt"))
		require.NoError(t, err)
		return string(pem)
	}
	first := readCert()

	// the configuration loses its caBundle and every patch fails from now on
	var got admissionv1.MutatingWebhookConfiguration
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: cfg.Name}, &got))
	got.Webhooks[0].ClientConfig.CABundle = nil
	require.NoError(t, c.Update(context.Background(), &got))
	patchFails.Store(true)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	step := func(d time.Duration) {
		t.Helper()
		require.Eventually(t, clk.HasWaiters, 5*time.Second, 10*time.Millisecond)
		clk.Step(d)
	}
	// past two thirds of the 168 h lifetime: renewed once
	step(112*time.Hour + time.Minute)
	require.Eventually(t, func() bool { return readCert() != first }, 5*time.Second, 10*time.Millisecond)
	renewed := readCert()
	// five minutes of failing caBundle checks: patched again each minute,
	// never re-issued (the old loop issued a certificate every minute)
	for range 5 {
		before := patches.Load()
		step(time.Minute)
		require.Eventually(t, func() bool { return patches.Load() > before }, 5*time.Second, 10*time.Millisecond)
	}
	assert.Equal(t, renewed, readCert(), "no new certificate while the caBundle patch fails")
	cancel()
	require.NoError(t, <-done)
}
