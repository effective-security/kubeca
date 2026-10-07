package webhook

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/csr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// CertFileName and KeyFileName are what the controller-runtime webhook
	// server reads from its CertDir.
	CertFileName = "tls.crt"
	KeyFileName  = "tls.key"

	certFileMode = 0o644
	keyFileMode  = 0o600
	certDirMode  = 0o700

	pemTypeCertificateRequest = "CERTIFICATE REQUEST"

	// renewFraction: the serving certificate is renewed after two thirds
	// of its lifetime.
	renewFraction = 3
	// retryInterval is the delay after a failed renewal.
	retryInterval = time.Minute
	// minRenewal bounds the renewal delay from below.
	minRenewal = 10 * time.Second
	// caBundleCheckInterval is how often the caBundle of the configuration
	// is compared with the root bundle (a helm upgrade re-renders the
	// configuration without it).
	caBundleCheckInterval = time.Minute
)

// ServingCertificate issues, stores and renews the webhook's TLS
// certificate and keeps the MutatingWebhookConfiguration's caBundle in
// step. It is a manager Runnable that runs on every replica.
type ServingCertificate struct {
	Authority *authority.Authority
	// Client patches the MutatingWebhookConfiguration; it reads it with
	// an uncached Get when Reader is set.
	Client client.Client
	Reader client.Reader
	// IssuerLabel and Profile select the signer; DNSNames are the
	// webhook Service names.
	IssuerLabel string
	Profile     string
	DNSNames    []string
	// CertDir receives tls.crt and tls.key.
	CertDir string
	// ConfigName is the MutatingWebhookConfiguration to patch; "" skips
	// the patch.
	ConfigName string
	// Clock is the time source; tests inject a fake.
	Clock clock.WithTicker

	mu sync.Mutex
	// renewAt is when Start issues the next certificate; caBundle the
	// root bundle of the last issuance.
	renewAt  time.Time
	caBundle []byte
}

// Issue signs a new certificate, writes the files and patches the
// caBundle. Call it before the manager starts so the webhook server finds
// its files.
func (s *ServingCertificate) Issue(ctx context.Context) error {
	if err := s.issue(ctx); err != nil {
		return err
	}
	return s.EnsureCABundle(ctx)
}

// issue signs a new certificate, writes the files and schedules the next
// renewal; the caBundle is left to the caller.
func (s *ServingCertificate) issue(ctx context.Context) error {
	if len(s.DNSNames) == 0 {
		return errors.New("webhook: no DNS name for the serving certificate")
	}
	issuer, err := s.Authority.GetIssuerByLabel(s.IssuerLabel)
	if err != nil {
		return errors.WithMessagef(err, "webhook issuer %q", s.IssuerLabel)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.WithMessage(err, "unable to generate the webhook key")
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: s.DNSNames[0]},
		DNSNames: s.DNSNames,
	}, key)
	if err != nil {
		return errors.WithMessage(err, "unable to create the webhook CSR")
	}
	leaf, raw, err := issuer.Sign(csr.SignRequest{
		Request: string(pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificateRequest, Bytes: der})),
		Profile: s.Profile,
		Subject: &csr.X509Subject{CommonName: s.DNSNames[0]},
	})
	if err != nil {
		return errors.WithMessagef(err, "unable to sign the webhook certificate with %s/%s", s.IssuerLabel, s.Profile)
	}
	keyPEM, err := certutil.EncodePrivateKeyToPEM(key)
	if err != nil {
		return errors.WithMessage(err, "unable to encode the webhook key")
	}
	certPEM := strings.TrimSpace(string(raw)) + "\n"
	if chain := strings.TrimSpace(issuer.PEM()); chain != "" {
		certPEM += chain + "\n"
	}
	if err := os.MkdirAll(s.CertDir, certDirMode); err != nil {
		return errors.WithMessagef(err, "unable to create %s", s.CertDir)
	}
	// the key is written first and both files atomically, so the file
	// watcher of the webhook server never loads a mismatched pair
	if err := writeAtomic(filepath.Join(s.CertDir, KeyFileName), keyPEM, keyFileMode); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(s.CertDir, CertFileName), []byte(certPEM), certFileMode); err != nil {
		return err
	}
	root := strings.TrimSpace(issuer.Bundle().RootCertPEM)
	if root == "" {
		root = strings.TrimSpace(string(s.Authority.RootBundle))
	}
	now := s.Clock.Now()
	s.mu.Lock()
	s.renewAt = now.Add(leaf.NotAfter.Sub(now) - leaf.NotAfter.Sub(now)/renewFraction)
	s.caBundle = []byte(root + "\n")
	s.mu.Unlock()
	logger.ContextKV(ctx, xlog.INFO,
		"status", "webhook_certificate_issued",
		"issuer", s.IssuerLabel,
		"profile", s.Profile,
		"serial", leaf.SerialNumber.String(),
		"not_after", leaf.NotAfter.UTC().Format(time.RFC3339),
		"file", filepath.Join(s.CertDir, CertFileName))
	return nil
}

// EnsureCABundle patches the configuration's caBundle when it differs
// from the root bundle of the last issuance; a no-op without ConfigName.
func (s *ServingCertificate) EnsureCABundle(ctx context.Context) error {
	s.mu.Lock()
	caBundle := s.caBundle
	s.mu.Unlock()
	if s.ConfigName == "" || len(caBundle) == 0 {
		return nil
	}
	return s.patchCABundle(ctx, caBundle)
}

// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations,verbs=get;patch

// patchCABundle sets clientConfig.caBundle of every webhook of the
// configuration.
func (s *ServingCertificate) patchCABundle(ctx context.Context, caBundle []byte) error {
	reader := s.Reader
	if reader == nil {
		reader = s.Client
	}
	var cfg admissionv1.MutatingWebhookConfiguration
	if err := reader.Get(ctx, client.ObjectKey{Name: s.ConfigName}, &cfg); err != nil {
		return errors.WithMessagef(err, "unable to get MutatingWebhookConfiguration %q", s.ConfigName)
	}
	orig := cfg.DeepCopy()
	changed := false
	for i := range cfg.Webhooks {
		if string(cfg.Webhooks[i].ClientConfig.CABundle) != string(caBundle) {
			cfg.Webhooks[i].ClientConfig.CABundle = caBundle
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := s.Client.Patch(ctx, &cfg, client.MergeFrom(orig)); err != nil {
		return errors.WithMessagef(err, "unable to patch MutatingWebhookConfiguration %q", s.ConfigName)
	}
	logger.ContextKV(ctx, xlog.INFO, "status", "webhook_ca_bundle_patched", "name", s.ConfigName)
	return nil
}

// NeedLeaderElection is false: every replica serves the webhook.
func (s *ServingCertificate) NeedLeaderElection() bool {
	return false
}

// Start renews the certificate at two thirds of its lifetime and checks
// the caBundle every minute until ctx ends; a failed renewal is retried
// every minute. Whether a renewal is due is decided by the clock on every
// wake-up, not by which channel fired.
func (s *ServingCertificate) Start(ctx context.Context) error {
	ticker := s.Clock.NewTicker(caBundleCheckInterval)
	defer ticker.Stop()
	for {
		s.mu.Lock()
		renewAt := s.renewAt
		s.mu.Unlock()
		now := s.Clock.Now()
		if !now.Before(renewAt) {
			if err := s.issue(ctx); err != nil {
				logger.ContextKV(ctx, xlog.ERROR, "reason", "unable to renew the webhook certificate", "err", err)
				s.mu.Lock()
				s.renewAt = now.Add(retryInterval)
				s.mu.Unlock()
				continue
			}
			// the certificate is renewed and its next renewal scheduled; a
			// caBundle that cannot be patched is retried by the ticker, not
			// by a new certificate every minute
			if err := s.EnsureCABundle(ctx); err != nil {
				logger.ContextKV(ctx, xlog.ERROR, "reason", "unable to patch the webhook caBundle after the renewal", "err", err)
			}
			continue
		}
		timer := s.Clock.NewTimer(max(renewAt.Sub(now), minRenewal))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-ticker.C():
			timer.Stop()
			if err := s.EnsureCABundle(ctx); err != nil {
				logger.ContextKV(ctx, xlog.ERROR, "reason", "unable to check the webhook caBundle", "err", err)
			}
		case <-timer.C():
		}
	}
}

// writeAtomic writes data to a temporary file next to path and renames it.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return errors.WithMessagef(err, "unable to create %s", path)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return errors.WithMessagef(err, "unable to write %s", path)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return errors.WithMessagef(err, "unable to chmod %s", path)
	}
	if err := tmp.Close(); err != nil {
		return errors.WithMessagef(err, "unable to close %s", path)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return errors.WithMessagef(err, "unable to rename %s", path)
	}
	return nil
}
