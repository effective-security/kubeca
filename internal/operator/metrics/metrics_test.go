package metrics_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/effective-security/kubeca/internal/operator/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	expirationMetric = "kubeca_certificate_expiration_timestamp_seconds"
	renewalMetric    = "kubeca_certificate_renewal_timestamp_seconds"
)

// expect checks the whole exposition of a gauge vector against the given
// sample lines (this test binary is the only writer of the vectors).
func expect(t *testing.T, vec *prometheus.GaugeVec, metric, help string, samples ...string) {
	t.Helper()
	var text strings.Builder
	if len(samples) > 0 {
		fmt.Fprintf(&text, "# HELP %s %s\n# TYPE %s gauge\n", metric, help, metric)
		for _, sample := range samples {
			text.WriteString(sample + "\n")
		}
	}
	require.NoError(t, testutil.CollectAndCompare(vec, strings.NewReader(text.String()), metric))
}

func TestObserveCertificate(t *testing.T) {
	const namespace, name = "shop", "web"
	expirationHelp := "notAfter of the certificate stored for a Certificate, as a Unix time."
	renewalHelp := "Time the Certificate controller will renew the certificate, as a Unix time."
	notAfter := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	renewal := notAfter.Add(-8 * time.Hour)
	expiration := func(issuer, profile string, at time.Time) string {
		return fmt.Sprintf(`%s{issuer=%q,name=%q,namespace=%q,profile=%q} %d`, expirationMetric, issuer, name, namespace, profile, at.Unix())
	}
	renewalSample := fmt.Sprintf(`%s{name=%q,namespace=%q} %d`, renewalMetric, name, namespace, renewal.Unix())

	metrics.ObserveCertificate(namespace, name, "kubeca", "server-24h", true, notAfter, renewal)
	expect(t, metrics.CertificateExpiration, expirationMetric, expirationHelp, expiration("kubeca", "server-24h", notAfter))
	expect(t, metrics.CertificateRenewal, renewalMetric, renewalHelp, renewalSample)
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.CertificateReady.WithLabelValues(namespace, name)))

	// another profile: the series of the old one goes away
	later := notAfter.Add(time.Hour)
	metrics.ObserveCertificate(namespace, name, "kubeca", "peer-24h", true, later, renewal)
	expect(t, metrics.CertificateExpiration, expirationMetric, expirationHelp, expiration("kubeca", "peer-24h", later))

	// another issuer, same profile
	metrics.ObserveCertificate(namespace, name, "other", "peer-24h", false, later, renewal)
	expect(t, metrics.CertificateExpiration, expirationMetric, expirationHelp, expiration("other", "peer-24h", later))
	assert.Equal(t, 0.0, testutil.ToFloat64(metrics.CertificateReady.WithLabelValues(namespace, name)))

	// nothing stored: neither an expiration nor a renewal series
	metrics.ObserveCertificate(namespace, name, "other", "peer-24h", false, time.Time{}, time.Time{})
	expect(t, metrics.CertificateExpiration, expirationMetric, expirationHelp)
	expect(t, metrics.CertificateRenewal, renewalMetric, renewalHelp)

	// forgotten, then observed again under a new profile: only the new series
	metrics.ObserveCertificate(namespace, name, "kubeca", "server-24h", true, notAfter, renewal)
	metrics.ForgetCertificate(namespace, name)
	expect(t, metrics.CertificateExpiration, expirationMetric, expirationHelp)
	expect(t, metrics.CertificateRenewal, renewalMetric, renewalHelp)
	assert.Equal(t, 0, testutil.CollectAndCount(metrics.CertificateReady))
	metrics.ObserveCertificate(namespace, name, "kubeca", "client-24h", true, notAfter, renewal)
	expect(t, metrics.CertificateExpiration, expirationMetric, expirationHelp, expiration("kubeca", "client-24h", notAfter))
	metrics.ForgetCertificate(namespace, name)
}

// TestObserveCertificateConcurrent races the Certificate controller's
// workers on the process-global bookkeeping (make test RACE=true):
// distinct Certificates moving between profiles each end with exactly
// their last series, and one Certificate observed and forgotten from
// several goroutines ends with the series of its last observation only.
func TestObserveCertificateConcurrent(t *testing.T) {
	const (
		namespace = "race"
		shared    = "shared"
		workers   = 8
		rounds    = 50
	)
	notAfter := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	renewal := notAfter.Add(-8 * time.Hour)
	profiles := []string{"peer-24h", "server-24h", "client-24h"}
	distinct := func(worker int) (name, profile string, at time.Time) {
		return fmt.Sprintf("distinct-%d", worker), profiles[worker%len(profiles)], notAfter.Add(time.Duration(worker) * time.Hour)
	}
	// series removes the expiration series of one Certificate and
	// returns how many there were
	series := func(name string) int {
		return metrics.CertificateExpiration.DeletePartialMatch(prometheus.Labels{"namespace": namespace, "name": name})
	}

	var wg sync.WaitGroup
	for worker := range workers {
		wg.Go(func() {
			name, profile, at := distinct(worker)
			for round := range rounds {
				metrics.ObserveCertificate(namespace, name, "kubeca", profiles[round%len(profiles)], round%2 == 0, notAfter, renewal)
			}
			metrics.ObserveCertificate(namespace, name, "kubeca", profile, true, at, renewal)
		})
		wg.Go(func() {
			issuer := fmt.Sprintf("issuer-%d", worker)
			for round := range rounds {
				if round%5 == 4 {
					metrics.ForgetCertificate(namespace, shared)
					continue
				}
				metrics.ObserveCertificate(namespace, shared, issuer, profiles[round%len(profiles)], true, notAfter, renewal)
			}
		})
	}
	wg.Wait()

	for worker := range workers {
		name, profile, at := distinct(worker)
		assert.Equal(t, float64(at.Unix()), testutil.ToFloat64(metrics.CertificateExpiration.WithLabelValues(namespace, name, "kubeca", profile)), name)
		assert.Equal(t, 1, series(name), name)
		metrics.ForgetCertificate(namespace, name)
	}
	metrics.ObserveCertificate(namespace, shared, "kubeca", "peer-24h", true, notAfter, renewal)
	assert.Equal(t, 1, series(shared), "only the last observation of the shared Certificate")
	metrics.ForgetCertificate(namespace, shared)

	assert.Equal(t, 0, testutil.CollectAndCount(metrics.CertificateExpiration))
	assert.Equal(t, 0, testutil.CollectAndCount(metrics.CertificateRenewal))
	assert.Equal(t, 0, testutil.CollectAndCount(metrics.CertificateReady))
}
