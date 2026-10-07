package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Values of the result label of IssuanceTotal.
const (
	ResultSuccess         = "success"
	ResultPolicyViolation = "policy_violation"
	ResultError           = "error"
)

var (
	// CertificateExpiration is kubeca_certificate_expiration_timestamp_seconds.
	CertificateExpiration = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubeca_certificate_expiration_timestamp_seconds",
		Help: "notAfter of the certificate stored for a Certificate, as a Unix time.",
	}, []string{"namespace", "name", "issuer", "profile"})

	// CertificateRenewal is kubeca_certificate_renewal_timestamp_seconds.
	CertificateRenewal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubeca_certificate_renewal_timestamp_seconds",
		Help: "Time the Certificate controller will renew the certificate, as a Unix time.",
	}, []string{"namespace", "name"})

	// CertificateReady is kubeca_certificate_ready.
	CertificateReady = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubeca_certificate_ready",
		Help: "1 when the Certificate's Ready condition is True, else 0.",
	}, []string{"namespace", "name"})

	// IssuanceTotal is kubeca_issuance_total.
	IssuanceTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kubeca_issuance_total",
		Help: "Issuance attempts of the Certificate controller by issuer, profile, trigger and result.",
	}, []string{"issuer", "profile", "trigger", "result"})

	// IssuanceDuration is kubeca_issuance_duration_seconds.
	IssuanceDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "kubeca_issuance_duration_seconds",
		Help:    "Time from the issuance decision to the Secret write, in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"issuer", "profile"})

	// ClusterIssuerCAExpiration is kubeca_clusterissuer_ca_expiration_timestamp_seconds.
	ClusterIssuerCAExpiration = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubeca_clusterissuer_ca_expiration_timestamp_seconds",
		Help: "notAfter of the issuing certificate of a ClusterIssuer, as a Unix time.",
	}, []string{"issuer"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		CertificateExpiration,
		CertificateRenewal,
		CertificateReady,
		IssuanceTotal,
		IssuanceDuration,
		ClusterIssuerCAExpiration,
	)
}

// expirationLabels are the issuer and profile of a CertificateExpiration
// series.
type expirationLabels struct {
	issuer  string
	profile string
}

// expirationSeries maps "<namespace>/<name>" to the labels of the
// expiration series last set for that Certificate.
var expirationSeries = struct {
	sync.Mutex
	labels map[string]expirationLabels
}{labels: map[string]expirationLabels{}}

// ObserveCertificate records the gauges of one Certificate. A zero
// notAfter or renewal (nothing issued yet) deletes that series, and an
// expiration series set earlier under another issuer or profile is
// deleted so that the old notAfter does not keep firing expiry alerts.
func ObserveCertificate(namespace, name, issuer, profile string, ready bool, notAfter, renewal time.Time) {
	readyValue := 0.0
	if ready {
		readyValue = 1
	}
	CertificateReady.WithLabelValues(namespace, name).Set(readyValue)

	key := namespace + "/" + name
	current := expirationLabels{issuer: issuer, profile: profile}
	expirationSeries.Lock()
	if previous, ok := expirationSeries.labels[key]; ok && previous != current {
		CertificateExpiration.DeleteLabelValues(namespace, name, previous.issuer, previous.profile)
	}
	if notAfter.IsZero() {
		CertificateExpiration.DeleteLabelValues(namespace, name, issuer, profile)
		delete(expirationSeries.labels, key)
	} else {
		CertificateExpiration.WithLabelValues(namespace, name, issuer, profile).Set(float64(notAfter.Unix()))
		expirationSeries.labels[key] = current
	}
	expirationSeries.Unlock()

	if renewal.IsZero() {
		CertificateRenewal.DeleteLabelValues(namespace, name)
	} else {
		CertificateRenewal.WithLabelValues(namespace, name).Set(float64(renewal.Unix()))
	}
}

// ForgetCertificate drops the gauges of a deleted Certificate.
func ForgetCertificate(namespace, name string) {
	expirationSeries.Lock()
	delete(expirationSeries.labels, namespace+"/"+name)
	expirationSeries.Unlock()
	labels := prometheus.Labels{"namespace": namespace, "name": name}
	CertificateReady.DeletePartialMatch(labels)
	CertificateExpiration.DeletePartialMatch(labels)
	CertificateRenewal.DeletePartialMatch(labels)
}
