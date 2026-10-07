package certificate

import (
	"cmp"
	"context"
	"fmt"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/kubeca/api/v1alpha1"
	"github.com/effective-security/kubeca/internal/operator/index"
	"github.com/effective-security/kubeca/internal/operator/metrics"
	"github.com/effective-security/kubeca/internal/signerr"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/authority"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/kubeca", "operator/certificate")

const (
	// ControllerName is the name of the controller in metrics and logs.
	ControllerName = "certificate"
	// DefaultMaxConcurrentReconciles is the worker count when the
	// Reconciler does not set one; Issuer.Sign is safe for concurrent use.
	DefaultMaxConcurrentReconciles = 4

	// issuerRetryInterval is the requeue delay while the ClusterIssuer is
	// missing or not Ready (its controller also enqueues the Certificates
	// of an issuer whose status changes).
	issuerRetryInterval = time.Minute
	// conflictRetryInterval is the requeue delay in SecretConflict: the
	// foreign Secret is not in the cache, so its deletion is not observed.
	conflictRetryInterval = 5 * time.Minute
	// minRequeue is the shortest delay until the renewal reconcile.
	minRequeue = 10 * time.Second
)

// Reconciler reconciles Certificates.
type Reconciler struct {
	client.Client
	// APIReader reads Secrets the cache does not hold (not labeled
	// managed=true) to detect a conflict before creating one.
	APIReader client.Reader
	Scheme    *runtime.Scheme
	Authority *authority.Authority
	Recorder  record.EventRecorder
	// Clock is the time source; tests inject a fake.
	Clock clock.Clock
	// ClusterDomain is the suffix of the Service names
	// spec.kubernetesNames adds and the policy placeholder
	// ${CLUSTER_DOMAIN}.
	ClusterDomain string
	// MaxConcurrentReconciles overrides DefaultMaxConcurrentReconciles.
	MaxConcurrentReconciles int
}

// +kubebuilder:rbac:groups=kubeca.effectivesecurity,resources=certificates,verbs=get;list;watch
// +kubebuilder:rbac:groups=kubeca.effectivesecurity,resources=certificates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=kubeca.effectivesecurity,resources=clusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=namespaces;services;pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// SetupWithManager registers the controller: it watches Certificates
// (CertificateChanged: not their status), the Secrets they own,
// ClusterIssuers (mapped to their Certificates),
// Services (mapped to the Certificates that name them) and Namespaces
// whose labels change (mapped to their Certificates, for the policy
// namespace selector). Pods are read from the cache (labeled Pods) for
// the policy placeholder ${SERVICE_ACCOUNT}, not watched: a Pod's
// ServiceAccount is immutable and its Certificate is garbage-collected
// with it.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named(ControllerName).
		For(&v1alpha1.Certificate{}, builder.WithPredicates(CertificateChanged)).
		Owns(&corev1.Secret{}).
		Watches(&v1alpha1.ClusterIssuer{}, handler.EnqueueRequestsFromMapFunc(r.certificatesOfIssuer)).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(r.certificatesOfService)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.certificatesInNamespace),
			builder.WithPredicates(predicate.LabelChangedPredicate{})).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: cmp.Or(r.MaxConcurrentReconciles, DefaultMaxConcurrentReconciles),
		}).
		Complete(r)
}

// CertificateChanged lets through the Certificate updates that can change
// the outcome of a reconcile: the spec (metadata.generation), the
// annotations (renew-requested) and the owner references (the Pod of the
// policy placeholder ${SERVICE_ACCOUNT}). A status-only update, the
// controller's own status patch included, is dropped: a recorded failure
// would otherwise enqueue its Certificate again at once, re-sign, record
// the next attempt and loop without backoff. Creates and deletes pass.
var CertificateChanged = predicate.Or[client.Object](
	predicate.GenerationChangedPredicate{},
	predicate.AnnotationChangedPredicate{},
	predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		return e.ObjectOld != nil && e.ObjectNew != nil &&
			!equality.Semantic.DeepEqual(e.ObjectOld.GetOwnerReferences(), e.ObjectNew.GetOwnerReferences())
	}},
)

func (r *Reconciler) certificatesOfIssuer(ctx context.Context, obj client.Object) []reconcile.Request {
	return r.listRequests(ctx, client.MatchingFields{index.CertificateIssuer: obj.GetName()})
}

func (r *Reconciler) certificatesOfService(ctx context.Context, obj client.Object) []reconcile.Request {
	return r.listRequests(ctx, client.InNamespace(obj.GetNamespace()), client.MatchingFields{index.CertificateServices: obj.GetName()})
}

// certificatesInNamespace enqueues every Certificate of a Namespace whose
// labels changed (the policy namespace selector).
func (r *Reconciler) certificatesInNamespace(ctx context.Context, obj client.Object) []reconcile.Request {
	return r.listRequests(ctx, client.InNamespace(obj.GetName()))
}

func (r *Reconciler) listRequests(ctx context.Context, opts ...client.ListOption) []reconcile.Request {
	var list v1alpha1.CertificateList
	if err := r.List(ctx, &list, opts...); err != nil {
		logger.ContextKV(ctx, xlog.ERROR, "reason", "unable to list Certificates", "err", err)
		return nil
	}
	requests := make([]reconcile.Request, 0, len(list.Items))
	for _, cert := range list.Items {
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: cert.Namespace, Name: cert.Name}})
	}
	return requests
}

// Reconcile runs the issuance pipeline for one Certificate and patches
// its status. It returns an error only for transient failures.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cert v1alpha1.Certificate
	if err := r.Get(ctx, req.NamespacedName, &cert); err != nil {
		if apierrors.IsNotFound(err) {
			metrics.ForgetCertificate(req.Namespace, req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.WithMessage(err, "unable to get Certificate")
	}
	if !cert.DeletionTimestamp.IsZero() {
		metrics.ForgetCertificate(req.Namespace, req.Name)
		return ctrl.Result{}, nil
	}
	orig := cert.DeepCopy()
	result, profile, err := r.reconcile(ctx, &cert)
	if !equality.Semantic.DeepEqual(orig.Status, cert.Status) {
		if perr := r.Status().Patch(ctx, &cert, client.MergeFrom(orig)); perr != nil {
			perr = errors.WithMessage(perr, "unable to patch Certificate status")
			if err == nil {
				return ctrl.Result{}, perr
			}
			return ctrl.Result{}, errors.CombineErrors(err, perr)
		}
	}
	r.observe(&cert, profile)
	return result, err
}

// observe records the Certificate gauges from its status, labeled with the
// issuer and the profile that signs the certificate.
func (r *Reconciler) observe(cert *v1alpha1.Certificate, profile string) {
	ready := meta.IsStatusConditionTrue(cert.Status.Conditions, v1alpha1.ConditionReady)
	var notAfter, renewal time.Time
	if cert.Status.NotAfter != nil {
		notAfter = cert.Status.NotAfter.Time
	}
	if cert.Status.RenewalTime != nil {
		renewal = cert.Status.RenewalTime.Time
	}
	metrics.ObserveCertificate(cert.Namespace, cert.Name, cert.Spec.IssuerRef.Name, profile, ready, notAfter, renewal)
}

// reconcile is the pipeline; it mutates cert.Status and the caller
// patches it. It also returns the profile for the metrics: the resolved
// one (spec.profile or the issuer's defaultProfile), or, when the issuer
// cannot be resolved, the profile recorded on the stored Secret.
func (r *Reconciler) reconcile(ctx context.Context, cert *v1alpha1.Certificate) (ctrl.Result, string, error) {
	now := r.Clock.Now()
	s, err := r.readSecret(ctx, cert)
	if err != nil {
		result, err := r.handleError(ctx, cert, nil, nil, err, now)
		return result, cert.Spec.Profile, err
	}
	restoreStatus(cert, s)
	ic, err := r.resolve(ctx, cert)
	if err != nil {
		result, err := r.handleError(ctx, cert, ic, s, err, now)
		return result, storedProfile(cert, s), err
	}
	result, err := r.issueOrKeep(ctx, cert, ic, s, now)
	return result, ic.profileName, err
}

// storedProfile is the profile recorded on the Secret, or spec.profile.
func storedProfile(cert *v1alpha1.Certificate, s *stored) string {
	if s != nil && s.secret != nil {
		if profile := s.secret.Annotations[v1alpha1.AnnotationProfile]; profile != "" {
			return profile
		}
	}
	return cert.Spec.Profile
}

// issueOrKeep decides whether to issue: it keeps an up-to-date Secret in
// line (syncSecret) or issues, writes the Secret and records the outcome.
func (r *Reconciler) issueOrKeep(ctx context.Context, cert *v1alpha1.Certificate, ic *issuanceContext, s *stored, now time.Time) (ctrl.Result, error) {

	renewal := effectiveRenewalTime(s, ic)
	trigger, detail := needsIssuance(cert, s, ic, renewal, now)
	if trigger != "" {
		// sign only on the Secret the API server holds
		fresh, changed, err := r.confirmSecret(ctx, cert, s)
		if err != nil {
			return r.handleError(ctx, cert, ic, s, err, now)
		}
		if changed {
			s = fresh
			restoreStatus(cert, s)
			renewal = effectiveRenewalTime(s, ic)
			trigger, detail = needsIssuance(cert, s, ic, renewal, now)
		}
	}
	if trigger == "" {
		if err := r.syncSecret(ctx, cert, ic, s); err != nil {
			return r.handleError(ctx, cert, ic, s, err, now)
		}
		r.setStored(cert, ic, s, renewal, now)
		logger.ContextKV(ctx, xlog.DEBUG,
			"ns", cert.Namespace,
			"name", cert.Name,
			"status", "up_to_date",
			"renewal_time", renewal.UTC().Format(time.RFC3339))
		return ctrl.Result{RequeueAfter: max(renewal.Sub(now), minRequeue)}, nil
	}

	logger.ContextKV(ctx, xlog.DEBUG,
		"ns", cert.Namespace,
		"name", cert.Name,
		"status", "issuing",
		"trigger", trigger,
		"reason", detail)
	r.setCondition(cert, v1alpha1.ConditionIssuing, metav1.ConditionTrue, trigger, detail, now)
	started := now
	out, err := r.issue(cert, ic, s)
	if err == nil {
		err = r.writeSecret(ctx, cert, ic, s, out, cert.Status.Revision+1, now)
	}
	if err != nil {
		// the status patch below does not enqueue the Certificate again
		// (CertificateChanged): a permanent failure waits for a relevant
		// change, a transient one for the rate-limited retry of the error
		cert.Status.FailedAttempts++
		cert.Status.LastFailureTime = &metav1.Time{Time: now}
		metrics.IssuanceTotal.WithLabelValues(ic.issuer.Name, ic.profileName, trigger, metrics.ResultError).Inc()
		if isPermanent(err) {
			r.fail(ctx, cert, v1alpha1.ReasonIssuanceFailed, err.Error(), now)
			return ctrl.Result{}, nil
		}
		// a stored certificate that is still valid keeps Ready while the
		// renewal is retried
		if !storedValid(s, now) {
			r.setCondition(cert, v1alpha1.ConditionReady, metav1.ConditionFalse, v1alpha1.ReasonIssuanceFailed, err.Error(), now)
		}
		r.Recorder.Event(cert, corev1.EventTypeWarning, v1alpha1.ReasonIssuanceFailed, err.Error())
		logger.ContextKV(ctx, xlog.ERROR,
			"ns", cert.Namespace,
			"name", cert.Name,
			"issuer", ic.issuer.Name,
			"profile", ic.profileName,
			"trigger", trigger,
			"reason", "issuance failed, retrying",
			"err", err)
		return ctrl.Result{}, errors.WithMessage(err, "issuance failed")
	}

	cert.Status.Revision++
	cert.Status.FailedAttempts = 0
	cert.Status.LastFailureTime = nil
	cert.Status.LastRenewRequest = cert.Annotations[v1alpha1.AnnotationRenewRequested]
	renewal = renewalTime(out.leaf, ic.renewBefore, now)
	r.setStored(cert, ic, &stored{leaf: out.leaf}, renewal, now)
	r.setCondition(cert, v1alpha1.ConditionIssuing, metav1.ConditionFalse, v1alpha1.ReasonIssued, "", now)

	elapsed := r.Clock.Since(started)
	metrics.IssuanceTotal.WithLabelValues(ic.issuer.Name, ic.profileName, trigger, metrics.ResultSuccess).Inc()
	metrics.IssuanceDuration.WithLabelValues(ic.issuer.Name, ic.profileName).Observe(elapsed.Seconds())
	eventReason := v1alpha1.EventIssued
	if cert.Status.Revision > 1 {
		eventReason = v1alpha1.EventRenewed
	}
	r.Recorder.Eventf(cert, corev1.EventTypeNormal, eventReason,
		"certificate %s issued by %s/%s, not after %s, revision %d",
		cert.Status.SerialNumber, ic.issuer.Name, ic.profileName, out.leaf.NotAfter.UTC().Format(time.RFC3339), cert.Status.Revision)
	logger.ContextKV(ctx, xlog.INFO,
		"ns", cert.Namespace,
		"name", cert.Name,
		"status", "issued",
		"issuer", ic.issuer.Name,
		"profile", ic.profileName,
		"serial", cert.Status.SerialNumber,
		"not_after", out.leaf.NotAfter.UTC().Format(time.RFC3339),
		"renewal_time", renewal.UTC().Format(time.RFC3339),
		"trigger", trigger,
		"revision", cert.Status.Revision,
		"elapsed", elapsed.String())
	return ctrl.Result{RequeueAfter: max(renewal.Sub(now), minRequeue)}, nil
}

// handleError records a permanent error on the Certificate and returns
// without error, or returns a transient one for the retry. An issuer that
// is missing or not Ready leaves a still valid stored certificate Ready:
// the workload is not affected until the renewal.
func (r *Reconciler) handleError(ctx context.Context, cert *v1alpha1.Certificate, ic *issuanceContext, s *stored, err error, now time.Time) (ctrl.Result, error) {
	var perr *permanentError
	if !errors.As(err, &perr) {
		return ctrl.Result{}, err
	}
	if perr.reason == v1alpha1.ReasonIssuerNotReady && storedValid(s, now) {
		r.setCondition(cert, v1alpha1.ConditionIssuing, metav1.ConditionFalse, v1alpha1.ReasonFailed, perr.message, now)
		r.Recorder.Event(cert, corev1.EventTypeWarning, perr.reason, perr.message)
		logger.ContextKV(ctx, xlog.WARNING,
			"ns", cert.Namespace,
			"name", cert.Name,
			"issuer", cert.Spec.IssuerRef.Name,
			"status", "issuer_not_ready",
			"reason", perr.message)
		return ctrl.Result{RequeueAfter: issuerRetryInterval}, nil
	}
	r.fail(ctx, cert, perr.reason, perr.message, now)
	switch perr.reason {
	case v1alpha1.ReasonIssuerNotReady:
		return ctrl.Result{RequeueAfter: issuerRetryInterval}, nil
	case v1alpha1.ReasonSecretConflict:
		return ctrl.Result{RequeueAfter: conflictRetryInterval}, nil
	case v1alpha1.ReasonPolicyViolation:
		issuer, profile := cert.Spec.IssuerRef.Name, cert.Spec.Profile
		if ic != nil {
			issuer, profile = ic.issuer.Name, ic.profileName
		}
		metrics.IssuanceTotal.WithLabelValues(issuer, profile, "", metrics.ResultPolicyViolation).Inc()
	}
	return ctrl.Result{}, nil
}

// fail sets Ready=False with the reason, Issuing=False/Failed, emits the
// Warning event and logs one line.
func (r *Reconciler) fail(ctx context.Context, cert *v1alpha1.Certificate, reason, message string, now time.Time) {
	r.setCondition(cert, v1alpha1.ConditionReady, metav1.ConditionFalse, reason, message, now)
	r.setCondition(cert, v1alpha1.ConditionIssuing, metav1.ConditionFalse, v1alpha1.ReasonFailed, message, now)
	r.Recorder.Event(cert, corev1.EventTypeWarning, reason, message)
	logger.ContextKV(ctx, xlog.WARNING,
		"ns", cert.Namespace,
		"name", cert.Name,
		"issuer", cert.Spec.IssuerRef.Name,
		"profile", cert.Spec.Profile,
		"status", "failed",
		"condition", reason,
		"reason", message)
}

// storedValid reports whether the Secret holds an unexpired certificate
// with a matching, parsed private key.
func storedValid(s *stored, now time.Time) bool {
	return s != nil && s.leaf != nil && s.key != nil &&
		publicKeysEqual(s.key.Public(), s.leaf.PublicKey) && now.Before(s.leaf.NotAfter)
}

// setStored copies the stored certificate into the status and sets
// Ready=True.
func (r *Reconciler) setStored(cert *v1alpha1.Certificate, ic *issuanceContext, s *stored, renewal, now time.Time) {
	cert.Status.NotBefore = &metav1.Time{Time: s.leaf.NotBefore}
	cert.Status.NotAfter = &metav1.Time{Time: s.leaf.NotAfter}
	cert.Status.RenewalTime = &metav1.Time{Time: renewal}
	cert.Status.SerialNumber = formatSerial(s.leaf.SerialNumber)
	cert.Status.IssuerLabel = ic.issuer.Spec.IssuerLabel
	cert.Status.IssuerKeyID = ic.issuer.Status.IssuerKeyID
	r.setCondition(cert, v1alpha1.ConditionReady, metav1.ConditionTrue, v1alpha1.ReasonIssued,
		fmt.Sprintf("certificate %s valid until %s", cert.Status.SerialNumber, s.leaf.NotAfter.UTC().Format(time.RFC3339)), now)
	if !meta.IsStatusConditionFalse(cert.Status.Conditions, v1alpha1.ConditionIssuing) {
		r.setCondition(cert, v1alpha1.ConditionIssuing, metav1.ConditionFalse, v1alpha1.ReasonIssued, "", now)
	}
}

func (r *Reconciler) setCondition(cert *v1alpha1.Certificate, condType string, status metav1.ConditionStatus, reason, message string, now time.Time) {
	meta.SetStatusCondition(&cert.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: cert.Generation,
		LastTransitionTime: metav1.NewTime(now),
	})
}

// permanentError is a failure recorded in the Ready condition under
// reason and not retried.
type permanentError struct {
	reason  string
	message string
}

func (e *permanentError) Error() string {
	return e.message
}

func permanent(reason, message string) error {
	return &permanentError{reason: reason, message: message}
}

// isPermanent reports whether err must not be retried: a permanentError
// or a request the issuer rejected on its content.
func isPermanent(err error) bool {
	var perr *permanentError
	return errors.As(err, &perr) || signerr.IsPermanent(err)
}
