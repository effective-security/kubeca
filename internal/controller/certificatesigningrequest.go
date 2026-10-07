package controller

import (
	"context"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/kubeca/internal/signerr"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/authority"
	csrapi "github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/metricskey"
	"github.com/effective-security/xpki/x/print"
	capi "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CertificateSigningRequestSigningReconciler reconciles CertificateSigningRequests.
type CertificateSigningRequestSigningReconciler struct {
	client.Client
	// APIReader lists the Pods of a requesting ServiceAccount without
	// caching every Pod of the cluster.
	APIReader     client.Reader
	Scheme        *runtime.Scheme
	Authority     *authority.Authority
	EventRecorder record.EventRecorder
	// ApproveMode of the approver; ApproveOff when empty.
	ApproveMode ApproveMode
	// AllowedNames every requester may use (localhost, 127.0.0.1).
	AllowedNames []string
	// ClusterDomain is the suffix of the derived DNS names.
	ClusterDomain string
}

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=update;patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/approval,verbs=update
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,verbs=sign;approve,resourceNames=kubeca.svc/*
// +kubebuilder:rbac:groups=core,resources=pods;services,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// Event and condition reasons.
const (
	eventReasonSigned        = "Signed"
	eventReasonSigningFailed = "SigningFailed"
	eventReasonApproved      = "Approved"
	eventReasonDenied        = "Denied"
	eventReasonApprovalAudit = "ApprovalAudit"

	// conditionReasonApproved is the reason of the Approved condition the
	// approver sets.
	conditionReasonApproved = "KubeCAApproved"
	// conditionReasonDenied is the reason of the Denied condition.
	conditionReasonDenied = "NamesNotAllowed"
	// conditionReasonFailed is the reason of the Failed condition.
	conditionReasonFailed = "SigningFailed"

	approvalSubResource = "approval"
	signerNameSeparator = "/"
)

// Reconcile signs one CSR: it skips deleted, signer-less, signed and
// denied requests and unknown signers, runs the approver, and signs an
// approved request. A request the issuer rejects on its content gets the
// Failed condition; API server and KMS errors are returned for the retry.
func (r *CertificateSigningRequestSigningReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// CSRs are cluster-scoped: the name identifies the object.
	logger := logger.WithValues("name", req.Name)
	var csr capi.CertificateSigningRequest
	if err := r.Get(ctx, req.NamespacedName, &csr); err != nil {
		if apierrors.IsNotFound(err) {
			// deleted between the event and the reconcile
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.WithMessage(err, "error getting CSR")
	}

	switch {
	case !csr.DeletionTimestamp.IsZero():
		logger.ContextKV(ctx, xlog.DEBUG, "ignoring", "CSR has been deleted")
		return ctrl.Result{}, nil
	case csr.Spec.SignerName == "":
		logger.ContextKV(ctx, xlog.INFO, "ignoring", "CSR does not have a signer name", "username", csr.Spec.Username)
		return ctrl.Result{}, nil
	case csr.Status.Certificate != nil:
		logger.ContextKV(ctx, xlog.DEBUG, "ignoring", "CSR has already been signed")
		return ctrl.Result{}, nil
	}
	approved, denied, failed := approvalConditions(&csr.Status)
	if denied || failed {
		logger.ContextKV(ctx, xlog.DEBUG, "ignoring", "CSR is denied or failed")
		return ctrl.Result{}, nil
	}
	issuer, profile := r.findIssuer(csr.Spec.SignerName)
	if issuer == nil {
		logger.ContextKV(ctx, xlog.INFO, "ignoring", "issuer not found", "signer", csr.Spec.SignerName)
		return ctrl.Result{}, nil
	}

	mode := r.ApproveMode
	if mode == "" {
		mode = ApproveOff
	}
	if mode != ApproveOff && !approved {
		violation, err := r.evaluateNames(ctx, &csr)
		if err != nil {
			return ctrl.Result{}, err
		}
		if mode == ApproveEnforce {
			return ctrl.Result{}, r.approve(ctx, &csr, violation)
		}
		if violation != "" {
			logger.ContextKV(ctx, xlog.WARNING,
				"status", "approval_audit",
				"username", csr.Spec.Username,
				"signer", csr.Spec.SignerName,
				"reason", violation)
			r.EventRecorder.Event(&csr, corev1.EventTypeWarning, eventReasonApprovalAudit, "would be denied with -approve=enforce: "+violation)
		}
	}
	if mode == ApproveEnforce && !approved {
		logger.ContextKV(ctx, xlog.INFO, "ignoring", "CSR is not approved")
		return ctrl.Result{}, nil
	}
	return r.sign(ctx, &csr, issuer, profile)
}

// approve sets the Approved or Denied condition through the approval
// subresource; the update triggers the reconcile that signs.
func (r *CertificateSigningRequestSigningReconciler) approve(ctx context.Context, csr *capi.CertificateSigningRequest, violation string) error {
	now := metav1.Now()
	condition := capi.CertificateSigningRequestCondition{
		Type:               capi.CertificateApproved,
		Status:             corev1.ConditionTrue,
		Reason:             conditionReasonApproved,
		Message:            "names match the Pods and Services of " + csr.Spec.Username,
		LastUpdateTime:     now,
		LastTransitionTime: now,
	}
	eventType, eventReason := corev1.EventTypeNormal, eventReasonApproved
	if violation != "" {
		condition.Type = capi.CertificateDenied
		condition.Reason = conditionReasonDenied
		condition.Message = violation
		eventType, eventReason = corev1.EventTypeWarning, eventReasonDenied
	}
	csr.Status.Conditions = append(csr.Status.Conditions, condition)
	if err := r.SubResource(approvalSubResource).Update(ctx, csr); err != nil {
		return errors.WithMessagef(err, "unable to set the %s condition", condition.Type)
	}
	r.EventRecorder.Event(csr, eventType, eventReason, condition.Message)
	logger.ContextKV(ctx, xlog.INFO,
		"name", csr.Name,
		"status", strings.ToLower(string(condition.Type)),
		"username", csr.Spec.Username,
		"signer", csr.Spec.SignerName,
		"reason", condition.Message)
	return nil
}

// sign issues the certificate and patches the CSR status.
func (r *CertificateSigningRequestSigningReconciler) sign(ctx context.Context, csr *capi.CertificateSigningRequest, issuer *authority.Issuer, profile string) (ctrl.Result, error) {
	now := time.Now()
	signReq := csrapi.SignRequest{
		Request: string(csr.Spec.Request),
		Profile: profile,
	}
	leaf, raw, err := issuer.Sign(signReq)
	if err != nil {
		r.EventRecorder.Event(csr, corev1.EventTypeWarning, eventReasonSigningFailed, err.Error())
		if signerr.IsPermanent(err) {
			// KUBECA-013: the request itself is rejected; no retry.
			return ctrl.Result{}, r.fail(ctx, csr, err)
		}
		logger.ContextKV(ctx, xlog.ERROR,
			"name", csr.Name,
			"reason", "unable to sign, retrying",
			"err", err)
		return ctrl.Result{}, errors.WithMessage(err, "failed to sign CSR")
	}

	logger.ContextKV(ctx, xlog.NOTICE,
		"name", csr.Name,
		"status", "signed",
		"issuer", issuer.Label(),
		"profile", profile,
		"serial", leaf.SerialNumber.String(),
		"not_after", leaf.NotAfter.UTC().Format(time.RFC3339),
		"elapsed", time.Since(now).String())
	b := new(strings.Builder)
	print.Certificate(b, leaf, false)
	logger.ContextKV(ctx, xlog.DEBUG, "name", csr.Name, "certificate", b.String())
	metricskey.PerfCASignRequest.MeasureSince(now, issuer.Label(), profile)

	pem := strings.TrimSpace(string(raw))
	if chain := strings.TrimSpace(issuer.PEM()); chain != "" {
		pem += "\n" + chain
	}
	patch := client.MergeFrom(csr.DeepCopy())
	csr.Status.Certificate = []byte(pem)
	if err := r.Status().Patch(ctx, csr, patch); err != nil {
		return ctrl.Result{}, errors.WithMessage(err, "error patching CSR")
	}
	r.EventRecorder.Event(csr, corev1.EventTypeNormal, eventReasonSigned, "The CSR has been signed")
	return ctrl.Result{}, nil
}

// fail sets the Failed condition with the signing error (KUBECA-013).
func (r *CertificateSigningRequestSigningReconciler) fail(ctx context.Context, csr *capi.CertificateSigningRequest, signErr error) error {
	now := metav1.Now()
	patch := client.MergeFrom(csr.DeepCopy())
	csr.Status.Conditions = append(csr.Status.Conditions, capi.CertificateSigningRequestCondition{
		Type:               capi.CertificateFailed,
		Status:             corev1.ConditionTrue,
		Reason:             conditionReasonFailed,
		Message:            signErr.Error(),
		LastUpdateTime:     now,
		LastTransitionTime: now,
	})
	if err := r.Status().Patch(ctx, csr, patch); err != nil {
		return errors.WithMessage(err, "unable to set the Failed condition")
	}
	logger.ContextKV(ctx, xlog.WARNING,
		"name", csr.Name,
		"status", "failed",
		"signer", csr.Spec.SignerName,
		"username", csr.Spec.Username,
		"reason", signErr.Error())
	return nil
}

// findIssuer maps `<label>/<profile>` to the issuer serving the profile.
func (r *CertificateSigningRequestSigningReconciler) findIssuer(signerName string) (*authority.Issuer, string) {
	label, profile, ok := strings.Cut(signerName, signerNameSeparator)
	if !ok || strings.Contains(profile, signerNameSeparator) {
		return nil, ""
	}
	issuer, _ := r.Authority.GetIssuerByProfile(profile)
	if issuer != nil && issuer.Label() == label {
		return issuer, profile
	}
	return nil, ""
}

// SetupWithManager registers the controller for CertificateSigningRequests.
func (r *CertificateSigningRequestSigningReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&capi.CertificateSigningRequest{}).
		Complete(r)
}

// approvalConditions reports the Approved, Denied and Failed conditions
// whose status is True. The API server only admits these three with status
// True; anything else is not taken as a decision, so with -approve=enforce
// a CSR is signed only after an explicit Approved=True.
func approvalConditions(status *capi.CertificateSigningRequestStatus) (approved, denied, failed bool) {
	for _, c := range status.Conditions {
		if c.Status != corev1.ConditionTrue {
			continue
		}
		switch c.Type {
		case capi.CertificateApproved:
			approved = true
		case capi.CertificateDenied:
			denied = true
		case capi.CertificateFailed:
			failed = true
		}
	}
	return approved, denied, failed
}
