package controller

import (
	"context"
	"strings"
	"time"

	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/authority"
	csrapi "github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/metricskey"
	"github.com/effective-security/xpki/x/print"
	"github.com/pkg/errors"
	capi "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CertificateSigningRequestSigningReconciler reconciles a CertificateSigningRequest object
type CertificateSigningRequestSigningReconciler struct {
	client.Client
	//Log           logr.Logger
	Scheme        *runtime.Scheme
	Authority     *authority.Authority
	EventRecorder record.EventRecorder
}

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=patch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// Reconcile implementation
func (r *CertificateSigningRequestSigningReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logger.WithValues("ns", req.NamespacedName)
	var csr capi.CertificateSigningRequest
	if err := r.Client.Get(ctx, req.NamespacedName, &csr); client.IgnoreNotFound(err) != nil {
		return ctrl.Result{}, errors.WithMessagef(err, "error getting CSR")
	}
	json, _ := marshal.EncodeBytes(marshal.PrettyPrint, csr)

	switch {
	case !csr.DeletionTimestamp.IsZero():
		logger.ContextKV(ctx, xlog.DEBUG, "ignoring", "CSR has been deleted")
	case csr.Spec.SignerName == "":
		logger.ContextKV(ctx, xlog.INFO, "ignoring", "CSR does not have a signer name: "+string(json))
	case csr.Status.Certificate != nil:
		logger.ContextKV(ctx, xlog.DEBUG, "ignoring", "CSR has already been signed")
	case !isCertificateRequestApproved(&csr):
		logger.ContextKV(ctx, xlog.INFO, "ignoring", "CSR is not approved")
	default:
		logger.ContextKV(ctx, xlog.DEBUG, "csr", string(json))

		/*
			// TODO: check
			x509cr, err := csrapi.ParsePEM(csr.Spec.Request)
			if err != nil {
				log.Error(err, "unable to parse CSR")
				r.EventRecorder.Event(&csr, v1.EventTypeWarning, "SigningFailed", "Unable to parse the CSR request")
				return ctrl.Result{}, nil
			}
			b := new(strings.Builder)
			print.Certificate(b, x509cr)
			log.V(1).Info("CSR", "info", b.String())
		*/

		issuer, profile := r.findIssuer(csr.Spec.SignerName)
		if issuer != nil {
			now := time.Now()

			signReq := csrapi.SignRequest{
				Request: string(csr.Spec.Request),
				Profile: profile,
			}
			cert, raw, err := issuer.Sign(signReq)
			if err != nil {
				logger.ContextKV(ctx, xlog.ERROR,
					"reason", "unable to sign",
					"err", err)
				return ctrl.Result{}, errors.WithMessagef(err, "failed to sign CSR")
			}

			b := new(strings.Builder)
			print.Certificate(b, cert, false)
			logger.ContextKV(ctx, xlog.NOTICE,
				"status", "signed",
				"issuer", issuer.Label(),
				"profile", profile,
				"elapsed", time.Since(now).String(),
				"certificate", b.String())
			metricskey.PerfCASignRequest.MeasureSince(now, issuer.Label(), profile)

			if len(issuer.PEM()) > 0 {
				pem := strings.TrimSpace(string(raw)) + "\n" + strings.TrimSpace(issuer.PEM())
				raw = []byte(pem)
			}

			patch := client.MergeFrom(csr.DeepCopy())
			csr.Status.Certificate = []byte(strings.TrimSpace(string(raw)))

			if err := r.Client.Status().Patch(ctx, &csr, patch); err != nil {
				logger.ContextKV(ctx, xlog.ERROR,
					"reason", "unable to patch status",
					"err", err)
				return ctrl.Result{}, errors.WithMessagef(err, "error patching CSR")
			}
			r.EventRecorder.Event(&csr, v1.EventTypeNormal, "Signed", "The CSR has been signed")
		} else {
			logger.ContextKV(ctx, xlog.INFO, "ignoring", "issuer not found", "signer", csr.Spec.SignerName)
		}
	}
	return ctrl.Result{}, nil
}

func (r *CertificateSigningRequestSigningReconciler) findIssuer(signerName string) (*authority.Issuer, string) {
	// [0] - issuer name, [1] - profile name
	issuerTokens := strings.Split(signerName, "/")
	if len(issuerTokens) == 2 {
		issuer, _ := r.Authority.GetIssuerByProfile(issuerTokens[1])
		if issuer != nil && issuer.Label() == issuerTokens[0] {
			return issuer, issuerTokens[1]
		}
	}
	return nil, ""
}

// SetupWithManager allows to set up controller manager
func (r *CertificateSigningRequestSigningReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&capi.CertificateSigningRequest{}).
		Complete(r)
}

// IsCertificateRequestApproved returns true if a certificate request has the
// "Approved" condition and no "Denied" conditions; false otherwise.
func isCertificateRequestApproved(csr *capi.CertificateSigningRequest) bool {
	// implicitly approve
	_, denied := getCertApprovalCondition(&csr.Status)
	return !denied
}

func getCertApprovalCondition(status *capi.CertificateSigningRequestStatus) (approved bool, denied bool) {
	for _, c := range status.Conditions {
		if c.Type == capi.CertificateApproved {
			approved = true
		}
		if c.Type == capi.CertificateDenied {
			denied = true
		}
	}
	return
}
