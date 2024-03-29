package controller

import (
	capi "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	// +kubebuilder:scaffold:imports
	"github.com/effective-security/kubeca/internal/logr"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/cryptoprov"
)

var (
	scheme = runtime.NewScheme()
	logger = xlog.NewPackageLogger("github.com/effective-security/kubeca", "controller")
)

const controllerName = "CSRSigningReconciler"

func init() {
	_ = capi.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

// CertificateSigningRequestControllerFlags provides controller flags
type CertificateSigningRequestControllerFlags struct {
	MetricsAddr          string
	EnableLeaderElection bool
	LeaderElectionID     string
	CaCfgPath            string
	HsmCfgPath           string
}

// StartCertificateSigningRequestController starts controller loop
func StartCertificateSigningRequestController(f *CertificateSigningRequestControllerFlags) error {
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: f.MetricsAddr,
		},
		LeaderElection:   f.EnableLeaderElection,
		LeaderElectionID: f.LeaderElectionID,
		Logger:           logr.New(logger),
	})
	if err != nil {
		logger.KV(xlog.ERROR,
			"reason", "unable to start manager",
			"err", err)
		return err
	}

	crypto, err := cryptoprov.Load(f.HsmCfgPath, nil)
	if err != nil {
		logger.KV(xlog.ERROR,
			"reason", "unable to load HSM config",
			"config", f.HsmCfgPath,
			"err", err)
		return err
	}

	caCfg, err := authority.LoadConfig(f.CaCfgPath)
	if err != nil {
		logger.KV(xlog.ERROR,
			"reason", "unable to load CA config",
			"config", f.CaCfgPath,
			"err", err)
		return err
	}

	ca, err := authority.NewAuthority(caCfg, crypto)
	if err != nil {
		logger.KV(xlog.ERROR,
			"reason", "unable to create CA",
			"err", err)
		return err
	}
	if err := (&CertificateSigningRequestSigningReconciler{
		Client: mgr.GetClient(),
		//Log:           ctrl.Log.WithName(controllerName),
		Scheme:        mgr.GetScheme(),
		Authority:     ca,
		EventRecorder: mgr.GetEventRecorderFor(controllerName),
	}).SetupWithManager(mgr); err != nil {
		logger.KV(xlog.ERROR,
			"reason", "unable to create Controller",
			"controller", controllerName,
			"err", err)
		return err

	}
	// +kubebuilder:scaffold:builder

	logger.KV(xlog.INFO, "status", "starting controller")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.KV(xlog.ERROR,
			"reason", "unable to start controller",
			"controller", controllerName,
			"err", err)
		return err
	}
	return nil
}
