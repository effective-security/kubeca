package main

import (
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/kubeca/internal/controller"
	"github.com/effective-security/kubeca/internal/k8snames"
	"github.com/effective-security/kubeca/internal/logr"
	"github.com/effective-security/kubeca/internal/operator"
	"github.com/effective-security/xlog"
	capi "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

const (
	csrRecorderName = "kubeca-csr-signer"

	// Names of the health checks.
	pingCheck    = "ping"
	webhookCheck = "webhook"
)

// run builds the manager, loads the Authority, registers the CSR signer
// and the operator, and runs until a signal.
func run(f *flags) error {
	approveMode, err := controller.ParseApproveMode(f.approve)
	if err != nil {
		return err
	}
	if f.enableWebhook && !f.enableOperator {
		return errors.New("-enable-webhook needs -enable-operator")
	}
	if f.disableCSRSigner && !f.enableOperator {
		return errors.New("nothing to run: -disable-csr-signer without -enable-operator")
	}

	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{capi.AddToScheme, corev1.AddToScheme} {
		if err := add(scheme); err != nil {
			return errors.WithStack(err)
		}
	}
	options := ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: f.metricsAddr,
		},
		HealthProbeBindAddress: f.healthProbeAddr,
		LeaderElection:         f.enableLeaderElection,
		LeaderElectionID:       f.leaderElectionID,
		Logger:                 logr.New(logger),
	}
	var operatorOptions operator.Options
	if f.enableOperator {
		if err := operator.AddToScheme(scheme); err != nil {
			return err
		}
		options.Cache = operator.CacheOptions()
		operatorOptions = operator.Options{ClusterDomain: f.clusterDomain}
		if f.enableWebhook {
			issuerLabel, profile, ok := strings.Cut(f.webhookSigner, "/")
			if !ok {
				return errors.Errorf("invalid -webhook-signer %q: use <issuer-label>/<profile>", f.webhookSigner)
			}
			operatorOptions.Webhook = &operator.WebhookOptions{
				Port:             f.webhookPort,
				CertDir:          f.webhookCertDir,
				ServiceName:      f.webhookService,
				ServiceNamespace: f.webhookNamespace,
				IssuerLabel:      issuerLabel,
				Profile:          profile,
				ConfigName:       f.webhookConfig,
			}
			options.WebhookServer = operator.WebhookServer(operatorOptions.Webhook)
		}
	} else {
		// without the operator nothing restricts the caches; Pods and
		// Services are listed by the approver only
		options.Cache = cache.Options{DefaultTransform: cache.TransformStripManagedFields()}
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), options)
	if err != nil {
		return errors.WithMessage(err, "unable to start manager")
	}
	// readiness: with the webhook, its server must accept TLS connections
	// (the webhook Service routes admission requests to ready replicas
	// only, and failurePolicy Fail rejects labeled Pods without one); the
	// controllers run on the leader and do not gate the readiness
	readyCheck, readyName := healthz.Ping, pingCheck
	if f.enableWebhook {
		readyCheck, readyName = mgr.GetWebhookServer().StartedChecker(), webhookCheck
	}
	if err := mgr.AddHealthzCheck(pingCheck, healthz.Ping); err != nil {
		return errors.WithMessage(err, "unable to add the health check")
	}
	if err := mgr.AddReadyzCheck(readyName, readyCheck); err != nil {
		return errors.WithMessage(err, "unable to add the readiness check")
	}
	ca, err := controller.LoadAuthority(f.caCfgPath, f.hsmCfgPath)
	if err != nil {
		return err
	}
	ctx := ctrl.SetupSignalHandler()

	if !f.disableCSRSigner {
		if err := (&controller.CertificateSigningRequestSigningReconciler{
			Client:        mgr.GetClient(),
			APIReader:     mgr.GetAPIReader(),
			Scheme:        mgr.GetScheme(),
			Authority:     ca,
			EventRecorder: mgr.GetEventRecorderFor(csrRecorderName), // nolint:staticcheck
			ApproveMode:   approveMode,
			AllowedNames:  slices.Collect(k8snames.SplitList(f.allowedNames)),
			ClusterDomain: f.clusterDomain,
		}).SetupWithManager(mgr); err != nil {
			return errors.WithMessage(err, "unable to create the CSR signing controller")
		}
		logger.KV(xlog.INFO, "status", "csr_signer_enabled", "approve", string(approveMode))
	}
	if f.enableOperator {
		if err := operator.Setup(ctx, mgr, ca, operatorOptions); err != nil {
			return errors.WithMessage(err, "unable to set up the operator")
		}
		logger.KV(xlog.INFO, "status", "operator_enabled", "webhook", f.enableWebhook, "cluster_domain", f.clusterDomain)
	}

	logger.KV(xlog.INFO, "status", "starting controller", "leader_election", f.enableLeaderElection)
	if err := mgr.Start(ctx); err != nil {
		return errors.WithMessage(err, "unable to start controller")
	}
	return nil
}
