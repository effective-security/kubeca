package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	// +kubebuilder:scaffold:imports

	"github.com/effective-security/kubeca/internal/controller"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xlog/stackdriver"
	"github.com/effective-security/xpki/crypto11"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/awskmscrypto"
	"github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("panic: %v\n%s\n", r, string(debug.Stack()))
		}
	}()

	_ = cryptoprov.Register("SoftHSM", crypto11.LoadProvider)
	_ = cryptoprov.Register("PKCS11", crypto11.LoadProvider)
	_ = cryptoprov.Register(awskmscrypto.ProviderName, awskmscrypto.KmsLoader)
	_ = cryptoprov.Register(awskmscrypto.ProviderName+"-1", awskmscrypto.KmsLoader)
	_ = cryptoprov.Register(awskmscrypto.ProviderName+"-2", awskmscrypto.KmsLoader)

	_ = cryptoprov.Register(gcpkmscrypto.ProviderName, gcpkmscrypto.KmsLoader)
	_ = cryptoprov.Register(gcpkmscrypto.ProviderName+"-1", gcpkmscrypto.KmsLoader)
	_ = cryptoprov.Register(gcpkmscrypto.ProviderName+"-2", gcpkmscrypto.KmsLoader)

	f := controller.CertificateSigningRequestControllerFlags{}
	var debugLogging bool
	var withStackdriver bool
	flag.BoolVar(&debugLogging, "debug", false, "Enable debug logging.")
	flag.StringVar(&f.MetricsAddr, "metrics-addr", ":9090", "The address the metric endpoint binds to.")
	flag.BoolVar(&f.EnableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&f.LeaderElectionID, "leader-election-id", "kube-ca-leader-election",
		"The name of the configmap used to coordinate leader election between controller-managers.")

	flag.StringVar(&f.CaCfgPath, "ca-cfg", "/kubeca/etc/ca-config.yaml", "Location of CA configuration file.")
	flag.StringVar(&f.HsmCfgPath, "hsm-cfg", "/kubeca/etc/aws-kms-us-west-2.json", "Location of HSM configuration file.")
	flag.BoolVar(&withStackdriver, "stackdriver", false, "Enable stackdriver logs formatting.")

	flag.Parse()

	var formatter xlog.Formatter
	if withStackdriver {
		formatter = stackdriver.NewFormatter(os.Stderr, "kubeca")
		xlog.SetFormatter(formatter)
	} else {
		formatter = xlog.NewPrettyFormatter(os.Stderr)
	}
	formatter.Options(xlog.FormatWithCaller)
	xlog.SetFormatter(formatter)

	ctrl.SetLogger(zap.New(zap.UseDevMode(debugLogging)))

	err := controller.StartCertificateSigningRequestController(&f)
	if err != nil {
		fmt.Printf("failed to start: %s\n", err.Error())
		os.Exit(1)
	}
}
