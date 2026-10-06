package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"

	ctrl "sigs.k8s.io/controller-runtime"

	// +kubebuilder:scaffold:imports

	"github.com/effective-security/kubeca/internal/controller"
	"github.com/effective-security/kubeca/internal/logr"
	"github.com/effective-security/kubeca/internal/version"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xlog/stackdriver"
	"github.com/effective-security/xpki/crypto11"
	"github.com/effective-security/xpki/cryptoprov"

	// The KMS providers register their manufacturer names (AWSKMS, GCPKMS)
	// in init(); importing them is the registration. crypto11 registers
	// SoftHSM the same way and is also used for the PKCS11 alias below.
	_ "github.com/effective-security/xpki/cryptoprov/awskmscrypto"
	_ "github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/kubeca", "kubeca")

const (
	serviceName           = "kubeca"
	defaultMetricsAddr    = ":9090"
	defaultLeaderElection = "kube-ca-leader-election"
	defaultCACfgPath      = "/kubeca/etc/ca-config.yaml"
	defaultHSMCfgPath     = "/kubeca/etc/aws-kms-us-west-2.json"
)

// providerAlias is an extra manufacturer name for a crypto provider loader,
// so a token config may name it instead of the provider's own name. The
// xpki providers register their own names in init() (see the imports), and
// a second registration of the same name is an error.
type providerAlias struct {
	name   string
	loader cryptoprov.ProviderLoader
}

var providerAliases = []providerAlias{
	{name: "PKCS11", loader: crypto11.LoadProvider},
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("panic: %v\n%s\n", r, string(debug.Stack()))
		}
	}()

	for _, alias := range providerAliases {
		if err := cryptoprov.Register(alias.name, alias.loader); err != nil {
			fmt.Printf("failed to register crypto provider %s: %s\n", alias.name, err.Error())
			os.Exit(1)
		}
	}

	f := controller.CertificateSigningRequestControllerFlags{}
	var debugLogging bool
	var withStackdriver bool
	var showVersion bool
	flag.BoolVar(&debugLogging, "debug", false, "Enable debug logging (xlog DEBUG level, including controller-runtime verbose lines).")
	flag.StringVar(&f.MetricsAddr, "metrics-addr", defaultMetricsAddr, "The address the metric endpoint binds to.")
	flag.BoolVar(&f.EnableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&f.LeaderElectionID, "leader-election-id", defaultLeaderElection,
		"The name of the Lease used to coordinate leader election between controller-managers.")

	flag.StringVar(&f.CaCfgPath, "ca-cfg", defaultCACfgPath, "Location of CA configuration file.")
	flag.StringVar(&f.HsmCfgPath, "hsm-cfg", defaultHSMCfgPath, "Location of HSM configuration file.")
	flag.BoolVar(&withStackdriver, "stackdriver", false, "Enable stackdriver logs formatting.")
	flag.BoolVar(&showVersion, "version", false, "Print the version and exit.")

	flag.Parse()

	if showVersion {
		fmt.Println(version.Current().Build)
		return
	}

	var formatter xlog.Formatter
	if withStackdriver {
		formatter = stackdriver.NewFormatter(os.Stderr, serviceName)
	} else {
		formatter = xlog.NewJSONFormatter(os.Stderr)
	}
	formatter.Options(xlog.FormatWithCaller(true))
	xlog.SetFormatter(formatter)
	if debugLogging {
		xlog.SetGlobalLogLevel(xlog.DEBUG)
	}

	// controller-runtime's global logger (metrics server, leader election,
	// internals that run before the manager exists) goes through the same
	// adapter as the manager logger, so every line has the xlog format.
	ctrl.SetLogger(logr.New(logger))

	logger.KV(xlog.INFO, "status", "starting", "version", version.Current().Build)

	err := controller.StartCertificateSigningRequestController(&f)
	if err != nil {
		fmt.Printf("failed to start: %s\n", err.Error())
		os.Exit(1)
	}
}
