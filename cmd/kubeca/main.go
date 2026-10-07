package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"slices"

	"github.com/effective-security/kubeca/internal/controller"
	"github.com/effective-security/kubeca/internal/k8snames"
	"github.com/effective-security/kubeca/internal/logr"
	"github.com/effective-security/kubeca/internal/operator"
	"github.com/effective-security/kubeca/internal/version"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xlog/stackdriver"
	"github.com/effective-security/xpki/crypto11"
	"github.com/effective-security/xpki/cryptoprov"
	ctrl "sigs.k8s.io/controller-runtime"

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
	defaultHealthAddr     = ":8081"
	defaultLeaderElection = "kube-ca-leader-election"
	defaultCACfgPath      = "/kubeca/etc/ca-config.yaml"
	defaultHSMCfgPath     = "/kubeca/etc/aws-kms-us-west-2.json"
	defaultAllowedNames   = "localhost,127.0.0.1"
	defaultWebhookService = "kubeca-webhook"
	defaultWebhookSigner  = "kubeca.svc/" + operator.DefaultWebhookProfile

	flagEnableLeaderElection = "enable-leader-election"
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

// flags of the command.
type flags struct {
	metricsAddr          string
	healthProbeAddr      string
	enableLeaderElection bool
	leaderElectionID     string
	caCfgPath            string
	hsmCfgPath           string

	disableCSRSigner bool
	approve          string
	allowedNames     string
	clusterDomain    string

	enableOperator   bool
	enableWebhook    bool
	webhookPort      int
	webhookCertDir   string
	webhookService   string
	webhookNamespace string
	webhookSigner    string
	webhookConfig    string
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

	var f flags
	var debugLogging bool
	var withStackdriver bool
	var showVersion bool
	flag.BoolVar(&debugLogging, "debug", false, "Enable debug logging (xlog DEBUG level, including controller-runtime verbose lines).")
	flag.StringVar(&f.metricsAddr, "metrics-addr", defaultMetricsAddr, "The address the metric endpoint binds to.")
	flag.StringVar(&f.healthProbeAddr, "health-probe-addr", defaultHealthAddr,
		"The address of the /healthz and /readyz endpoints (readyz waits for the webhook server with -enable-webhook); 0 disables them.")
	flag.BoolVar(&f.enableLeaderElection, flagEnableLeaderElection, false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager. On by default with -enable-operator.")
	flag.StringVar(&f.leaderElectionID, "leader-election-id", defaultLeaderElection,
		"The name of the Lease used to coordinate leader election between controller-managers.")
	flag.StringVar(&f.caCfgPath, "ca-cfg", defaultCACfgPath, "Location of CA configuration file.")
	flag.StringVar(&f.hsmCfgPath, "hsm-cfg", defaultHSMCfgPath, "Location of HSM configuration file.")

	flag.BoolVar(&f.disableCSRSigner, "disable-csr-signer", false, "Do not run the CertificateSigningRequest signer.")
	flag.StringVar(&f.approve, "approve", string(controller.ApproveOff),
		"CSR approval: off signs every CSR of a known signer (pre-0.9 behaviour), audit logs the CSRs enforce would deny, "+
			"enforce approves a CSR whose names match the requesting ServiceAccount's Pods and Services and denies the others.")
	flag.StringVar(&f.allowedNames, "approve-allowed-names", defaultAllowedNames, "Names every requester may use with -approve; comma separated.")
	flag.StringVar(&f.clusterDomain, "cluster-domain", k8snames.DefaultClusterDomain, "Kubernetes cluster domain of the derived DNS names.")

	flag.BoolVar(&f.enableOperator, "enable-operator", false, "Run the operator: the ClusterIssuer, Certificate and Pod controllers.")
	flag.BoolVar(&f.enableWebhook, "enable-webhook", false, "Serve the Pod mutating webhook (needs -enable-operator).")
	flag.IntVar(&f.webhookPort, "webhook-port", operator.DefaultWebhookPort, "Port of the webhook server.")
	flag.StringVar(&f.webhookCertDir, "webhook-cert-dir", "", "Directory of the webhook serving certificate; the controller-runtime default when empty.")
	flag.StringVar(&f.webhookService, "webhook-service", defaultWebhookService, "Name of the webhook Service (DNS name of the serving certificate).")
	flag.StringVar(&f.webhookNamespace, "webhook-namespace", os.Getenv("POD_NAMESPACE"), "Namespace of the webhook Service; defaults to $POD_NAMESPACE.")
	flag.StringVar(&f.webhookSigner, "webhook-signer", defaultWebhookSigner, "Signer `<issuer-label>/<profile>` of the webhook serving certificate.")
	flag.StringVar(&f.webhookConfig, "webhook-config", operator.DefaultWebhookConfigName, "MutatingWebhookConfiguration whose caBundle the operator maintains; empty to skip.")

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
	formatter.Options(xlog.FormatWithCaller(true), xlog.FormatWithLocation(true))
	xlog.SetFormatter(formatter)
	if debugLogging {
		xlog.SetGlobalLogLevel(xlog.DEBUG)
	}

	// controller-runtime's global logger (metrics server, leader election,
	// internals that run before the manager exists) goes through the same
	// adapter as the manager logger, so every line has the xlog format.
	ctrl.SetLogger(logr.New(logger))

	// leader election is on by default in operator mode unless the flag
	// was given explicitly
	if f.enableOperator && !slices.Contains(explicitFlags(), flagEnableLeaderElection) {
		f.enableLeaderElection = true
	}

	logger.KV(xlog.INFO, "status", "starting", "version", version.Current().Build)

	if err := run(&f); err != nil {
		fmt.Printf("failed to start: %s\n", err.Error())
		os.Exit(1)
	}
}

// explicitFlags returns the names of the flags given on the command line.
func explicitFlags() []string {
	var names []string
	flag.Visit(func(fl *flag.Flag) { names = append(names, fl.Name) })
	return names
}
