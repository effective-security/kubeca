package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"time"

	"github.com/effective-security/kubeca/internal/certinit"
	"github.com/effective-security/kubeca/internal/version"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xlog/stackdriver"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/kubeca", "kubecertinit")

const (
	serviceName          = "kubecertinit"
	defaultCertDir       = "/etc/tls"
	defaultClusterDomain = "cluster.local"
	exitError            = 2
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("panic: %v\n%s\n", r, string(debug.Stack()))
		}
	}()

	var kubeConfig string
	var withStackdriver bool
	var showVersion bool
	var timeout time.Duration
	r := &certinit.Request{}
	flag.StringVar(&kubeConfig, "kubeconfig", "", "(optional) path to kubeconfig file")
	flag.StringVar(&r.Namespace, "namespace", "", "namespace as defined by pod.metadata.namespace")
	flag.StringVar(&r.PodName, "pod-name", "", "name as defined by pod.metadata.name")
	flag.StringVar(&r.CertDir, "cert-dir", defaultCertDir, "directory where the TLS certs should be written")
	flag.StringVar(&r.ClusterDomain, "cluster-domain", defaultClusterDomain, "kubernetes cluster domain")
	flag.StringVar(&r.Labels, "labels", "", "labels to include in CertificateSigningRequest object; comma separated list of key=value")
	flag.BoolVar(&r.QueryK8s, "query-k8s", false, "query kubernetes for names appropriate to this Pod")
	flag.StringVar(&r.SAN, "san", "", "additional SAN; comma separated")
	flag.StringVar(&r.ServiceNames, "service-names", "", "additional service names in the Pod's namespace that resolve to this Pod; comma separated")
	flag.BoolVar(&r.IncludeUnqualified, "include-unqualified", false, "include unqualified .svc domains in names from --query-k8s and --service-names")
	flag.StringVar(&r.SignerName, "signer", "", "signer name")
	flag.StringVar(&r.Usages, "usages", "", "key usages to request, comma separated; required for a profile other than peer, server or client")
	flag.DurationVar(&timeout, "timeout", 0, "give up waiting for the certificate after this duration; 0 waits for ever")
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

	logger.KV(xlog.INFO, "status", "starting", "version", version.Current().Build)

	// Create a Kubernetes client.
	client, err := certinit.NewClient(kubeConfig, r.Namespace)
	if err != nil {
		log.Printf("unable to create Kubernetes client: %v\n", err)
		os.Exit(exitError)
	}

	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	err = r.Create(ctx, client)
	if err != nil {
		log.Printf("error: %v\n", err)
		os.Exit(exitError)
	}

	os.Exit(0)
}
