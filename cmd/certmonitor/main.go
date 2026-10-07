package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/effective-security/porto/pkg/tlsconfig"
)

// flags of the command.
type flags struct {
	cert     string
	key      string
	root     string
	interval string
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("panic: %v\n%s\n", r, string(debug.Stack()))
		}
	}()

	var f flags
	flag.StringVar(&f.cert, "cert", "", "Path to the certificate file.")
	flag.StringVar(&f.key, "key", "", "Path to the key file.")
	flag.StringVar(&f.root, "root", "", "Path to the root bundle of the TLS configuration; optional (the system roots), the monitor itself never connects.")
	flag.StringVar(&f.interval, "interval", "30s", "Interval to check the certificate.")
	flag.Parse()

	if f.cert == "" || f.key == "" {
		fmt.Println("cert and key are required")
		os.Exit(1)
	}

	interval, err := time.ParseDuration(f.interval)
	if err != nil {
		fmt.Println("invalid interval")
		os.Exit(1)
	}

	_, reloader, err := tlsconfig.NewClientTLSWithReloader(
		f.cert,
		f.key,
		f.root,
		interval,
	)
	if err != nil {
		fmt.Printf("failed to create HTTP transport: %s\n", err.Error())
		os.Exit(1)
	}

	// the reloader loads the pair before a handler can be registered:
	// print it here, then on every reload (a renewal rewrites the files)
	printCertificate("certificate loaded", reloader.Keypair())
	reloader.OnReload(func(pair *tls.Certificate) {
		printCertificate("certificate reloaded", pair)
	})

	sigs := make(chan os.Signal, 1)
	// check os signal and exit if SIGINT or SIGTERM is received
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	reloader.Close()
}

// printCertificate prints the leaf of a key pair: a Pod certificate of the
// operator has no common name, so its names are printed as well.
func printCertificate(event string, pair *tls.Certificate) {
	if pair == nil || pair.Leaf == nil {
		fmt.Printf("%s: no certificate\n", event)
		return
	}
	leaf := pair.Leaf
	uris := make([]string, 0, len(leaf.URIs))
	for _, u := range leaf.URIs {
		uris = append(uris, u.String())
	}

	now := time.Now()
	fmt.Printf("%s: %s\n", now.Format(time.RFC3339), event)
	fmt.Printf("  subject: %s\n", leaf.Subject.CommonName)
	fmt.Printf("  dns names: %v\n", leaf.DNSNames)
	fmt.Printf("  ip addresses: %v\n", leaf.IPAddresses)
	fmt.Printf("  uris: %v\n", uris)
	fmt.Printf("  expires at: %s\n", leaf.NotAfter.Format(time.RFC3339))
	fmt.Printf("  issued at: %s\n", leaf.NotBefore.Format(time.RFC3339))
	fmt.Printf("  serial number: %s\n", leaf.SerialNumber.String())
	// the full name: an issuing CA may have no common name
	fmt.Printf("  issuer: %s\n", leaf.Issuer.String())
}
