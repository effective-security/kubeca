// Command certmonitor monitors a certificate and its chain. Used to test
// certificate renewal: it loads the key pair (and the root bundle when
// -root is given; the monitor never connects, so it is optional), prints
// the certificate, then checks the files every -interval and prints the
// certificate again each time it was rewritten (a renewal).
//
// Usage:
//
//	certmonitor -cert=.tmp/minikube_api_tls.crt_local -key=.tmp/minikube_api_tls.key_local -root=.tmp/kubeca_root_local.pem -interval=30s
//
// In a Pod, point it at the Secret the operator writes, as
// examples/shop/pod.yaml does with the image effectivesecurity/certmonitor
// (Dockerfile.certmonitor, built and loaded by make minikube-images):
//
//	certmonitor -cert=/etc/tls/tls.crt -key=/etc/tls/tls.key -root=/etc/tls/ca.crt -interval=10s
//
// The image is distroless: it has no shell, ls or cat, so kubectl exec into
// it does not work; read its log, and the files from the Secret.
package main
