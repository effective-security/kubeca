package certinit

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/kubeca/internal/k8snames"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/x/print"
	capi "k8s.io/api/certificates/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
)

const (
	randAlphabet            = "0123456789abcdefghijklmnopqrstuvwxyz"
	requestNameSuffixLength = 5

	// pollInterval is the delay between reads of the CSR while waiting for
	// the certificate when the watch is unavailable.
	pollInterval = 5 * time.Second
	// watchRetryDelay is the pause before the CSR is read and watched
	// again after a watch ended without a decision.
	watchRetryDelay = time.Second

	keyFileName  = "tls.key"
	csrFileName  = "tls.csr"
	certFileName = "tls.crt"

	// TODO: for 0600 the POD got access denied (KUBECA-003)
	keyFileMode  = 0644
	fileMode     = 0644
	keyAlgorithm = "ECDSA"
	keySize      = 256
)

var (
	randAlphabetLength = big.NewInt(int64(len(randAlphabet)))
)

// usages maps a profile name to the Kubernetes key usages requested in the
// CSR. Request.Usages overrides it for any profile.
var usages = map[string][]capi.KeyUsage{
	"peer": {
		capi.UsageDigitalSignature,
		capi.UsageKeyEncipherment,
		capi.UsageServerAuth,
		capi.UsageClientAuth,
	},
	"client": {
		capi.UsageDigitalSignature,
		capi.UsageKeyEncipherment,
		capi.UsageClientAuth,
	},
	"server": {
		capi.UsageDigitalSignature,
		capi.UsageKeyEncipherment,
		capi.UsageServerAuth,
	},
}

// profileUsages returns the key usages to request: Request.Usages when set,
// otherwise the built-in list for the profile.
func (r *Request) profileUsages(profile string) ([]capi.KeyUsage, error) {
	if r.Usages != "" {
		var list []capi.KeyUsage
		for u := range k8snames.SplitList(r.Usages) {
			list = append(list, capi.KeyUsage(u))
		}
		if len(list) == 0 {
			return nil, errors.New("invalid usages: " + r.Usages)
		}
		return list, nil
	}
	if list := usages[profile]; list != nil {
		return list, nil
	}
	return nil, errors.New("unsupported profile: " + r.SignerName + "; set usages for a profile other than peer, server or client")
}

func (r *Request) requestCertificate(ctx context.Context, client MinCertificates) error {
	issuerAndProfile := strings.Split(r.SignerName, "/")
	if len(issuerAndProfile) != 2 {
		return errors.New("unsupported signer: " + r.SignerName)
	}

	profileUsages, err := r.profileUsages(issuerAndProfile[1])
	if err != nil {
		return err
	}

	prov := csr.NewProvider(inmemcrypto.NewProvider())
	req := csr.CertificateRequest{
		KeyRequest: prov.NewKeyRequest("", keyAlgorithm, keySize, csr.SigningKey),
		SAN:        r.san,
	}

	pemCsr, pemKeyBytes, _, _, err := prov.CreateRequestAndExportKey(&req)
	if err != nil {
		return errors.WithStack(err)
	}

	keyFile := path.Join(r.CertDir, keyFileName)
	if err := os.WriteFile(keyFile, pemKeyBytes, keyFileMode); err != nil {
		return errors.WithMessage(err, "unable to save key")
	}

	logger.ContextKV(ctx, xlog.INFO, "status", "wrote_key", "file", keyFile)

	csrFile := path.Join(r.CertDir, csrFileName)
	if err := os.WriteFile(csrFile, pemCsr, fileMode); err != nil {
		return errors.WithMessage(err, "unable to save CSR")
	}

	logger.ContextKV(ctx, xlog.INFO, "status", "wrote_csr", "file", csrFile)

	// Submit a certificate signing request, wait for it to be approved, then save
	// the signed certificate to the file system.
	certificateSigningRequestName := r.requestName()
	certificateSigningRequest := &capi.CertificateSigningRequest{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "CertificateSigningRequest",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:   certificateSigningRequestName,
			Labels: r.labelsMap,
		},
		Spec: capi.CertificateSigningRequestSpec{
			Request:    pemCsr,
			Usages:     profileUsages,
			SignerName: r.SignerName,
		},
	}

	_, err = client.Get(ctx, certificateSigningRequestName, metaV1.GetOptions{})
	if err != nil {
		logger.ContextKV(ctx, xlog.DEBUG, "status", "unable to get CSR", "err", err.Error())
		_, err = client.Create(ctx, certificateSigningRequest, metaV1.CreateOptions{})
		if err != nil {
			return errors.WithMessage(err, "unable to create the certificate signing request")
		}
		logger.ContextKV(ctx, xlog.INFO, "status", "waiting for certificate")
	} else {
		logger.ContextKV(ctx, xlog.INFO, "status", "signing request already exists")
	}

	certificate, err := r.waitForCertificate(ctx, client, certificateSigningRequestName)
	if err != nil {
		return err
	}

	chain, err := certutil.ParseChainFromPEM(certificate)
	if err != nil {
		logger.ContextKV(ctx, xlog.ERROR, "reason", "ParseChainFromPEM", "err", err)
		logger.ContextKV(ctx, xlog.DEBUG, "chain", string(certificate))
	} else {
		b := new(strings.Builder)
		print.Certificates(b, chain, false)
		logger.ContextKV(ctx, xlog.DEBUG, "cert", b.String())
	}

	certFile := path.Join(r.CertDir, certFileName)
	if err := os.WriteFile(certFile, certificate, fileMode); err != nil {
		return errors.WithMessage(err, "unable to save certificate")
	}

	logger.ContextKV(ctx, xlog.INFO, "status", "wrote_cert", "file", certFile)

	return nil
}

// waitForCertificate reads the CSR once, then watches it until it carries
// a certificate, a Denied or Failed condition, is deleted, or ctx is done
// (KUBECA-006). When the watch ends without a decision, the CSR is read
// again and the watch reopened after watchRetryDelay; when it cannot be
// opened or reports an error event, after pollInterval.
func (r *Request) waitForCertificate(ctx context.Context, client MinCertificates, name string) ([]byte, error) {
	for {
		delay := pollInterval
		csr, err := client.Get(ctx, name, metaV1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			// If the request got deleted, waiting won't help.
			return nil, errors.New("certificate signing request not found: " + name)
		case err != nil:
			logger.ContextKV(ctx, xlog.ERROR, "status", "unable to retrieve certificate signing request",
				"name", name,
				"err", err.Error(),
			)
		default:
			if cert, done, err := certificateOf(ctx, csr, name); done {
				return cert, err
			}
			logger.ContextKV(ctx, xlog.INFO, "status", "csr not issued, waiting", "name", name)
			cert, done, err := r.watchCertificate(ctx, client, name, csr.ResourceVersion)
			if done {
				return cert, err
			}
			if err == nil {
				// the watch ended: read and watch again after a short pause
				delay = watchRetryDelay
			} else {
				logger.ContextKV(ctx, xlog.WARNING, "status", "unable to watch certificate signing request, polling",
					"name", name,
					"retry", "in "+pollInterval.String(),
					"err", err.Error(),
				)
			}
		}

		select {
		case <-ctx.Done():
			return nil, errors.Wrapf(ctx.Err(), "gave up waiting for certificate signing request %s", name)
		case <-time.After(delay):
		}
	}
}

// watchCertificate follows the CSR from resourceVersion. done is true
// with the outcome; otherwise err is the Watch error or the error event
// the server sent, or nil when the watch ended without a decision.
func (r *Request) watchCertificate(ctx context.Context, client MinCertificates, name, resourceVersion string) (cert []byte, done bool, err error) {
	w, err := client.Watch(ctx, metaV1.ListOptions{
		FieldSelector:   fields.OneTermEqualSelector(metaV1.ObjectNameField, name).String(),
		ResourceVersion: resourceVersion,
	})
	if err != nil {
		return nil, false, errors.WithStack(err)
	}
	defer w.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, true, errors.Wrapf(ctx.Err(), "gave up waiting for certificate signing request %s", name)
		case event, ok := <-w.ResultChan():
			if !ok {
				return nil, false, nil
			}
			switch event.Type {
			case watch.Deleted:
				return nil, true, errors.New("certificate signing request not found: " + name)
			case watch.Added, watch.Modified:
				updated, isCSR := event.Object.(*capi.CertificateSigningRequest)
				if !isCSR {
					continue
				}
				if cert, done, err := certificateOf(ctx, updated, name); done {
					return cert, true, err
				}
			case watch.Error:
				// an API status (410 Gone for a resource version that
				// is too old, a server error): the caller polls
				return nil, false, errors.WithMessage(apierrors.FromObject(event.Object), "watch error event")
			}
		}
	}
}

// certificateOf returns the certificate of an issued CSR, or the error of
// a Denied or Failed one; done is false while the CSR is pending.
func certificateOf(ctx context.Context, csr *capi.CertificateSigningRequest, name string) (cert []byte, done bool, err error) {
	if len(csr.Status.Certificate) > 0 {
		logger.ContextKV(ctx, xlog.INFO, "status", "got certificate", "name", name)
		return csr.Status.Certificate, true, nil
	}
	for _, condition := range csr.Status.Conditions {
		switch condition.Type {
		case capi.CertificateDenied:
			return nil, true, errors.Errorf("certificate signing request (%s) denied for %q: %q", name, condition.Reason, condition.Message)
		case capi.CertificateFailed:
			return nil, true, errors.Errorf("certificate signing request (%s) failed for %q: %q", name, condition.Reason, condition.Message)
		}
	}
	return nil, false, nil
}

func (r *Request) requestName() (name string) {
	name = fmt.Sprintf("%s-%s-", r.PodName, r.Namespace)
	for range requestNameSuffixLength {
		n, err := rand.Int(rand.Reader, randAlphabetLength)
		if err != nil {
			logger.Panicf("failed to generate request name: %v", err)
		}
		name += string(randAlphabet[n.Int64()])
	}
	return
}
