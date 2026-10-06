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

	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/x/print"
	"github.com/pkg/errors"
	capi "k8s.io/api/certificates/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	randAlphabet            = "0123456789abcdefghijklmnopqrstuvwxyz"
	requestNameSuffixLength = 5

	// pollInterval is the delay between reads of the CSR while waiting for
	// the certificate.
	pollInterval = 5 * time.Second

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
		for u := range splitList(r.Usages) {
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

// waitForCertificate polls the CSR every pollInterval until it carries a
// certificate, a Denied or Failed condition, is deleted, or ctx is done.
func (r *Request) waitForCertificate(ctx context.Context, client MinCertificates, name string) ([]byte, error) {
	for {
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
		case len(csr.Status.Certificate) > 0:
			logger.ContextKV(ctx, xlog.INFO, "status", "got certificate")
			return csr.Status.Certificate, nil
		default:
			for _, condition := range csr.Status.Conditions {
				switch condition.Type {
				case capi.CertificateDenied:
					return nil, errors.Errorf("certificate signing request (%s) denied for %q: %q", name, condition.Reason, condition.Message)
				case capi.CertificateFailed:
					return nil, errors.Errorf("certificate signing request (%s) failed for %q: %q", name, condition.Reason, condition.Message)
				}
			}

			logger.ContextKV(ctx, xlog.INFO, "status", "csr not issued",
				"name", name,
				"retry", "in "+pollInterval.String(),
			)
		}

		select {
		case <-ctx.Done():
			return nil, errors.Wrapf(ctx.Err(), "gave up waiting for certificate signing request %s", name)
		case <-time.After(pollInterval):
		}
	}
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
