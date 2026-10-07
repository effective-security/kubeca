package index

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/kubeca/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// CertificateIssuer indexes Certificates by spec.issuerRef.name.
	CertificateIssuer = "spec.issuerRef.name"
	// CertificateServices indexes Certificates by every entry of
	// spec.kubernetesNames.services.
	CertificateServices = "spec.kubernetesNames.services"
)

// Register adds the indexes to the manager's cache.
func Register(ctx context.Context, indexer client.FieldIndexer) error {
	if err := indexer.IndexField(ctx, &v1alpha1.Certificate{}, CertificateIssuer, CertificateIssuerValue); err != nil {
		return errors.WithMessagef(err, "unable to index Certificates by %s", CertificateIssuer)
	}
	if err := indexer.IndexField(ctx, &v1alpha1.Certificate{}, CertificateServices, CertificateServicesValue); err != nil {
		return errors.WithMessagef(err, "unable to index Certificates by %s", CertificateServices)
	}
	return nil
}

// CertificateIssuerValue is the indexer of CertificateIssuer.
func CertificateIssuerValue(obj client.Object) []string {
	cert, ok := obj.(*v1alpha1.Certificate)
	if !ok || cert.Spec.IssuerRef.Name == "" {
		return nil
	}
	return []string{cert.Spec.IssuerRef.Name}
}

// CertificateServicesValue is the indexer of CertificateServices.
func CertificateServicesValue(obj client.Object) []string {
	cert, ok := obj.(*v1alpha1.Certificate)
	if !ok || cert.Spec.KubernetesNames == nil {
		return nil
	}
	return cert.Spec.KubernetesNames.Services
}
