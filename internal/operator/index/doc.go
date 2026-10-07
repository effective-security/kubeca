// Package index registers the field indexes the operator controllers list
// Certificates by, so that a ClusterIssuer or a Service change maps to the
// Certificates it affects. Register once per manager, before the
// controllers start; the tests register the same indexes on the fake
// client with WithIndex.
//
//	if err := index.Register(ctx, mgr.GetFieldIndexer()); err != nil {
//		return err
//	}
//	var certs v1alpha1.CertificateList
//	err := c.List(ctx, &certs, client.MatchingFields{index.CertificateIssuer: issuer.Name})
package index
