// Package testauthority builds an xpki authority.Authority for unit tests:
// a root and an issuing CA generated with xpki's testca, their keys in
// memory (inmemcrypto), and the profiles of testdata/ca-config.yaml (the
// chart's profiles without the Helm templating) loaded through
// authority.LoadConfig. It is imported by tests only (internal/controller,
// internal/operator/*); no non-test code depends on it.
//
//	ca := testauthority.New(t) // issuer label testauthority.IssuerLabel
package testauthority
