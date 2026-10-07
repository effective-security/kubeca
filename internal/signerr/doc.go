// Package signerr classifies the errors xpki's authority.Issuer.Sign
// returns into permanent failures (a request the policy or the parser
// rejects, which no retry fixes) and transient ones (the crypto provider,
// KMS or anything unknown). xpki v1.0 returns untyped errors, so the split
// matches the messages of authority/issuer.go and csr/san.go; an unknown
// message is transient, the conservative choice (KUBECA-013). Shared by
// the CSR signer (internal/controller) and the Certificate controller
// (internal/operator/certificate).
//
//	if _, _, err := issuer.Sign(req); err != nil && signerr.IsPermanent(err) {
//		// record the failure on the object, do not retry
//	}
package signerr
