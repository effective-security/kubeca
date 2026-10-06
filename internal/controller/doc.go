// Package controller implements the CertificateSigningRequest signing
// controller behind the kubeca command.
//
// StartCertificateSigningRequestController builds a controller-runtime
// manager, loads the crypto provider and the xpki authority.Authority from
// the configured files and registers CertificateSigningRequestSigningReconciler,
// which signs every CSR without a Denied condition (KUBECA-001) whose
// signerName maps to a loaded issuer and profile.
package controller
