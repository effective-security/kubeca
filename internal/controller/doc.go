// Package controller implements the CertificateSigningRequest signing
// controller of the kubeca command: CertificateSigningRequestSigningReconciler
// signs every CSR whose signerName maps to a loaded issuer and profile,
// after the in-process approver has approved it when -approve is enforce
// (KUBECA-001). A CSR the issuer rejects on its content gets the Failed
// condition instead of endless retries (KUBECA-013).
//
// LoadAuthority loads the crypto provider and the xpki authority.Authority
// from the configured files; cmd/kubeca builds the manager, registers the
// reconciler and, with -enable-operator, the operator controllers
// (internal/operator).
//
//	ca, err := controller.LoadAuthority(caCfgPath, hsmCfgPath)
//	...
//	err = (&controller.CertificateSigningRequestSigningReconciler{
//		Client:        mgr.GetClient(),
//		APIReader:     mgr.GetAPIReader(),
//		Scheme:        mgr.GetScheme(),
//		Authority:     ca,
//		EventRecorder: mgr.GetEventRecorderFor("kubeca-csr-signer"),
//		ApproveMode:   controller.ApproveEnforce,
//		AllowedNames:  []string{"localhost", "127.0.0.1"},
//		ClusterDomain: "cluster.local",
//	}).SetupWithManager(mgr)
package controller
