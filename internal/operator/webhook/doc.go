// Package webhook implements the operator's mutating admission webhook for
// Pods and the bootstrap of its own serving certificate.
//
// PodMutator handles Pod CREATE for Pods labeled
// kubeca.effectivesecurity/inject=true: it fixes the Secret name (the
// secret-name annotation; a generated kubeca-<8 chars> for generateName
// Pods, <name>-tls otherwise), adds the Secret volume and mounts it into
// the containers of the containers annotation (default all) at the
// mount-path annotation (default /etc/tls). The Pod controller then
// creates the Certificate. Mutate is the pure function the handler
// applies, so the tests check the patch without an admission server.
//
// ServingCertificate issues the webhook's TLS certificate from the
// Authority (D-6: self-issued, in process, no Secret to mount before the
// Pod runs), writes it to the directory the controller-runtime webhook
// server watches, renews it at two thirds of its lifetime, and patches the
// caBundle of the MutatingWebhookConfiguration with the root bundle.
package webhook
