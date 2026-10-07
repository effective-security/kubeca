// Package operator wires the KubeCA operator into a controller-runtime
// manager: the scheme, the informer cache restrictions, the field indexes,
// the ClusterIssuer, Certificate and Pod controllers and the Pod mutating
// webhook with its self-issued serving certificate. The command
// cmd/kubeca calls it when -enable-operator is set:
//
//	scheme, err := operator.Scheme()
//	if err != nil {
//		return err
//	}
//	opts := operator.Options{ClusterDomain: "cluster.local"}
//	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
//		Scheme:        scheme,
//		Cache:         operator.CacheOptions(),
//		WebhookServer: operator.WebhookServer(opts.Webhook),
//	})
//	if err != nil {
//		return err
//	}
//	if err := operator.Setup(ctx, mgr, authority, opts); err != nil {
//		return err
//	}
//
// The sub-packages do not import each other: shared helpers live in
// policy, index, metrics and internal/k8snames.
package operator
