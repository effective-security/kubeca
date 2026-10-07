package pod

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/kubeca/api/v1alpha1"
	"github.com/effective-security/kubeca/internal/k8snames"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/csr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/kubeca", "operator/pod")

const (
	// ControllerName is the name of the controller in metrics and logs.
	ControllerName = "pod"
	// podKind is the kind of a Pod owner reference.
	podKind = "Pod"
	// staleOwnerRetry is the requeue delay while the Certificate of a
	// previous Pod of the same name awaits garbage collection.
	staleOwnerRetry = 15 * time.Second
)

// Reconciler reconciles labeled Pods into Certificates.
type Reconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	// ClusterDomain is the suffix of the derived DNS names.
	ClusterDomain string
}

// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups=kubeca.effectivesecurity,resources=certificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kubeca.effectivesecurity,resources=clusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// SetupWithManager registers the controller: it watches labeled Pods, the
// Certificates they own, Services (mapped to the Pods they select) and
// ClusterIssuers (mapped to the Pods that name them).
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named(ControllerName).
		For(&corev1.Pod{}, builder.WithPredicates(predicate.NewPredicateFuncs(Injected))).
		Owns(&v1alpha1.Certificate{}).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(r.podsOfService)).
		Watches(&v1alpha1.ClusterIssuer{}, handler.EnqueueRequestsFromMapFunc(r.podsOfIssuer)).
		Complete(r)
}

// Injected reports whether an object carries the inject label.
func Injected(obj client.Object) bool {
	return obj.GetLabels()[v1alpha1.LabelInject] == v1alpha1.TrueValue
}

// podsOfService enqueues the labeled Pods a Service selects.
func (r *Reconciler) podsOfService(ctx context.Context, obj client.Object) []reconcile.Request {
	svc, ok := obj.(*corev1.Service)
	if !ok || len(svc.Spec.Selector) == 0 {
		return nil
	}
	return r.listRequests(ctx, func(*corev1.Pod) bool { return true },
		client.InNamespace(svc.Namespace), client.MatchingLabels(svc.Spec.Selector))
}

// podsOfIssuer enqueues the labeled Pods annotated with the ClusterIssuer.
func (r *Reconciler) podsOfIssuer(ctx context.Context, obj client.Object) []reconcile.Request {
	name := obj.GetName()
	return r.listRequests(ctx, func(pod *corev1.Pod) bool {
		return pod.Annotations[v1alpha1.AnnotationIssuer] == name
	})
}

func (r *Reconciler) listRequests(ctx context.Context, keep func(*corev1.Pod) bool, opts ...client.ListOption) []reconcile.Request {
	var list corev1.PodList
	if err := r.List(ctx, &list, opts...); err != nil {
		logger.ContextKV(ctx, xlog.ERROR, "reason", "unable to list Pods", "err", err)
		return nil
	}
	var requests []reconcile.Request
	for i := range list.Items {
		pod := &list.Items[i]
		if Injected(pod) && keep(pod) {
			requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}})
		}
	}
	return requests
}

// Reconcile creates or updates the Certificate of a labeled Pod. A Pod
// whose annotations are unusable gets an InvalidPod event and no retry.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.WithMessage(err, "unable to get Pod")
	}
	if !pod.DeletionTimestamp.IsZero() || !Injected(&pod) {
		return ctrl.Result{}, nil
	}
	issuerName := pod.Annotations[v1alpha1.AnnotationIssuer]
	if issuerName == "" {
		r.invalid(ctx, &pod, fmt.Sprintf("annotation %s is required", v1alpha1.AnnotationIssuer))
		return ctrl.Result{}, nil
	}
	spec, err := r.desiredSpec(ctx, &pod, issuerName)
	if err != nil {
		var ierr *invalidPodError
		if errors.As(err, &ierr) {
			r.invalid(ctx, &pod, ierr.Error())
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if len(spec.DNSNames)+len(spec.IPAddresses)+len(spec.URIs)+len(spec.EmailAddresses) == 0 {
		// Nothing to put in the certificate yet. The IP update re-triggers
		// the reconcile, but a Pod whose only Secret volume is the injected
		// one never gets an IP before the Secret exists (the kubelet mounts
		// volumes before creating the sandbox), so say what is missing.
		r.invalid(ctx, &pod, fmt.Sprintf("no name for the certificate: the Pod has no IP yet and no Service selects it, "+
			"no hostname/subdomain, no %s annotation and ClusterIssuer %q has no SPIFFE trust domain", v1alpha1.AnnotationSAN, issuerName))
		return ctrl.Result{}, nil
	}

	// the Certificate controller recomputes this name from the Pod to
	// trust the owner reference for the policy placeholder ${SERVICE_ACCOUNT}
	cert, op, err := r.writeCertificate(ctx, &pod, spec)
	if err != nil {
		var refused *refusedError
		switch {
		case errors.As(err, &refused):
			r.invalid(ctx, &pod, refused.message)
			return ctrl.Result{RequeueAfter: refused.retryAfter}, nil
		case apierrors.IsInvalid(err):
			// rejected by the CRD validation (an annotation such as a
			// duration under 1m): a Pod edit re-triggers the reconcile
			r.invalid(ctx, &pod, fmt.Sprintf("Certificate %q is invalid: %s", cert.Name, err.Error()))
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.WithMessagef(err, "unable to write Certificate %s/%s", cert.Namespace, cert.Name)
	}
	switch op {
	case controllerutil.OperationResultCreated:
		r.Recorder.Eventf(&pod, corev1.EventTypeNormal, v1alpha1.EventCertificateCreated, "Certificate %s created for Secret %s", cert.Name, spec.SecretName)
	case controllerutil.OperationResultUpdated:
		r.Recorder.Eventf(&pod, corev1.EventTypeNormal, v1alpha1.EventCertificateUpdated, "Certificate %s updated", cert.Name)
	default:
		return ctrl.Result{}, nil
	}
	logger.ContextKV(ctx, xlog.INFO,
		"ns", pod.Namespace,
		"pod", pod.Name,
		"status", "certificate_"+string(op),
		"name", cert.Name,
		"issuer", issuerName,
		"profile", spec.Profile,
		"secret", spec.SecretName)
	return ctrl.Result{}, nil
}

// refusedError is an existing Certificate the Pod controller does not own:
// it is never written. retryAfter is non-zero when the obstacle goes away
// by itself (a previous Pod's Certificate awaiting garbage collection).
type refusedError struct {
	message    string
	retryAfter time.Duration
}

func (e *refusedError) Error() string {
	return e.message
}

// writeCertificate creates the Certificate of the Pod, controlled by the
// Pod, or updates the spec of the one the Pod already controls (owner
// reference with the Pod's UID; an existing secretName is kept: it is
// immutable). Any other Certificate of that name, one without a
// controller included, is refused (refusedError): taking it over would
// let anyone who can create a labeled Pod rewrite another workload's
// Certificate and its Secret, and have them garbage-collected with the
// Pod. The returned Certificate carries the name even on error.
func (r *Reconciler) writeCertificate(ctx context.Context, pod *corev1.Pod, spec *v1alpha1.CertificateSpec) (*v1alpha1.Certificate, controllerutil.OperationResult, error) {
	cert := &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: pod.Namespace,
			// the Certificate controller recomputes this name from the Pod
			// to trust the owner reference for ${SERVICE_ACCOUNT}
			Name: v1alpha1.PodCertificateName(pod.Name, pod.Annotations[v1alpha1.AnnotationSecretName]),
		},
	}
	var existing v1alpha1.Certificate
	err := r.Get(ctx, client.ObjectKeyFromObject(cert), &existing)
	if apierrors.IsNotFound(err) {
		cert.Spec = *spec
		// no blockOwnerDeletion: the OwnerReferencesPermissionEnforcement
		// admission plugin would otherwise require update on pods/finalizers
		if err := controllerutil.SetControllerReference(pod, cert, r.Scheme, controllerutil.WithBlockOwnerDeletion(false)); err != nil {
			return cert, controllerutil.OperationResultNone, errors.WithStack(err)
		}
		if err := r.Create(ctx, cert); err != nil {
			return cert, controllerutil.OperationResultNone, err
		}
		return cert, controllerutil.OperationResultCreated, nil
	}
	if err != nil {
		return cert, controllerutil.OperationResultNone, err
	}

	switch owner := metav1.GetControllerOf(&existing); {
	case owner == nil:
		return cert, controllerutil.OperationResultNone, &refusedError{
			message: fmt.Sprintf("Certificate %q exists and is not controlled by this Pod; delete it or rename the Pod", cert.Name),
		}
	case owner.Kind == podKind && owner.Name == pod.Name && owner.UID != pod.UID:
		// a previous Pod of this name: the garbage collector deletes its
		// Certificate, and the deletion enqueues this Pod again (Owns)
		return cert, controllerutil.OperationResultNone, &refusedError{
			message:    fmt.Sprintf("Certificate %q belongs to a previous Pod %q; waiting for its garbage collection", cert.Name, owner.Name),
			retryAfter: staleOwnerRetry,
		}
	case owner.UID != pod.UID:
		return cert, controllerutil.OperationResultNone, &refusedError{
			message: fmt.Sprintf("Certificate %q is owned by %s %q", cert.Name, owner.Kind, owner.Name),
		}
	}

	desired := existing.DeepCopy()
	desired.Spec = *spec
	if existing.Spec.SecretName != "" {
		// immutable once set
		desired.Spec.SecretName = existing.Spec.SecretName
	}
	if equality.Semantic.DeepEqual(existing.Spec, desired.Spec) {
		return desired, controllerutil.OperationResultNone, nil
	}
	if err := r.Update(ctx, desired); err != nil {
		return desired, controllerutil.OperationResultNone, err
	}
	return desired, controllerutil.OperationResultUpdated, nil
}

// invalidPodError is a Pod whose annotations cannot produce a Certificate.
type invalidPodError struct {
	message string
}

func (e *invalidPodError) Error() string {
	return e.message
}

func (r *Reconciler) invalid(ctx context.Context, pod *corev1.Pod, message string) {
	r.Recorder.Event(pod, corev1.EventTypeWarning, v1alpha1.EventInvalidPod, message)
	logger.ContextKV(ctx, xlog.WARNING, "ns", pod.Namespace, "pod", pod.Name, "reason", message)
}

// desiredSpec derives the Certificate spec from the Pod, its Services,
// the issuer's trust domain and the annotations.
func (r *Reconciler) desiredSpec(ctx context.Context, pod *corev1.Pod, issuerName string) (*v1alpha1.CertificateSpec, error) {
	var services corev1.ServiceList
	if err := r.List(ctx, &services, client.InNamespace(pod.Namespace)); err != nil {
		return nil, errors.WithMessagef(err, "unable to list Services in %q", pod.Namespace)
	}
	names := k8snames.ForPod(pod, services.Items, k8snames.Options{ClusterDomain: r.ClusterDomain, IncludeUnqualified: true})
	all := slices.Concat(names.DNS, k8snames.PodIPs(pod), names.IPs)

	var issuer v1alpha1.ClusterIssuer
	if err := r.Get(ctx, client.ObjectKey{Name: issuerName}, &issuer); err != nil && !apierrors.IsNotFound(err) {
		return nil, errors.WithMessagef(err, "unable to get ClusterIssuer %q", issuerName)
	}
	if id := k8snames.SPIFFEID(issuer.TrustDomain(), pod.Namespace, pod.Spec.ServiceAccountName); id != "" {
		all = append(all, id)
	}
	all = slices.AppendSeq(all, k8snames.SplitList(pod.Annotations[v1alpha1.AnnotationSAN]))

	san, err := csr.ParseSAN(all)
	if err != nil {
		return nil, &invalidPodError{message: "invalid names: " + err.Error()}
	}
	spec := &v1alpha1.CertificateSpec{
		IssuerRef:      v1alpha1.IssuerReference{Name: issuerName},
		Profile:        pod.Annotations[v1alpha1.AnnotationProfile],
		SecretName:     v1alpha1.PodSecretName(pod.Name, pod.Annotations[v1alpha1.AnnotationSecretName]),
		DNSNames:       san.DNSNames,
		EmailAddresses: san.EmailAddresses,
	}
	for _, ip := range san.IPAddresses {
		spec.IPAddresses = append(spec.IPAddresses, ip.String())
	}
	for _, u := range san.URIs {
		spec.URIs = append(spec.URIs, u.String())
	}
	if spec.Duration, err = annotationDuration(pod, v1alpha1.AnnotationDuration); err != nil {
		return nil, err
	}
	if spec.RenewBefore, err = annotationDuration(pod, v1alpha1.AnnotationRenewBefore); err != nil {
		return nil, err
	}
	return spec, nil
}

func annotationDuration(pod *corev1.Pod, annotation string) (*metav1.Duration, error) {
	value := pod.Annotations[annotation]
	if value == "" {
		return nil, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return nil, &invalidPodError{message: fmt.Sprintf("annotation %s: %s", annotation, err.Error())}
	}
	return &metav1.Duration{Duration: d}, nil
}
