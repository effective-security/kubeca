package issuer

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/kubeca/api/v1alpha1"
	"github.com/effective-security/kubeca/internal/operator/index"
	"github.com/effective-security/kubeca/internal/operator/metrics"
	"github.com/effective-security/kubeca/internal/operator/policy"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/authority"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/kubeca", "operator/issuer")

const (
	// ControllerName is the name of the controller in metrics and logs.
	ControllerName = "clusterissuer"

	// recheckInterval bounds the time between two evaluations of a Ready
	// issuer, so the CAExpiring transition is never missed.
	recheckInterval = time.Hour
	// minRequeue is the shortest requeue delay.
	minRequeue = time.Minute
	// defaultBackdate is xpki's backdate for a profile without one.
	defaultBackdate = 5 * time.Minute
)

// Reconciler reconciles ClusterIssuers.
type Reconciler struct {
	client.Client
	// APIReader reads ConfigMaps the cache does not hold (not labeled
	// managed=true) before creating one.
	APIReader client.Reader
	Scheme    *runtime.Scheme
	Authority *authority.Authority
	Recorder  record.EventRecorder
	// Clock is the time source; tests inject a fake.
	Clock clock.Clock
}

// +kubebuilder:rbac:groups=kubeca.effectivesecurity,resources=clusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=kubeca.effectivesecurity,resources=clusterissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=kubeca.effectivesecurity,resources=certificates,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// SetupWithManager registers the controller: it watches ClusterIssuers and,
// for the CA bundle ConfigMaps, the creation and deletion of Certificates
// and the updates that move one to another issuer (IssuerRefChanged; the
// map handler enqueues the issuers of the old and the new object).
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named(ControllerName).
		For(&v1alpha1.ClusterIssuer{}).
		Watches(&v1alpha1.Certificate{},
			handler.EnqueueRequestsFromMapFunc(mapCertificateToIssuer),
			builder.WithPredicates(IssuerRefChanged)).
		Complete(r)
}

// IssuerRefChanged passes the creation and deletion of a Certificate and
// the updates that change spec.issuerRef.name, the only updates that
// change the namespaces an issuer publishes its CA bundle into.
var IssuerRefChanged = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		before, ok := e.ObjectOld.(*v1alpha1.Certificate)
		after, ok2 := e.ObjectNew.(*v1alpha1.Certificate)
		return ok && ok2 && before.Spec.IssuerRef.Name != after.Spec.IssuerRef.Name
	},
}

// mapCertificateToIssuer enqueues the ClusterIssuer a Certificate refers to.
func mapCertificateToIssuer(_ context.Context, obj client.Object) []reconcile.Request {
	cert, ok := obj.(*v1alpha1.Certificate)
	if !ok || cert.Spec.IssuerRef.Name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: cert.Spec.IssuerRef.Name}}}
}

// Reconcile evaluates the ClusterIssuer, patches its status when it changed
// and maintains the CA bundle ConfigMaps: written while the issuer is
// Ready, pruned whatever its state. Only API errors are returned.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var ci v1alpha1.ClusterIssuer
	if err := r.Get(ctx, req.NamespacedName, &ci); err != nil {
		if apierrors.IsNotFound(err) {
			metrics.ClusterIssuerCAExpiration.DeleteLabelValues(req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.WithMessage(err, "unable to get ClusterIssuer")
	}
	if !ci.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	orig := ci.DeepCopy()
	now := r.Clock.Now()
	requeueAfter := r.evaluate(&ci, now)

	ready := meta.FindStatusCondition(ci.Status.Conditions, v1alpha1.ConditionReady)
	if before := meta.FindStatusCondition(orig.Status.Conditions, v1alpha1.ConditionReady); before == nil || before.Status != ready.Status || before.Reason != ready.Reason {
		eventType, eventReason := corev1.EventTypeWarning, ready.Reason
		if ready.Reason == v1alpha1.ReasonLoaded {
			eventType, eventReason = corev1.EventTypeNormal, v1alpha1.EventReady
		}
		r.Recorder.Event(&ci, eventType, eventReason, ready.Message)
		logger.ContextKV(ctx, xlog.INFO,
			"name", ci.Name,
			"issuer", ci.Spec.IssuerLabel,
			"status", string(ready.Status),
			"condition", ready.Reason,
			"reason", ready.Message)
	}
	if !equality.Semantic.DeepEqual(orig.Status, ci.Status) {
		if err := r.Status().Patch(ctx, &ci, client.MergeFrom(orig)); err != nil {
			return ctrl.Result{}, errors.WithMessage(err, "unable to patch ClusterIssuer status")
		}
	}
	namespaces, err := r.certificateNamespaces(ctx, &ci)
	if err != nil {
		return ctrl.Result{}, err
	}
	if ready.Status == metav1.ConditionTrue && ci.Spec.CABundle != nil {
		if err := r.publishCABundle(ctx, &ci, namespaces); err != nil {
			return ctrl.Result{}, err
		}
	}
	if err := r.pruneCABundles(ctx, &ci, namespaces); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// evaluate computes the status from the Authority and the clock and
// returns the delay until the next time-driven re-evaluation (0: none).
func (r *Reconciler) evaluate(ci *v1alpha1.ClusterIssuer, now time.Time) time.Duration {
	issuer, err := r.Authority.GetIssuerByLabel(ci.Spec.IssuerLabel)
	if err != nil {
		r.setNotReady(ci, v1alpha1.ReasonIssuerNotFound,
			fmt.Sprintf("issuer %q is not loaded in the CA configuration", ci.Spec.IssuerLabel), now)
		return 0
	}

	// status.profiles is sorted by name (the API contract), whatever the
	// order of spec.profiles
	exposed := slices.Sorted(slices.Values(ci.Spec.Profiles))
	if len(exposed) == 0 {
		exposed = slices.Sorted(maps.Keys(issuer.Profiles()))
	}
	profiles := make([]v1alpha1.ProfileStatus, 0, len(exposed))
	var maxExpiry time.Duration
	for _, name := range exposed {
		profile := issuer.Profile(name)
		if profile == nil {
			r.setNotReady(ci, v1alpha1.ReasonProfileNotFound,
				fmt.Sprintf("profile %q is not served by issuer %q", name, ci.Spec.IssuerLabel), now)
			return 0
		}
		expiry := profile.Expiry.TimeDuration()
		maxExpiry = max(maxExpiry, expiry)
		profiles = append(profiles, v1alpha1.ProfileStatus{
			Name:     name,
			Expiry:   metav1.Duration{Duration: expiry},
			Backdate: metav1.Duration{Duration: Backdate(profile)},
			Usages:   slices.Clone(profile.Usage),
		})
	}
	if name := ci.Spec.DefaultProfile; name != "" && issuer.Profile(name) == nil {
		r.setNotReady(ci, v1alpha1.ReasonProfileNotFound,
			fmt.Sprintf("default profile %q is not served by issuer %q", name, ci.Spec.IssuerLabel), now)
		return 0
	}
	if err := policy.Compile(ci.Spec.Policy); err != nil {
		r.setNotReady(ci, v1alpha1.ReasonInvalidPolicy, "policy: "+err.Error(), now)
		return 0
	}

	bundle := issuer.Bundle()
	caNotAfter := bundle.Cert.NotAfter
	ci.Status.IssuerKeyID = issuer.SubjectKID()
	ci.Status.CACertificate = strings.TrimSpace(issuer.PEM()) + "\n"
	ci.Status.RootCertificate = RootPEM(r.Authority, issuer)
	ci.Status.CANotAfter = &metav1.Time{Time: caNotAfter}
	ci.Status.Profiles = profiles
	metrics.ClusterIssuerCAExpiration.WithLabelValues(ci.Name).Set(float64(caNotAfter.Unix()))

	// the longest certificate the issuer can sign: policy.BoundDuration
	// bounds a lifetime by the profile expiry and by maxDuration
	bound := maxExpiry
	if maxDuration := policy.MaxDuration(ci.Spec.Policy); maxDuration > 0 && (bound == 0 || maxDuration < bound) {
		bound = maxDuration
	}
	switch {
	case !caNotAfter.After(now):
		r.setNotReady(ci, v1alpha1.ReasonCAExpired,
			fmt.Sprintf("issuing certificate of %q expired at %s", ci.Spec.IssuerLabel, caNotAfter.UTC().Format(time.RFC3339)), now)
		return 0
	case caNotAfter.Before(now.Add(bound)):
		r.setCondition(ci, metav1.ConditionTrue, v1alpha1.ReasonCAExpiring,
			fmt.Sprintf("issuing certificate of %q expires at %s, within the maximum lifetime %s; issued certificates are clipped",
				ci.Spec.IssuerLabel, caNotAfter.UTC().Format(time.RFC3339), bound), now)
		return clamp(caNotAfter.Sub(now))
	default:
		r.setCondition(ci, metav1.ConditionTrue, v1alpha1.ReasonLoaded,
			fmt.Sprintf("issuer %s, %d profiles", ci.Spec.IssuerLabel, len(profiles)), now)
		return clamp(caNotAfter.Add(-bound).Sub(now))
	}
}

// clamp bounds a requeue delay to [minRequeue, recheckInterval].
func clamp(d time.Duration) time.Duration {
	return min(max(d, minRequeue), recheckInterval)
}

func (r *Reconciler) setNotReady(ci *v1alpha1.ClusterIssuer, reason, message string, now time.Time) {
	ci.Status.IssuerKeyID = ""
	ci.Status.CACertificate = ""
	ci.Status.RootCertificate = ""
	ci.Status.CANotAfter = nil
	ci.Status.Profiles = nil
	metrics.ClusterIssuerCAExpiration.DeleteLabelValues(ci.Name)
	r.setCondition(ci, metav1.ConditionFalse, reason, message, now)
}

func (r *Reconciler) setCondition(ci *v1alpha1.ClusterIssuer, status metav1.ConditionStatus, reason, message string, now time.Time) {
	meta.SetStatusCondition(&ci.Status.Conditions, metav1.Condition{
		Type:               v1alpha1.ConditionReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: ci.Generation,
		LastTransitionTime: metav1.NewTime(now),
	})
}

// certificateNamespaces returns the namespaces that hold a Certificate of
// the ClusterIssuer (the issuer index).
func (r *Reconciler) certificateNamespaces(ctx context.Context, ci *v1alpha1.ClusterIssuer) (sets.Set[string], error) {
	var list v1alpha1.CertificateList
	if err := r.List(ctx, &list, client.MatchingFields{index.CertificateIssuer: ci.Name}); err != nil {
		return nil, errors.WithMessage(err, "unable to list Certificates")
	}
	namespaces := sets.New[string]()
	for _, cert := range list.Items {
		namespaces.Insert(cert.Namespace)
	}
	return namespaces, nil
}

// pruneCABundles deletes the CA bundle ConfigMaps the ClusterIssuer
// controls (managed label, controller reference with its UID) that are no
// longer wanted: in a namespace without a Certificate of the issuer, under
// a previous spec.caBundle.configMapName, or all of them without
// spec.caBundle. Others' ConfigMaps are never touched.
func (r *Reconciler) pruneCABundles(ctx context.Context, ci *v1alpha1.ClusterIssuer, namespaces sets.Set[string]) error {
	var list corev1.ConfigMapList
	if err := r.List(ctx, &list, client.MatchingLabels{v1alpha1.LabelManaged: v1alpha1.TrueValue}); err != nil {
		return errors.WithMessage(err, "unable to list ConfigMaps")
	}
	for i := range list.Items {
		cm := &list.Items[i]
		owner := metav1.GetControllerOf(cm)
		if owner == nil || owner.UID != ci.UID || owner.Kind != v1alpha1.KindClusterIssuer {
			continue
		}
		if ci.Spec.CABundle != nil && cm.Name == ci.Spec.CABundle.ConfigMapName && namespaces.Has(cm.Namespace) {
			continue
		}
		if err := r.Delete(ctx, cm); err != nil && !apierrors.IsNotFound(err) {
			return errors.WithMessagef(err, "unable to delete ConfigMap %s/%s", cm.Namespace, cm.Name)
		}
		logger.ContextKV(ctx, xlog.INFO,
			"name", ci.Name,
			"status", "ca_bundle_deleted",
			"ns", cm.Namespace,
			"configmap", cm.Name)
	}
	return nil
}

// publishCABundle writes the root bundle into spec.caBundle.configMapName
// in every namespace that holds a Certificate of this issuer. The
// ConfigMaps are owned by the ClusterIssuer and carry the managed label; a
// ConfigMap of that name that is controlled by something else (another
// ClusterIssuer with the same configMapName included), or has no
// controller and no managed label (the cache holds managed ones only, so
// it is read uncached), is left alone and reported with a Warning event.
func (r *Reconciler) publishCABundle(ctx context.Context, ci *v1alpha1.ClusterIssuer, namespaces sets.Set[string]) error {
	for _, ns := range sets.List(namespaces) {
		if err := r.writeCABundle(ctx, ci, ns); err != nil {
			return err
		}
	}
	return nil
}

// configMapConflict says why an existing ConfigMap cannot hold the CA
// bundle of the ClusterIssuer, or "". Ours: controlled by a ClusterIssuer
// of this name (a stale reference of a deleted one with the same name is
// replaced, as SetControllerReference does), or without a controller and
// labeled managed. A ConfigMap controlled by another ClusterIssuer that
// publishes into the same name is not taken over: SetControllerReference
// would refuse it on every reconcile.
func configMapConflict(ci *v1alpha1.ClusterIssuer, cm *corev1.ConfigMap, key client.ObjectKey) string {
	owner := metav1.GetControllerOf(cm)
	switch {
	case owner != nil && (owner.APIVersion != v1alpha1.GroupVersion.String() || owner.Kind != v1alpha1.KindClusterIssuer || owner.Name != ci.Name):
		return fmt.Sprintf("ConfigMap %s is controlled by %s %q; use another spec.caBundle.configMapName", key, owner.Kind, owner.Name)
	case owner == nil && cm.Labels[v1alpha1.LabelManaged] != v1alpha1.TrueValue:
		return fmt.Sprintf("ConfigMap %s exists and is not managed by kubeca; delete it or change spec.caBundle.configMapName", key)
	}
	return ""
}

func (r *Reconciler) writeCABundle(ctx context.Context, ci *v1alpha1.ClusterIssuer, ns string) error {
	key := client.ObjectKey{Namespace: ns, Name: ci.Spec.CABundle.ConfigMapName}
	var cm corev1.ConfigMap
	err := r.Get(ctx, key, &cm)
	if apierrors.IsNotFound(err) {
		err = r.APIReader.Get(ctx, key, &cm)
	}
	create := apierrors.IsNotFound(err)
	if err != nil && !create {
		return errors.WithMessagef(err, "unable to get ConfigMap %s", key)
	}
	if !create {
		if msg := configMapConflict(ci, &cm, key); msg != "" {
			r.Recorder.Event(ci, corev1.EventTypeWarning, v1alpha1.EventConfigMapConflict, msg)
			logger.ContextKV(ctx, xlog.WARNING, "name", ci.Name, "ns", ns, "reason", msg)
			return nil
		}
	}
	desired := cm.DeepCopy()
	desired.Name, desired.Namespace = key.Name, key.Namespace
	if desired.Labels == nil {
		desired.Labels = map[string]string{}
	}
	desired.Labels[v1alpha1.LabelManaged] = v1alpha1.TrueValue
	if desired.Annotations == nil {
		desired.Annotations = map[string]string{}
	}
	desired.Annotations[v1alpha1.AnnotationIssuer] = ci.Name
	desired.Data = map[string]string{
		v1alpha1.SecretKeyCA: ci.Status.RootCertificate,
	}
	// no blockOwnerDeletion: the OwnerReferencesPermissionEnforcement
	// admission plugin would otherwise require update on
	// clusterissuers/finalizers
	if err := controllerutil.SetControllerReference(ci, desired, r.Scheme, controllerutil.WithBlockOwnerDeletion(false)); err != nil {
		return errors.WithMessagef(err, "unable to own ConfigMap %s", key)
	}
	op := controllerutil.OperationResultNone
	switch {
	case create:
		if err := r.Create(ctx, desired); err != nil {
			return errors.WithMessagef(err, "unable to create ConfigMap %s", key)
		}
		op = controllerutil.OperationResultCreated
	case !equality.Semantic.DeepEqual(cm, *desired):
		if err := r.Update(ctx, desired); err != nil {
			return errors.WithMessagef(err, "unable to update ConfigMap %s", key)
		}
		op = controllerutil.OperationResultUpdated
	}
	if op != controllerutil.OperationResultNone {
		logger.ContextKV(ctx, xlog.INFO,
			"name", ci.Name,
			"status", "ca_bundle_"+string(op),
			"ns", ns,
			"configmap", key.Name)
	}
	return nil
}

// Backdate returns the profile backdate, or xpki's 5 minute default.
func Backdate(profile *authority.CertProfile) time.Duration {
	if d := profile.Backdate.TimeDuration(); d != 0 {
		return d
	}
	return defaultBackdate
}

// RootPEM returns the root bundle of an issuer, PEM with a trailing
// newline: the root of the issuer's chain, or the Authority's configured
// root bundle when the chain has none.
func RootPEM(ca *authority.Authority, issuer *authority.Issuer) string {
	root := strings.TrimSpace(issuer.Bundle().RootCertPEM)
	if root == "" {
		root = strings.TrimSpace(string(ca.RootBundle))
	}
	if root == "" {
		return ""
	}
	return root + "\n"
}
