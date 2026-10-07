package pod_test

import (
	"context"
	"testing"
	"time"

	"github.com/effective-security/kubeca/api/v1alpha1"
	"github.com/effective-security/kubeca/internal/operator/pod"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	namespace = "shop"
	podName   = "worker-1"
)

func ptr[T any](v T) *T { return &v }

func drain(events chan string) []string {
	var out []string
	for {
		select {
		case e := <-events:
			out = append(out, e)
		default:
			return out
		}
	}
}

type fixture struct {
	client   client.Client
	recorder *record.FakeRecorder
	r        *pod.Reconciler
}

func newFixture(t *testing.T, objs ...client.Object) *fixture {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, v1alpha1.AddToScheme(s))
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
	recorder := record.NewFakeRecorder(20)
	return &fixture{
		client:   c,
		recorder: recorder,
		r: &pod.Reconciler{
			Client:        c,
			Scheme:        s,
			Recorder:      recorder,
			ClusterDomain: "cluster.local",
		},
	}
}

func (f *fixture) reconcile(t *testing.T, name string) *v1alpha1.CertificateList {
	t.Helper()
	res, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, res)
	var list v1alpha1.CertificateList
	require.NoError(t, f.client.List(context.Background(), &list, client.InNamespace(namespace)))
	return &list
}

func issuer() *v1alpha1.ClusterIssuer {
	return &v1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "kubeca"},
		Spec: v1alpha1.ClusterIssuerSpec{
			IssuerLabel: "kubeca.svc",
			SPIFFE:      &v1alpha1.SPIFFESpec{TrustDomain: "example.org"},
		},
	}
}

func workerPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
			UID:       "pod-uid",
			Labels: map[string]string{
				"app":                "worker",
				v1alpha1.LabelInject: v1alpha1.TrueValue,
			},
			Annotations: map[string]string{
				v1alpha1.AnnotationIssuer:  "kubeca",
				v1alpha1.AnnotationProfile: "client-24h",
				v1alpha1.AnnotationSAN:     "localhost, ops@example.org",
			},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "worker",
			Hostname:           "worker-1",
			Subdomain:          "workers",
		},
		Status: corev1.PodStatus{PodIP: "10.1.2.3"},
	}
}

func services() []client.Object {
	return []client.Object{
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: namespace},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "worker"}, ClusterIP: "10.96.0.5"},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "workers", Namespace: namespace},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "worker"}, ClusterIP: corev1.ClusterIPNone},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: namespace},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "other"}, ClusterIP: "10.96.0.6"},
		},
	}
}

func TestReconcileCreatesCertificate(t *testing.T) {
	f := newFixture(t, append(services(), issuer(), workerPod())...)
	list := f.reconcile(t, podName)
	require.Len(t, list.Items, 1)
	cert := list.Items[0]
	assert.Equal(t, podName, cert.Name)
	owner := metav1.GetControllerOf(&cert)
	require.NotNil(t, owner)
	assert.Equal(t, "Pod", owner.Kind)
	assert.Equal(t, types.UID("pod-uid"), owner.UID)
	require.NotNil(t, owner.BlockOwnerDeletion)
	assert.False(t, *owner.BlockOwnerDeletion, "no pods/finalizers permission needed")
	assert.Empty(t, cert.Annotations, "nothing the Certificate controller would have to trust")
	assert.Equal(t, v1alpha1.CertificateSpec{
		IssuerRef:  v1alpha1.IssuerReference{Name: "kubeca"},
		Profile:    "client-24h",
		SecretName: "worker-1-tls",
		DNSNames: []string{
			"10-1-2-3.shop.pod.cluster.local",
			"worker-1.workers.shop.svc.cluster.local",
			"worker-1.workers.shop.svc",
			"worker.shop.svc.cluster.local",
			"worker.shop.svc",
			"workers.shop.svc.cluster.local",
			"workers.shop.svc",
			"localhost",
		},
		IPAddresses:    []string{"10.1.2.3", "10.96.0.5"},
		URIs:           []string{"spiffe://example.org/ns/shop/sa/worker"},
		EmailAddresses: []string{"ops@example.org"},
	}, cert.Spec)
	assert.Equal(t, []string{"Normal CertificateCreated Certificate worker-1 created for Secret worker-1-tls"}, drain(f.recorder.Events))

	// unchanged: no update, no event
	f.reconcile(t, podName)
	assert.Empty(t, drain(f.recorder.Events))

	// the Pod IP changes: the Certificate is updated
	var p corev1.Pod
	require.NoError(t, f.client.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: podName}, &p))
	p.Status.PodIP = "10.1.2.4"
	require.NoError(t, f.client.Status().Update(context.Background(), &p))
	list = f.reconcile(t, podName)
	require.Len(t, list.Items, 1)
	assert.Equal(t, "10-1-2-4.shop.pod.cluster.local", list.Items[0].Spec.DNSNames[0])
	assert.Equal(t, []string{"10.1.2.4", "10.96.0.5"}, list.Items[0].Spec.IPAddresses)
	assert.Equal(t, []string{"Normal CertificateUpdated Certificate worker-1 updated"}, drain(f.recorder.Events))
}

func TestReconcileAnnotations(t *testing.T) {
	p := workerPod()
	p.Annotations[v1alpha1.AnnotationSecretName] = "kubeca-ab12cd34"
	p.Annotations[v1alpha1.AnnotationDuration] = "12h"
	p.Annotations[v1alpha1.AnnotationRenewBefore] = "4h"
	delete(p.Annotations, v1alpha1.AnnotationProfile)
	delete(p.Annotations, v1alpha1.AnnotationSAN)
	p.Spec.Hostname, p.Spec.Subdomain = "", ""
	p.Spec.ServiceAccountName = ""
	// no ClusterIssuer: no SPIFFE ID, the Certificate controller reports the issuer
	f := newFixture(t, p)
	list := f.reconcile(t, podName)
	require.Len(t, list.Items, 1)
	cert := list.Items[0]
	assert.Equal(t, "worker-1-ab12cd34", cert.Name)
	assert.Empty(t, cert.Annotations)
	assert.Equal(t, v1alpha1.CertificateSpec{
		IssuerRef:   v1alpha1.IssuerReference{Name: "kubeca"},
		SecretName:  "kubeca-ab12cd34",
		DNSNames:    []string{"10-1-2-3.shop.pod.cluster.local"},
		IPAddresses: []string{"10.1.2.3"},
		Duration:    &metav1.Duration{Duration: 12 * time.Hour},
		RenewBefore: &metav1.Duration{Duration: 4 * time.Hour},
	}, cert.Spec)
}

func TestReconcileInvalid(t *testing.T) {
	tcases := []struct {
		name   string
		mutate func(*corev1.Pod)
		event  string
	}{
		{
			name:   "no issuer annotation",
			mutate: func(p *corev1.Pod) { delete(p.Annotations, v1alpha1.AnnotationIssuer) },
			event:  "Warning InvalidPod annotation kubeca.effectivesecurity/issuer is required",
		},
		{
			name:   "bad duration",
			mutate: func(p *corev1.Pod) { p.Annotations[v1alpha1.AnnotationDuration] = "soon" },
			event:  `Warning InvalidPod annotation kubeca.effectivesecurity/duration: time: invalid duration "soon"`,
		},
		{
			name:   "bad renew-before",
			mutate: func(p *corev1.Pod) { p.Annotations[v1alpha1.AnnotationRenewBefore] = "1x" },
			event:  `Warning InvalidPod annotation kubeca.effectivesecurity/renew-before: time: unknown unit "x" in duration "1x"`,
		},
		{
			name:   "bad san",
			mutate: func(p *corev1.Pod) { p.Annotations[v1alpha1.AnnotationSAN] = "bad..name" },
			event:  `Warning InvalidPod invalid names: invalid SAN "bad..name": empty DNS label`,
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			p := workerPod()
			tc.mutate(p)
			f := newFixture(t, issuer(), p)
			list := f.reconcile(t, podName)
			assert.Empty(t, list.Items)
			assert.Equal(t, []string{tc.event}, drain(f.recorder.Events))
		})
	}
}

func TestReconcileSkips(t *testing.T) {
	// not labeled
	p := workerPod()
	p.Labels = map[string]string{"app": "worker"}
	f := newFixture(t, issuer(), p)
	assert.Empty(t, f.reconcile(t, podName).Items)

	// no names yet: no IP, no Services, no trust domain, no san; said on
	// the Pod because the injected Secret volume keeps it from getting an IP
	p = workerPod()
	p.Status.PodIP = ""
	p.Spec.Hostname = ""
	delete(p.Annotations, v1alpha1.AnnotationSAN)
	ci := issuer()
	ci.Spec.SPIFFE = nil
	f = newFixture(t, ci, p)
	assert.Empty(t, f.reconcile(t, podName).Items)
	assert.Equal(t, []string{"Warning InvalidPod no name for the certificate: the Pod has no IP yet and no Service selects it, " +
		"no hostname/subdomain, no kubeca.effectivesecurity/san annotation and ClusterIssuer \"kubeca\" has no SPIFFE trust domain"}, drain(f.recorder.Events))

	// deleted
	f = newFixture(t)
	assert.Empty(t, f.reconcile(t, podName).Items)
}

func TestReconcileAlreadyOwned(t *testing.T) {
	existing := &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1",
				Kind:       "StatefulSet",
				Name:       "workers",
				UID:        "sts-uid",
				Controller: ptr(true),
			}},
		},
		Spec: v1alpha1.CertificateSpec{IssuerRef: v1alpha1.IssuerReference{Name: "kubeca"}, DNSNames: []string{"x"}},
	}
	f := newFixture(t, issuer(), workerPod(), existing)
	list := f.reconcile(t, podName)
	require.Len(t, list.Items, 1)
	assert.Equal(t, []string{"x"}, list.Items[0].Spec.DNSNames, "untouched")
	assert.Equal(t, []string{`Warning InvalidPod Certificate "worker-1" is owned by StatefulSet "workers"`}, drain(f.recorder.Events))
}

// TestReconcileRefusesForeignCertificate: an existing Certificate with the
// Pod's Certificate name that this Pod does not control is never written,
// whoever created it: a labeled Pod must not take over another workload's
// Certificate (and its Secret, and have both garbage-collected with it).
func TestReconcileRefusesForeignCertificate(t *testing.T) {
	foreign := func(owners ...metav1.OwnerReference) *v1alpha1.Certificate {
		return &v1alpha1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: namespace, OwnerReferences: owners},
			Spec: v1alpha1.CertificateSpec{
				IssuerRef:  v1alpha1.IssuerReference{Name: "kubeca"},
				SecretName: "web-tls",
				DNSNames:   []string{"web.shop.svc"},
			},
		}
	}
	previousPod := metav1.OwnerReference{APIVersion: "v1", Kind: "Pod", Name: podName, UID: "old-pod-uid", Controller: ptr(true)}
	tcases := []struct {
		name    string
		cert    *v1alpha1.Certificate
		message string
		result  ctrl.Result
	}{
		{
			name:    "no controller",
			cert:    foreign(),
			message: `Warning InvalidPod Certificate "worker-1" exists and is not controlled by this Pod; delete it or rename the Pod`,
		},
		{
			name:    "a previous Pod of the same name",
			cert:    foreign(previousPod),
			message: `Warning InvalidPod Certificate "worker-1" belongs to a previous Pod "worker-1"; waiting for its garbage collection`,
			result:  ctrl.Result{RequeueAfter: 15 * time.Second},
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, append(services(), issuer(), workerPod(), tc.cert)...)
			res, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: podName}})
			require.NoError(t, err)
			assert.Equal(t, tc.result, res)
			var got v1alpha1.Certificate
			require.NoError(t, f.client.Get(context.Background(), client.ObjectKeyFromObject(tc.cert), &got))
			assert.Equal(t, tc.cert.Spec, got.Spec, "untouched")
			assert.Equal(t, tc.cert.OwnerReferences, got.OwnerReferences, "not adopted")
			assert.Equal(t, []string{tc.message}, drain(f.recorder.Events))
		})
	}
}

func TestInjected(t *testing.T) {
	t.Parallel()
	assert.True(t, pod.Injected(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{v1alpha1.LabelInject: "true"}}}))
	assert.False(t, pod.Injected(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{v1alpha1.LabelInject: "yes"}}}))
}
