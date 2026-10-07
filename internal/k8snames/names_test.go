package k8snames_test

import (
	"slices"
	"testing"

	"github.com/effective-security/kubeca/internal/k8snames"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSplitList(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"a", "b", "c d"}, slices.Collect(k8snames.SplitList(" a, b ,,c d, ")))
	assert.Nil(t, slices.Collect(k8snames.SplitList(" , ")))
	assert.Nil(t, slices.Collect(k8snames.SplitList("")))
}

func TestServiceNames(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"web.shop.svc.cluster.local"}, k8snames.ServiceNames("web", "shop", k8snames.Options{}))
	assert.Equal(t, []string{"web.shop.svc.example.org", "web.shop.svc"},
		k8snames.ServiceNames("web", "shop", k8snames.Options{ClusterDomain: "example.org", IncludeUnqualified: true}))
}

func TestPodDNSName(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "", k8snames.PodDNSName("", "shop", k8snames.Options{}))
	assert.Equal(t, "10-1-2-3.shop.pod.cluster.local", k8snames.PodDNSName("10.1.2.3", "shop", k8snames.Options{}))
	assert.Equal(t, "fd00--1.shop.pod.cluster.local", k8snames.PodDNSName("fd00::1", "shop", k8snames.Options{}))
}

func TestSPIFFEID(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "", k8snames.SPIFFEID("", "shop", "web"))
	assert.Equal(t, "spiffe://example.org/ns/shop/sa/web", k8snames.SPIFFEID("example.org", "shop", "web"))
	assert.Equal(t, "spiffe://example.org/ns/shop/sa/default", k8snames.SPIFFEID("example.org", "shop", ""))
}

func testPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-1",
			Namespace: "test",
			Labels: map[string]string{
				"app": "svc1",
			},
		},
		Spec: corev1.PodSpec{
			Hostname:  "pod1",
			Subdomain: "headless",
		},
		Status: corev1.PodStatus{
			PodIP: "10.1.2.3",
		},
	}
}

func testServices() []corev1.Service {
	return []corev1.Service{
		{
			// selects the pod: service DNS names, both ClusterIPs and external IPs are added
			ObjectMeta: metav1.ObjectMeta{Name: "service1", Namespace: "test"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{
					"app": "svc1",
				},
				ClusterIP:   "10.0.0.1",
				ClusterIPs:  []string{"10.0.0.1", "fd00::1"},
				ExternalIPs: []string{"192.0.2.10"},
			},
		},
		{
			// headless and selecting the pod: DNS names only, no "None" (KUBECA-007)
			ObjectMeta: metav1.ObjectMeta{Name: "headless", Namespace: "test"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{
					"app": "svc1",
				},
				ClusterIP: corev1.ClusterIPNone,
			},
		},
		{
			// ExternalName selecting the pod: the external name is a DNS name
			ObjectMeta: metav1.ObjectMeta{Name: "alias", Namespace: "test"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{
					"app": "svc1",
				},
				Type:         corev1.ServiceTypeExternalName,
				ExternalName: "alias.example.org",
			},
		},
		{
			// selector does not match the pod: ignored
			ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "test"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{
					"app": "other",
				},
				ClusterIP: "10.0.0.2",
			},
		},
		{
			// another namespace: ignored even when the selector matches
			ObjectMeta: metav1.ObjectMeta{Name: "foreign", Namespace: "elsewhere"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{
					"app": "svc1",
				},
				ClusterIP: "10.0.0.4",
			},
		},
		{
			// no selector: ignored
			ObjectMeta: metav1.ObjectMeta{Name: "external", Namespace: "test"},
			Spec:       corev1.ServiceSpec{ClusterIP: "10.0.0.3"},
		},
		{
			// empty selector: ignored like no selector, not matched against every Pod
			ObjectMeta: metav1.ObjectMeta{Name: "empty", Namespace: "test"},
			Spec: corev1.ServiceSpec{
				Selector:  map[string]string{},
				ClusterIP: "10.0.0.5",
			},
		},
	}
}

func TestForPod(t *testing.T) {
	t.Parallel()
	names := k8snames.ForPod(testPod(), testServices(), k8snames.Options{ClusterDomain: "cluster.local", IncludeUnqualified: true})
	assert.Equal(t, []string{
		"10-1-2-3.test.pod.cluster.local",
		"pod1.headless.test.svc.cluster.local",
		"pod1.headless.test.svc",
		"service1.test.svc.cluster.local",
		"service1.test.svc",
		"headless.test.svc.cluster.local",
		"headless.test.svc",
		"alias.test.svc.cluster.local",
		"alias.test.svc",
		"alias.example.org",
	}, names.DNS)
	assert.Equal(t, []string{"10.0.0.1", "fd00::1", "192.0.2.10"}, names.IPs)
	assert.Equal(t, append(slices.Clone(names.DNS), names.IPs...), names.All())

	// no IP, no hostname: only the Service names, qualified
	pod := testPod()
	pod.Status.PodIP = ""
	pod.Spec.Hostname = ""
	names = k8snames.ForPod(pod, testServices(), k8snames.Options{})
	assert.Equal(t, []string{
		"service1.test.svc.cluster.local",
		"headless.test.svc.cluster.local",
		"alias.test.svc.cluster.local",
		"alias.example.org",
	}, names.DNS)
	assert.Equal(t, []string{"10.0.0.1", "fd00::1", "192.0.2.10"}, names.IPs)

	// no Services at all
	names = k8snames.ForPod(pod, nil, k8snames.Options{})
	assert.Empty(t, names.DNS)
	assert.Empty(t, names.IPs)
	assert.Empty(t, names.All())
}

func TestPodIPs(t *testing.T) {
	t.Parallel()
	assert.Nil(t, k8snames.PodIPs(&corev1.Pod{}))
	assert.Equal(t, []string{"10.1.2.3"}, k8snames.PodIPs(&corev1.Pod{Status: corev1.PodStatus{PodIP: "10.1.2.3"}}))
	dual := &corev1.Pod{Status: corev1.PodStatus{
		PodIP:  "10.1.2.3",
		PodIPs: []corev1.PodIP{{IP: "10.1.2.3"}, {IP: "fd00::3"}},
	}}
	assert.Equal(t, []string{"10.1.2.3", "fd00::3"}, k8snames.PodIPs(dual))
	dual.Namespace = "test"
	names := k8snames.ForPod(dual, nil, k8snames.Options{})
	assert.Equal(t, []string{"10-1-2-3.test.pod.cluster.local", "fd00--3.test.pod.cluster.local"}, names.DNS)
}

func TestSelectingServices(t *testing.T) {
	t.Parallel()
	selecting := k8snames.SelectingServices(testPod(), testServices())
	require.Len(t, selecting, 3)
	assert.Equal(t, "service1", selecting[0].Name)
	assert.Equal(t, "headless", selecting[1].Name)
	assert.Equal(t, "alias", selecting[2].Name)
}

func TestClusterIPs(t *testing.T) {
	t.Parallel()
	tcases := []struct {
		name string
		spec corev1.ServiceSpec
		want []string
	}{
		{name: "no address"},
		{name: "clusterIP only", spec: corev1.ServiceSpec{ClusterIP: "10.0.0.1"}, want: []string{"10.0.0.1"}},
		{name: "dual-stack", spec: corev1.ServiceSpec{ClusterIP: "10.0.0.1", ClusterIPs: []string{"10.0.0.1", "fd00::1"}}, want: []string{"10.0.0.1", "fd00::1"}},
		{name: "headless", spec: corev1.ServiceSpec{ClusterIP: corev1.ClusterIPNone, ClusterIPs: []string{corev1.ClusterIPNone}}},
		{name: "empty list entry falls back", spec: corev1.ServiceSpec{ClusterIP: "10.0.0.1", ClusterIPs: []string{""}}, want: []string{"10.0.0.1"}},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, k8snames.ClusterIPs(&corev1.Service{Spec: tc.spec}))
		})
	}
}
