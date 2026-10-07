package webhook_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/effective-security/kubeca/api/v1alpha1"
	"github.com/effective-security/kubeca/internal/operator/webhook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	jsonpatch "gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func deploymentPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "api-7d9f8b-",
			Namespace:    "shop",
			Labels:       map[string]string{v1alpha1.LabelInject: v1alpha1.TrueValue},
			Annotations: map[string]string{
				v1alpha1.AnnotationIssuer:     "kubeca",
				v1alpha1.AnnotationContainers: "api",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "api", VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}},
				{Name: "metrics-sidecar"},
			},
			Volumes: []corev1.Volume{{Name: "data"}},
		},
	}
}

func TestMutate(t *testing.T) {
	t.Parallel()
	pod := deploymentPod()
	require.True(t, webhook.Mutate(pod, "kubeca-ab12cd34"))
	assert.Equal(t, "kubeca-ab12cd34", pod.Annotations[v1alpha1.AnnotationSecretName])
	assert.Equal(t, []corev1.Volume{
		{Name: "data"},
		{Name: "kubeca-tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "kubeca-ab12cd34"}}},
	}, pod.Spec.Volumes)
	assert.Equal(t, []corev1.VolumeMount{
		{Name: "data", MountPath: "/data"},
		{Name: "kubeca-tls", MountPath: "/etc/tls", ReadOnly: true},
	}, pod.Spec.Containers[0].VolumeMounts)
	assert.Empty(t, pod.Spec.Containers[1].VolumeMounts, "not in the containers annotation")

	// idempotent
	require.False(t, webhook.Mutate(pod, "kubeca-ab12cd34"))

	// all containers, custom mount path, user-defined volume for the Secret
	pod = deploymentPod()
	delete(pod.Annotations, v1alpha1.AnnotationContainers)
	pod.Annotations[v1alpha1.AnnotationMountPath] = "/var/run/tls"
	pod.Spec.Volumes = append(pod.Spec.Volumes,
		corev1.Volume{Name: "kubeca-tls"},
		corev1.Volume{Name: "certs", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "worker-tls"}}})
	pod.Spec.Containers[1].VolumeMounts = []corev1.VolumeMount{{Name: "other", MountPath: "/var/run/tls"}}
	require.True(t, webhook.Mutate(pod, "worker-tls"))
	assert.Len(t, pod.Spec.Volumes, 3, "the existing volume is reused")
	assert.Equal(t, []corev1.VolumeMount{
		{Name: "data", MountPath: "/data"},
		{Name: "certs", MountPath: "/var/run/tls", ReadOnly: true},
	}, pod.Spec.Containers[0].VolumeMounts)
	assert.Equal(t, []corev1.VolumeMount{{Name: "other", MountPath: "/var/run/tls"}}, pod.Spec.Containers[1].VolumeMounts, "mount path taken")

	// a volume named kubeca-tls that is not ours gets a suffix
	pod = deploymentPod()
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: "kubeca-tls"})
	require.True(t, webhook.Mutate(pod, "x"))
	assert.Equal(t, "kubeca-tls-1", pod.Spec.Volumes[2].Name)
	assert.Equal(t, "kubeca-tls-1", pod.Spec.Containers[0].VolumeMounts[1].Name)
}

func TestGenerateSecretName(t *testing.T) {
	t.Parallel()
	a, err := webhook.GenerateSecretName()
	require.NoError(t, err)
	b, err := webhook.GenerateSecretName()
	require.NoError(t, err)
	assert.Regexp(t, "^kubeca-[a-z0-9]{8}$", a)
	assert.NotEqual(t, a, b)
}

func request(t *testing.T, pod *corev1.Pod, op admissionv1.Operation) admission.Request {
	t.Helper()
	raw, err := json.Marshal(pod)
	require.NoError(t, err)
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		UID:       "req-1",
		Operation: op,
		Namespace: pod.Namespace,
		Object:    runtime.RawExtension{Raw: raw},
	}}
}

func patchOps(resp admission.Response) map[string]jsonpatch.Operation {
	ops := map[string]jsonpatch.Operation{}
	for _, p := range resp.Patches {
		ops[p.Path] = p
	}
	return ops
}

func TestHandle(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	m := webhook.NewPodMutator(scheme)

	// generateName Pod: a generated Secret name, volume and mount
	resp := m.Handle(context.Background(), request(t, deploymentPod(), admissionv1.Create))
	require.True(t, resp.Allowed, resp.Result)
	ops := patchOps(resp)
	secretOp, ok := ops["/metadata/annotations/kubeca.effectivesecurity~1secret-name"]
	require.True(t, ok, ops)
	assert.Equal(t, "add", secretOp.Operation)
	assert.Regexp(t, "^kubeca-[a-z0-9]{8}$", secretOp.Value)
	volume, ok := ops["/spec/volumes/1"]
	require.True(t, ok, ops)
	assert.Equal(t, map[string]any{"name": "kubeca-tls", "secret": map[string]any{"secretName": secretOp.Value}}, volume.Value)
	mount, ok := ops["/spec/containers/0/volumeMounts/1"]
	require.True(t, ok, ops)
	assert.Equal(t, map[string]any{"name": "kubeca-tls", "mountPath": "/etc/tls", "readOnly": true}, mount.Value)
	_, ok = ops["/spec/containers/1/volumeMounts"]
	assert.False(t, ok, "sidecar not in the containers annotation")

	// a named Pod gets <name>-tls
	pod := deploymentPod()
	pod.GenerateName, pod.Name = "", "worker-1"
	resp = m.Handle(context.Background(), request(t, pod, admissionv1.Create))
	require.True(t, resp.Allowed)
	assert.Equal(t, "worker-1-tls", patchOps(resp)["/metadata/annotations/kubeca.effectivesecurity~1secret-name"].Value)

	// the annotation wins
	pod.Annotations[v1alpha1.AnnotationSecretName] = "custom"
	resp = m.Handle(context.Background(), request(t, pod, admissionv1.Create))
	require.True(t, resp.Allowed)
	ops = patchOps(resp)
	_, ok = ops["/metadata/annotations/kubeca.effectivesecurity~1secret-name"]
	assert.False(t, ok)
	assert.Equal(t, map[string]any{"name": "kubeca-tls", "secret": map[string]any{"secretName": "custom"}}, ops["/spec/volumes/1"].Value)

	// not labeled: allowed unchanged
	pod.Labels = nil
	resp = m.Handle(context.Background(), request(t, pod, admissionv1.Create))
	require.True(t, resp.Allowed)
	assert.Empty(t, resp.Patches)
	assert.Equal(t, "not labeled for injection", resp.Result.Message)

	// already injected: allowed unchanged
	pod = deploymentPod()
	pod.Name = "worker-1"
	require.True(t, webhook.Mutate(pod, "worker-1-tls"))
	resp = m.Handle(context.Background(), request(t, pod, admissionv1.Create))
	require.True(t, resp.Allowed)
	assert.Empty(t, resp.Patches)
	assert.Equal(t, "already injected", resp.Result.Message)

	// not a CREATE: allowed without decoding
	resp = m.Handle(context.Background(), request(t, deploymentPod(), admissionv1.Delete))
	require.True(t, resp.Allowed)
	assert.Empty(t, resp.Patches)
	assert.Equal(t, "not a CREATE", resp.Result.Message)

	// not a Pod
	resp = m.Handle(context.Background(), admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: admissionv1.Create,
		Object:    runtime.RawExtension{Raw: []byte("{")},
	}})
	require.False(t, resp.Allowed)
	assert.Equal(t, int32(400), resp.Result.Code)
}
