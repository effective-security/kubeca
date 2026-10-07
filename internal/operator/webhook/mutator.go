package webhook

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"net/http"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/kubeca/api/v1alpha1"
	"github.com/effective-security/kubeca/internal/k8snames"
	"github.com/effective-security/xlog"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/kubeca", "operator/webhook")

const (
	// Path is the URL path the webhook is served at.
	Path = "/mutate-pod"

	generatedNameAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	generatedNameLength   = 8
)

// The marker generates the reference configuration in
// config/webhook/manifests.yaml; the chart's templates/webhook.yaml is the
// hand-written copy with the Service reference and the object selector.
//
// +kubebuilder:webhook:path=/mutate-pod,mutating=true,failurePolicy=fail,sideEffects=None,groups="",resources=pods,verbs=create,versions=v1,name=pods.kubeca.effectivesecurity,admissionReviewVersions=v1

// PodMutator is the admission handler.
type PodMutator struct {
	decoder admission.Decoder
}

// NewPodMutator returns the handler; register it with
// admission.Webhook{Handler: ...} at Path.
func NewPodMutator(scheme *runtime.Scheme) *PodMutator {
	return &PodMutator{decoder: admission.NewDecoder(scheme)}
}

// Handle mutates a labeled Pod and returns the JSON patch; other Pods and
// non-CREATE operations are allowed unchanged.
func (m *PodMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	if req.Operation != admissionv1.Create {
		return admission.Allowed("not a CREATE")
	}
	pod := &corev1.Pod{}
	if err := m.decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, errors.WithMessage(err, "unable to decode Pod"))
	}
	if pod.Labels[v1alpha1.LabelInject] != v1alpha1.TrueValue {
		return admission.Allowed("not labeled for injection")
	}
	secretName, err := secretNameFor(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	if !Mutate(pod, secretName) {
		return admission.Allowed("already injected")
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, errors.WithMessage(err, "unable to encode Pod"))
	}
	// one line per admitted Pod: DEBUG, the Pod and its Certificate events
	// record the outcome
	logger.ContextKV(ctx, xlog.DEBUG,
		"ns", req.Namespace,
		"pod", podName(pod, req),
		"status", "injected",
		"secret", secretName,
		"issuer", pod.Annotations[v1alpha1.AnnotationIssuer])
	return admission.PatchResponseFromRaw(req.Object.Raw, raw)
}

func podName(pod *corev1.Pod, req admission.Request) string {
	if pod.Name != "" {
		return pod.Name
	}
	if req.Name != "" {
		return req.Name
	}
	return pod.GenerateName + "*"
}

// secretNameFor returns the Secret name of a Pod: the annotation, the Pod
// name plus -tls (v1alpha1.PodSecretName), or a generated name for a
// generateName Pod.
func secretNameFor(pod *corev1.Pod) (string, error) {
	annotation := pod.Annotations[v1alpha1.AnnotationSecretName]
	if annotation != "" || pod.Name != "" {
		return v1alpha1.PodSecretName(pod.Name, annotation), nil
	}
	return GenerateSecretName()
}

// GenerateSecretName returns kubeca-<8 random lower-case alphanumerics>
// from crypto/rand.
func GenerateSecretName() (string, error) {
	var b strings.Builder
	b.WriteString(v1alpha1.GeneratedSecretPrefix)
	alphabetLength := big.NewInt(int64(len(generatedNameAlphabet)))
	for range generatedNameLength {
		n, err := rand.Int(rand.Reader, alphabetLength)
		if err != nil {
			return "", errors.WithMessage(err, "unable to generate a Secret name")
		}
		b.WriteByte(generatedNameAlphabet[n.Int64()])
	}
	return b.String(), nil
}

// Mutate injects the Secret into the Pod: it records secretName in the
// secret-name annotation, adds a Secret volume unless one already
// references the Secret, and mounts it at the mount-path annotation into
// the containers of the containers annotation (all when absent) that have
// no mount at that path. It reports whether the Pod changed.
func Mutate(pod *corev1.Pod, secretName string) bool {
	changed := false
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	if pod.Annotations[v1alpha1.AnnotationSecretName] != secretName {
		pod.Annotations[v1alpha1.AnnotationSecretName] = secretName
		changed = true
	}

	volumeName := ""
	for _, v := range pod.Spec.Volumes {
		if v.Secret != nil && v.Secret.SecretName == secretName {
			volumeName = v.Name
			break
		}
	}
	if volumeName == "" {
		volumeName = uniqueVolumeName(pod)
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: volumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: secretName},
			},
		})
		changed = true
	}

	mountPath := pod.Annotations[v1alpha1.AnnotationMountPath]
	if mountPath == "" {
		mountPath = v1alpha1.DefaultMountPath
	}
	selected := slices.Collect(k8snames.SplitList(pod.Annotations[v1alpha1.AnnotationContainers]))
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if len(selected) > 0 && !slices.Contains(selected, c.Name) {
			continue
		}
		if slices.ContainsFunc(c.VolumeMounts, func(m corev1.VolumeMount) bool {
			return m.MountPath == mountPath // || m.Name == volumeName
		}) {
			continue
		}
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{
			Name:      volumeName,
			MountPath: mountPath,
			ReadOnly:  true,
		})
		changed = true
	}
	return changed
}

// uniqueVolumeName returns InjectedVolumeName, suffixed when a volume of
// that name exists.
func uniqueVolumeName(pod *corev1.Pod) string {
	name := v1alpha1.InjectedVolumeName
	for i := 1; slices.ContainsFunc(pod.Spec.Volumes, func(v corev1.Volume) bool { return v.Name == name }); i++ {
		name = v1alpha1.InjectedVolumeName + "-" + big.NewInt(int64(i)).String()
	}
	return name
}
