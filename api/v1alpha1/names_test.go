package v1alpha1_test

import (
	"strings"
	"testing"

	"github.com/effective-security/kubeca/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/validation"
)

func TestPodNames(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "worker-1-tls", v1alpha1.PodSecretName("worker-1", ""))
	assert.Equal(t, "custom", v1alpha1.PodSecretName("worker-1", "custom"))
	assert.Equal(t, "worker-1", v1alpha1.PodCertificateName("worker-1", ""))
	assert.Equal(t, "worker-1", v1alpha1.PodCertificateName("worker-1", "worker-1-tls"), "the webhook's default for a named Pod")
	assert.Equal(t, "worker-1-ab12cd34", v1alpha1.PodCertificateName("worker-1", "kubeca-ab12cd34"))
	assert.Equal(t, "worker-1-custom", v1alpha1.PodCertificateName("worker-1", "custom"))
}

// TestPodNamesLength: a named Pod may use the whole 253 characters of a
// DNS subdomain; the derived names stay valid and distinct.
func TestPodNamesLength(t *testing.T) {
	t.Parallel()
	// 251 characters with a dot at index 243, where a shortened name is
	// cut (253 minus the 9 characters of "-<hash>"): the dot must go
	label := strings.Repeat("a", 63)
	long := strings.Join([]string{label, label, label, label[:51], "bbbbbbb"}, ".")
	require.Len(t, long, 251)
	require.Equal(t, byte('.'), long[243])
	other := long[:250] + "c"

	for _, name := range []string{
		v1alpha1.PodSecretName(long, ""),
		v1alpha1.PodSecretName(other, ""),
		v1alpha1.PodCertificateName(long, "kubeca-ab12cd34"),
		v1alpha1.PodCertificateName(other, "kubeca-ab12cd34"),
	} {
		assert.LessOrEqual(t, len(name), 253, name)
		assert.Empty(t, validation.IsDNS1123Subdomain(name), name)
		assert.NotContains(t, name, ".-", name)
	}
	assert.NotEqual(t, v1alpha1.PodSecretName(long, ""), v1alpha1.PodSecretName(other, ""))
	assert.NotEqual(t, v1alpha1.PodCertificateName(long, "kubeca-ab12cd34"), v1alpha1.PodCertificateName(other, "kubeca-ab12cd34"))
	// the Pod's own default Secret still maps to the Pod name
	assert.Equal(t, long, v1alpha1.PodCertificateName(long, v1alpha1.PodSecretName(long, "")))
	// short enough: unchanged
	fits := long[:249]
	assert.Equal(t, fits+"-tls", v1alpha1.PodSecretName(fits, ""))
}
