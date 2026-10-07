package v1alpha1

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const (
	// maxNameLength is the longest name of a Secret or a Certificate (a
	// DNS subdomain).
	maxNameLength = 253
	// nameHashLength is the number of hex characters of the hash that ends
	// a shortened name.
	nameHashLength = 8
)

// PodSecretName returns the Secret of a labeled Pod's certificate: the
// secret-name annotation when set, else <pod-name>-tls (DefaultSecretSuffix),
// shortened by boundedName when the Pod name is close to the limit.
func PodSecretName(podName, secretAnnotation string) string {
	if secretAnnotation != "" {
		return secretAnnotation
	}
	return boundedName(podName + DefaultSecretSuffix)
}

// PodCertificateName returns the Certificate the Pod controller creates for
// a labeled Pod: the Pod name when the secret-name annotation is absent or
// the default <pod-name>-tls (the webhook sets it for named Pods), else
// <pod-name>-<suffix> where suffix is the last dash-separated part of the
// annotation (the webhook sets kubeca-<8 chars> for generateName Pods),
// shortened by boundedName when it would be too long. The Certificate
// controller recomputes it to tell the Pod's own Certificate from one that
// merely claims the Pod as its owner.
func PodCertificateName(podName, secretAnnotation string) string {
	if secretAnnotation == "" || secretAnnotation == PodSecretName(podName, "") {
		return podName
	}
	suffix := secretAnnotation
	if i := strings.LastIndex(secretAnnotation, "-"); i >= 0 {
		suffix = secretAnnotation[i+1:]
	}
	return boundedName(podName + "-" + suffix)
}

// boundedName returns name when it fits in maxNameLength, else a prefix of
// it followed by "-" and the first nameHashLength hex characters of the
// SHA-256 of the whole name, so that two long names with the same prefix
// stay apart. The prefix loses its trailing dots and dashes, so the result
// stays a DNS subdomain.
func boundedName(name string) string {
	if len(name) <= maxNameLength {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	suffix := "-" + hex.EncodeToString(sum[:])[:nameHashLength]
	return strings.TrimRight(name[:maxNameLength-len(suffix)], "-.") + suffix
}
