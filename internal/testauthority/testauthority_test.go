package testauthority_test

import (
	"testing"

	"github.com/effective-security/kubeca/internal/testauthority"
	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	ca := testauthority.New(t)
	issuer, err := ca.GetIssuerByLabel(testauthority.IssuerLabel)
	require.NoError(t, err)
	assert.Equal(t, testauthority.IssuerLabel, issuer.Label())
	assert.Equal(t, certutil.GetSubjectKeyID(ca.Issuer.Certificate), issuer.SubjectKID())
	for _, name := range []string{testauthority.ProfilePeer, testauthority.ProfileServer, testauthority.ProfileClient, testauthority.ProfileWebhook} {
		require.NotNil(t, issuer.Profile(name), name)
		byProfile, err := ca.GetIssuerByProfile(name)
		require.NoError(t, err)
		assert.Same(t, issuer, byProfile)
	}
	assert.Equal(t, ca.RootPEM(), issuer.Bundle().RootCertPEM+"\n")
	assert.Contains(t, issuer.PEM(), "BEGIN CERTIFICATE")
}
