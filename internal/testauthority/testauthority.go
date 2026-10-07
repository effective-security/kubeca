package testauthority

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/require"
)

const (
	// IssuerLabel is the label of the issuer the Authority serves, the same
	// as the chart's.
	IssuerLabel = "kubeca.svc"
	// Profiles of the example configuration.
	ProfilePeer    = "peer-24h"
	ProfileServer  = "server-24h"
	ProfileClient  = "client-24h"
	ProfileWebhook = "webhook"

	// fixtureConfig is the CA configuration the profiles come from,
	// relative to this file.
	fixtureConfig = "testdata/ca-config.yaml"

	rootCommonName   = "[TEST] kubeca Root CA"
	issuerCommonName = "[TEST] kubeca Issuing CA G1"
	caLifetime       = 10 * 365 * 24 * time.Hour
)

// Placeholders of the fixture, replaced with the generated files.
var placeholders = map[string]string{
	"ISSUER_CERT_FILE": "issuer.pem",
	"ISSUER_KEY_FILE":  "issuer.key",
	"ROOT_BUNDLE_FILE": "root.pem",
}

// CA is a test Authority with its generated certificates.
type CA struct {
	*authority.Authority
	// Root and Issuer are the generated CA entities (certificate and key).
	Root   *testca.Entity
	Issuer *testca.Entity
	// Dir holds issuer.pem, issuer.key, root.pem and ca-config.yaml.
	Dir string
}

// New builds the Authority; it fails the test on any error.
func New(t *testing.T) *CA {
	t.Helper()
	root := testca.NewEntity(
		testca.Authority,
		testca.Subject(pkix.Name{CommonName: rootCommonName}),
		testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign),
		testca.NotAfter(time.Now().Add(caLifetime)),
	)
	issuer := root.Issue(
		testca.Authority,
		testca.Subject(pkix.Name{CommonName: issuerCommonName}),
		testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature),
		testca.NotAfter(time.Now().Add(caLifetime/2)),
	)
	return FromEntities(t, root, issuer)
}

// FromEntities builds the Authority around the given root and issuing CA,
// so a test can control their validity (an expiring CA).
func FromEntities(t *testing.T, root, issuer *testca.Entity) *CA {
	t.Helper()
	dir := t.TempDir()
	keyPEM, err := certutil.EncodePrivateKeyToPEM(issuer.PrivateKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "issuer.pem"), testca.ToPEM(issuer.Certificate), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "issuer.key"), keyPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.pem"), testca.ToPEM(root.Certificate), 0o600))

	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	fixture, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), fixtureConfig))
	require.NoError(t, err)
	config := string(fixture)
	for placeholder, file := range placeholders {
		config = strings.ReplaceAll(config, placeholder, filepath.Join(dir, file))
	}
	configFile := filepath.Join(dir, "ca-config.yaml")
	require.NoError(t, os.WriteFile(configFile, []byte(config), 0o600))

	cfg, err := authority.LoadConfig(configFile)
	require.NoError(t, err)
	crypto, err := cryptoprov.New(inmemcrypto.NewProvider(), nil)
	require.NoError(t, err)
	ca, err := authority.NewAuthority(cfg, crypto)
	require.NoError(t, err)
	return &CA{Authority: ca, Root: root, Issuer: issuer, Dir: dir}
}

// RootPEM returns the root certificate, PEM.
func (ca *CA) RootPEM() string {
	return string(testca.ToPEM(ca.Root.Certificate))
}
