package signerr_test

import (
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/kubeca/internal/signerr"
	"github.com/stretchr/testify/assert"
)

func TestIsPermanent(t *testing.T) {
	t.Parallel()
	tcases := []struct {
		err       error
		permanent bool
	}{
		{nil, false},
		{errors.New("failed to parse CSR: asn1: syntax error"), true},
		{errors.New("unsupported profile: foo"), true},
		{errors.New("DNS Name does not match allowed list: evil.com"), true},
		{errors.New("URI does not match allowed list: spiffe://x"), true},
		{errors.New(`CSR: invalid SAN "a..b": empty label`), true},
		{errors.New("extension not allowed: 1.2.3"), true},
		{errors.New("the policy disallows issuing CA certificate"), true},
		{errors.New("invalid validity: NotAfter 2026-10-06T00:00:00Z is not after NotBefore 2026-10-07T00:00:00Z"), true},
		{errors.New("validity 25h0m0s exceeds profile expiry 24h0m0s"), true},
		{errors.WithMessage(errors.New("validity 25h0m0s exceeds profile expiry 24h0m0s"), "failed to sign"), true},
		{errors.New("NotBefore 2026-10-06T09:55:00Z is earlier than allowed 2026-10-06T09:56:00Z"), false},
		{errors.New("operation error KMS: Sign, https response error StatusCode: 500"), false},
		{errors.New("context deadline exceeded"), false},
	}
	for _, tc := range tcases {
		assert.Equal(t, tc.permanent, signerr.IsPermanent(tc.err), "%v", tc.err)
	}
}
