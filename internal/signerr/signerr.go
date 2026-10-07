package signerr

import "strings"

// permanentMessages are substrings of the errors authority.Issuer.Sign
// and csr.ParseSAN return for a request that is rejected on its content.
var permanentMessages = []string{
	"failed to parse CSR",
	"unsupported profile",
	"does not match allowed list",
	"invalid SAN",
	"extension not allowed",
	"duplicate profile extension",
	"disallows",
	"invalid validity",
	"exceeds profile expiry",
	"expiry is not set",
	"invalid profile",
	"CA template is not specified",
	"is not before issuer NotAfter",
}

// IsPermanent reports whether err is a rejection of the request itself,
// which must not be retried. A NotBefore the issuer finds too early is
// transient: it comes from a minute boundary passing between the
// controller's clock read and the signature, and the next attempt
// recomputes the window.
func IsPermanent(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	if strings.Contains(msg, "is earlier than allowed") {
		return false
	}
	for _, m := range permanentMessages {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}
