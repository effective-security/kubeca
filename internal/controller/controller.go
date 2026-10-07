package controller

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/cryptoprov"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/kubeca", "controller")

// ApproveMode selects what the in-process approver does with a CSR that
// has neither an Approved nor a Denied condition (KUBECA-001).
type ApproveMode string

const (
	// ApproveOff signs every CSR of a known signer that is not Denied,
	// without an Approved condition: the behaviour before v0.9.
	ApproveOff ApproveMode = "off"
	// ApproveAudit evaluates the names, logs and emits an ApprovalAudit
	// event for a CSR that enforce would deny, and signs it anyway.
	ApproveAudit ApproveMode = "audit"
	// ApproveEnforce sets Approved when every name of the CSR is one the
	// requesting ServiceAccount's Pods and Services may carry, Denied
	// otherwise, and signs only approved CSRs.
	ApproveEnforce ApproveMode = "enforce"
)

// ParseApproveMode validates the value of the -approve flag.
func ParseApproveMode(s string) (ApproveMode, error) {
	switch mode := ApproveMode(s); mode {
	case ApproveOff, ApproveAudit, ApproveEnforce:
		return mode, nil
	default:
		return "", errors.Errorf("invalid approve mode %q: use off, audit or enforce", s)
	}
}

// LoadAuthority loads the crypto provider from the token configuration
// and the xpki Authority from the CA configuration.
func LoadAuthority(caCfgPath, hsmCfgPath string) (*authority.Authority, error) {
	crypto, err := cryptoprov.Load(hsmCfgPath, nil)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to load HSM config %s", hsmCfgPath)
	}
	caCfg, err := authority.LoadConfig(caCfgPath)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to load CA config %s", caCfgPath)
	}
	ca, err := authority.NewAuthority(caCfg, crypto)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to create CA")
	}
	return ca, nil
}
