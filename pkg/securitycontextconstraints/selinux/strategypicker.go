package selinux

import (
	"fmt"

	securityv1 "github.com/openshift/api/security/v1"
)

// createSELinuxStrategy creates a new selinux strategy.
func CreateSELinuxStrategy(opts *securityv1.SELinuxContextStrategyOptions) (SELinuxSecurityContextConstraintsStrategy, error) {
	switch opts.Type {
	case securityv1.SELinuxStrategyMustRunAs:
		return NewMustRunAs(opts)
	case securityv1.SELinuxStrategyRunAsAny:
		return NewRunAsAny(opts)
	default:
		return nil, fmt.Errorf("Unrecognized SELinuxContext strategy type %s", opts.Type)
	}
}
