package user

import (
	"fmt"

	securityv1 "github.com/openshift/api/security/v1"
)

func CreateUserStrategy(opts *securityv1.RunAsUserStrategyOptions) (RunAsUserSecurityContextConstraintsStrategy, error) {
	switch opts.Type {
	case securityv1.RunAsUserStrategyMustRunAs:
		return NewMustRunAs(opts)
	case securityv1.RunAsUserStrategyMustRunAsRange:
		return NewMustRunAsRange(opts)
	case securityv1.RunAsUserStrategyMustRunAsNonRoot:
		return NewRunAsNonRoot(opts)
	case securityv1.RunAsUserStrategyRunAsAny:
		return NewRunAsAny(opts)
	default:
		return nil, fmt.Errorf("unrecognized RunAsUser strategy type %s", opts.Type)
	}
}
