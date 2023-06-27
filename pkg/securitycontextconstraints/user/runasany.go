package user

import (
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/securitycontext"

	securityv1 "github.com/openshift/api/security/v1"
)

// runAsAny implements the interface RunAsUserSecurityContextConstraintsStrategy.
type runAsAny struct{}

var _ RunAsUserSecurityContextConstraintsStrategy = &runAsAny{}

// NewRunAsAny provides a strategy that will return nil.
func NewRunAsAny(options *securityv1.RunAsUserStrategyOptions) (RunAsUserSecurityContextConstraintsStrategy, error) {
	return &runAsAny{}, nil
}

// Generate creates the uid based on policy rules.
func (s *runAsAny) MutateContainer(sc securitycontext.ContainerSecurityContextMutator) error {
	return nil
}

// Validate ensures that the specified values fall within the range of the strategy.
func (s *runAsAny) ValidateContainer(fldPath *field.Path, _ securitycontext.ContainerSecurityContextAccessor) field.ErrorList {
	return field.ErrorList{}
}
