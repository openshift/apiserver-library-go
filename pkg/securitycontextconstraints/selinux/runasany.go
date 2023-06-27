package selinux

import (
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/securitycontext"

	securityv1 "github.com/openshift/api/security/v1"
)

// runAsAny implements the SELinuxSecurityContextConstraintsStrategy interface.
type runAsAny struct{}

var _ SELinuxSecurityContextConstraintsStrategy = &runAsAny{}

// NewRunAsAny provides a strategy that will return the configured se linux context or nil.
func NewRunAsAny(options *securityv1.SELinuxContextStrategyOptions) (SELinuxSecurityContextConstraintsStrategy, error) {
	return &runAsAny{}, nil
}

func (s *runAsAny) MutatePod(securitycontext.PodSecurityContextMutator) error {
	return nil
}

// Generate creates the SELinuxOptions based on constraint rules.
func (s *runAsAny) MutateContainer(securitycontext.ContainerSecurityContextMutator) error {
	return nil
}

// Validate ensures that the specified values fall within the range of the strategy.
func (s *runAsAny) ValidateContainer(_ *field.Path, _ securitycontext.ContainerSecurityContextAccessor) field.ErrorList {
	return field.ErrorList{}
}

func (s *runAsAny) ValidatePod(_ *field.Path, _ securitycontext.PodSecurityContextAccessor) field.ErrorList {
	return field.ErrorList{}
}
