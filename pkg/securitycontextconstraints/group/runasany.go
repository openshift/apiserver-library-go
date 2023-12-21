package group

import (
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/securitycontext"
)

// mustRunAs implements the GroupSecurityContextConstraintsStrategy interface
type runAsAny struct {
}

var _ GroupSecurityContextConstraintsStrategy = &runAsAny{}

// NewRunAsAny provides a new RunAsAny strategy.
func NewRunAsAny() (GroupSecurityContextConstraintsStrategy, error) {
	return &runAsAny{}, nil
}

// Generate creates the group based on policy rules.  This strategy returns an empty slice.
func (s *runAsAny) MutatePod(securitycontext.PodSecurityContextMutator) error {
	return nil
}

// Validate ensures that the specified values fall within the range of the strategy.
func (s *runAsAny) ValidatePod(fldPath *field.Path, _ securitycontext.PodSecurityContextAccessor) field.ErrorList {
	return field.ErrorList{}

}
