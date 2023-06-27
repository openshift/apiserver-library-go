package user

import (
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/securitycontext"
)

// RunAsUserSecurityContextConstraintsStrategy defines the interface for all uid constraint strategies.
type RunAsUserSecurityContextConstraintsStrategy interface {
	// Generate creates the uid based on policy rules.
	MutateContainer(sc securitycontext.ContainerSecurityContextMutator) error
	// ValidateContainer ensures that the specified values fall within the range of the strategy.
	ValidateContainer(fldPath *field.Path, sc securitycontext.ContainerSecurityContextAccessor) field.ErrorList
}
