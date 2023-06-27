package capabilities

import (
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/securitycontext"
)

// CapabilitiesSecurityContextConstraintsStrategy defines the interface for all cap constraint strategies.
type CapabilitiesSecurityContextConstraintsStrategy interface {
	// Generate creates the capabilities based on policy rules.
	MutateContainer(sc securitycontext.ContainerSecurityContextMutator) error
	// Validate ensures that the specified values fall within the range of the strategy.
	ValidateContainer(fldPath *field.Path, sc securitycontext.ContainerSecurityContextAccessor) field.ErrorList
}
