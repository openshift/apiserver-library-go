package capabilities

import (
	"k8s.io/apimachinery/pkg/util/validation/field"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/securitycontext"
)

// CapabilitiesSecurityContextConstraintsStrategy defines the interface for all cap constraint strategies.
type CapabilitiesSecurityContextConstraintsStrategy interface {
	// Generate creates the capabilities based on policy rules.
	Generate(pod *api.Pod, container *api.Container) (*api.Capabilities, error)
	// Validate ensures that the specified values fall within the range of the strategy.
	ValidateContainer(fldPath *field.Path, sc securitycontext.ContainerSecurityContextAccessor) field.ErrorList
}
