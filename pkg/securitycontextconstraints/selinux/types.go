package selinux

import (
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/securitycontext"
)

// SELinuxSecurityContextConstraintsStrategy defines the interface for all SELinux constraint strategies.
type SELinuxSecurityContextConstraintsStrategy interface {
	// Generate creates the SELinuxOptions based on constraint rules.
	MutatePod(podSC securitycontext.PodSecurityContextMutator) error
	MutateContainer(sc securitycontext.ContainerSecurityContextMutator) error
	// Validate ensures that the specified values fall within the range of the strategy.
	ValidateContainer(fldPath *field.Path, sc securitycontext.ContainerSecurityContextAccessor) field.ErrorList
	ValidatePod(fltPath *field.Path, podSC securitycontext.PodSecurityContextAccessor) field.ErrorList
}
