package group

import (
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/securitycontext"
)

// GroupSecurityContextConstraintsStrategy defines the interface for all group constraint strategies.
type GroupSecurityContextConstraintsStrategy interface {
	// Generate creates the group based on policy rules.  The underlying implementation can
	// decide whether it will return a full range of values or a subset of values from the
	// configured ranges.
	MutatePod(podSC securitycontext.PodSecurityContextMutator) error
	// Validate ensures that the specified values fall within the range of the strategy.
	ValidatePod(fldPath *field.Path, podSC securitycontext.PodSecurityContextAccessor) field.ErrorList
}
