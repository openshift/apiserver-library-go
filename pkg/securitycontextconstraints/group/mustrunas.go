package group

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/validation/field"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/securitycontext"

	securityv1 "github.com/openshift/api/security/v1"
)

// mustRunAs implements the GroupSecurityContextConstraintsStrategy interface
type mustRunAs struct {
	ranges        []securityv1.IDRange
	field         string
	groupAccessor GroupAccessorFunc
	groupMutator  GroupMutatorFunc
}

var _ GroupSecurityContextConstraintsStrategy = &mustRunAs{}

type GroupAccessorFunc func(securitycontext.PodSecurityContextAccessor) []int64
type GroupMutatorFunc func(securitycontext.PodSecurityContextMutator, int64)

// NewMustRunAs provides a new MustRunAs strategy based on ranges.
func NewMustRunAs(ranges []securityv1.IDRange, field string, groupAccessor GroupAccessorFunc, groupMutator GroupMutatorFunc) (GroupSecurityContextConstraintsStrategy, error) {
	if groupAccessor == nil {
		return nil, fmt.Errorf("function describing accessing groups is required")
	}

	if len(ranges) == 0 {
		return nil, fmt.Errorf("ranges must be supplied for MustRunAs")
	}
	return &mustRunAs{
		ranges:        ranges,
		field:         field,
		groupAccessor: groupAccessor,
		groupMutator:  groupMutator,
	}, nil
}

// Generate creates the group based on policy rules.  By default this returns the first group of the
// first range (min val).
func (s *mustRunAs) MutatePod(podSC securitycontext.PodSecurityContextMutator) error {
	if s.groupMutator == nil {
		return fmt.Errorf("mutation is not allowed")
	}

	if len(s.groupAccessor(podSC)) > 0 {
		return nil
	}

	s.groupMutator(podSC, s.ranges[0].Min)
	return nil
}

// Generate a single value to be applied.  This is used for FSGroup.  This strategy will return
// the first group of the first range (min val).
func (s *mustRunAs) GenerateSingle(_ *api.Pod) (*int64, error) {
	single := new(int64)
	*single = s.ranges[0].Min
	return single, nil
}

// Validate ensures that the specified values fall within the range of the strategy.
// Groups are passed in here to allow this strategy to support multiple group fields (fsgroup and
// supplemental groups).
func (s *mustRunAs) ValidatePod(fldPath *field.Path, podSC securitycontext.PodSecurityContextAccessor) field.ErrorList {
	allErrs := field.ErrorList{}
	groups := s.groupAccessor(podSC)

	if len(groups) == 0 && len(s.ranges) > 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child(s.field), groups, "unable to validate empty groups against required ranges"))
	}

	for _, group := range groups {
		if !s.isGroupValid(group) {
			detail := fmt.Sprintf("%d is not an allowed group", group)
			allErrs = append(allErrs, field.Invalid(fldPath.Child(s.field), groups, detail))
		}
	}

	return allErrs
}

func (s *mustRunAs) isGroupValid(group int64) bool {
	for _, rng := range s.ranges {
		if fallsInRange(group, rng) {
			return true
		}
	}
	return false
}

func fallsInRange(group int64, rng securityv1.IDRange) bool {
	return group >= rng.Min && group <= rng.Max
}
