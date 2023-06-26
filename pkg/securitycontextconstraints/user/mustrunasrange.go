package user

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/validation/field"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/securitycontext"

	securityv1 "github.com/openshift/api/security/v1"
)

// mustRunAsRange implements the RunAsUserSecurityContextConstraintsStrategy interface
type mustRunAsRange struct {
	UIDRangeMin, UIDRangeMax int64
}

var _ RunAsUserSecurityContextConstraintsStrategy = &mustRunAsRange{}

// NewMustRunAsRange provides a strategy that requires the container to run as a specific UID in a range.
func NewMustRunAsRange(options *securityv1.RunAsUserStrategyOptions) (RunAsUserSecurityContextConstraintsStrategy, error) {
	if options == nil {
		return nil, fmt.Errorf("MustRunAsRange requires run as user options")
	}
	if options.UIDRangeMin == nil {
		return nil, fmt.Errorf("MustRunAsRange requires a UIDRangeMin")
	}
	if options.UIDRangeMax == nil {
		return nil, fmt.Errorf("MustRunAsRange requires a UIDRangeMax")
	}
	return &mustRunAsRange{
		UIDRangeMin: *options.UIDRangeMin,
		UIDRangeMax: *options.UIDRangeMax,
	}, nil
}

// Generate creates the uid based on policy rules.  MustRunAs returns the UIDRangeMin it is initialized with.
func (s *mustRunAsRange) Generate(pod *api.Pod, container *api.Container) (*int64, error) {
	uid := s.UIDRangeMin
	return &uid, nil
}

// Validate ensures that the specified values fall within the range of the strategy.
func (s *mustRunAsRange) ValidateContainer(fldPath *field.Path, sc securitycontext.ContainerSecurityContextAccessor) field.ErrorList {
	allErrs := field.ErrorList{}
	runAsUser := sc.RunAsUser()

	if runAsUser == nil {
		allErrs = append(allErrs, field.Required(fldPath.Child("runAsUser"), ""))
		return allErrs
	}

	if *runAsUser < s.UIDRangeMin || *runAsUser > s.UIDRangeMax {
		detail := fmt.Sprintf("must be in the ranges: [%v, %v]", s.UIDRangeMin, s.UIDRangeMax)
		allErrs = append(allErrs, field.Invalid(fldPath.Child("runAsUser"), *runAsUser, detail))
		return allErrs
	}

	return allErrs
}
