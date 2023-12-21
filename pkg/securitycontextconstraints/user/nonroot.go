package user

import (
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/securitycontext"

	securityv1 "github.com/openshift/api/security/v1"
)

type nonRoot struct{}

var _ RunAsUserSecurityContextConstraintsStrategy = &nonRoot{}

func NewRunAsNonRoot(options *securityv1.RunAsUserStrategyOptions) (RunAsUserSecurityContextConstraintsStrategy, error) {
	return &nonRoot{}, nil
}

// Generate creates the uid based on policy rules.  This strategy does return a UID.  It assumes
// that the user will specify a UID or the container image specifies a UID.
func (s *nonRoot) MutateContainer(sc securitycontext.ContainerSecurityContextMutator) error {
	return nil
}

// Validate ensures that the specified values fall within the range of the strategy.  Validation
// of this will pass if either the UID is not set, assuming that the image will provided the UID
// or if the UID is set it is not root.  In order to work properly this assumes that the kubelet
// will populate an
func (s *nonRoot) ValidateContainer(fldPath *field.Path, sc securitycontext.ContainerSecurityContextAccessor) field.ErrorList {
	allErrs := field.ErrorList{}
	runAsNonRoot := sc.RunAsNonRoot()
	runAsUser := sc.RunAsUser()

	if runAsNonRoot == nil && runAsUser == nil {
		allErrs = append(allErrs, field.Required(fldPath.Child("runAsNonRoot"), "must be true"))
		return allErrs
	}
	if runAsNonRoot != nil && *runAsNonRoot == false {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("runAsNonRoot"), *runAsNonRoot, "must be true"))
		return allErrs
	}
	if runAsUser != nil && *runAsUser == 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("runAsUser"), *runAsUser, "running with the root UID is forbidden"))
		return allErrs
	}
	return allErrs
}
