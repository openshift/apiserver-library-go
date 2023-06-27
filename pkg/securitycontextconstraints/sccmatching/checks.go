package sccmatching

import (
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/securitycontext"

	"github.com/openshift/apiserver-library-go/pkg/securitycontextconstraints/api"
)

type podBoolFieldAccessor func(securitycontext.PodSecurityContextAccessor) bool

type podValidatorFunc func(fieldPath *field.Path, podSC securitycontext.PodSecurityContextAccessor) field.ErrorList

func (v podValidatorFunc) ValidatePod(fieldPath *field.Path, podSc securitycontext.PodSecurityContextAccessor) field.ErrorList {
	return v(fieldPath, podSc)
}

type containerValidatorFunc func(fieldPath *field.Path, sc securitycontext.ContainerSecurityContextAccessor) field.ErrorList

func (v containerValidatorFunc) ValidateContainer(fieldPath *field.Path, sc securitycontext.ContainerSecurityContextAccessor) field.ErrorList {
	return v(fieldPath, sc)
}

func NewPodBoolChecker(fieldAccessor podBoolFieldAccessor, pathChild string, allowed bool, errorString string) api.PodSecurityValidator {
	return podValidatorFunc(func(fieldPath *field.Path, podSC securitycontext.PodSecurityContextAccessor) field.ErrorList {
		allErrs := field.ErrorList{}

		if val := fieldAccessor(podSC); !allowed && val {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child(pathChild), val, errorString))
		}
		return allErrs
	})
}

func checkPrivileged(privilegedAllowed bool) api.ContainerSecurityValidator {
	return containerValidatorFunc(func(fieldPath *field.Path, sc securitycontext.ContainerSecurityContextAccessor) field.ErrorList {
		allErrs := field.ErrorList{}

		privileged := sc.Privileged()
		if !privilegedAllowed && privileged != nil && *privileged {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("privileged"), *privileged, "Privileged containers are not allowed"))
		}

		return allErrs
	})
}

func checkReadOnlyFileSystem(readOnlyRootFSRequired bool) api.ContainerSecurityValidator {
	return containerValidatorFunc(func(fieldPath *field.Path, sc securitycontext.ContainerSecurityContextAccessor) field.ErrorList {
		allErrs := field.ErrorList{}
		if !readOnlyRootFSRequired {
			return allErrs
		}

		readOnly := sc.ReadOnlyRootFilesystem()
		if readOnly == nil {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("readOnlyRootFilesystem"), readOnly, "ReadOnlyRootFilesystem may not be nil and must be set to true"))
		} else if !*readOnly {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("readOnlyRootFilesystem"), *readOnly, "ReadOnlyRootFilesystem must be set to true"))
		}

		return allErrs
	})
}

// checkAllowPrivilegeEscalation checks whether SUID bits are allowed in the container
func checkAllowPrivilegeEscalation(privilegeEscalationAllowed *bool) containerValidatorFunc {
	return containerValidatorFunc(func(fieldPath *field.Path, sc securitycontext.ContainerSecurityContextAccessor) field.ErrorList {
		allErrs := field.ErrorList{}
		if privilegeEscalationAllowed == nil || *privilegeEscalationAllowed {
			return allErrs
		}

		allowEscalation := sc.AllowPrivilegeEscalation()
		if allowEscalation == nil {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("allowPrivilegeEscalation"), allowEscalation, "Allowing privilege escalation for containers is not allowed"))
		}

		if allowEscalation != nil && *allowEscalation {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("allowPrivilegeEscalation"), *allowEscalation, "Allowing privilege escalation for containers is not allowed"))
		}

		return allErrs
	})
}

func getPodHostPID(podSC securitycontext.PodSecurityContextAccessor) bool {
	return podSC.HostPID()
}

func getPodHostNetwork(podSC securitycontext.PodSecurityContextAccessor) bool {
	return podSC.HostNetwork()
}

func getPodHostIPC(podSC securitycontext.PodSecurityContextAccessor) bool {
	return podSC.HostIPC()
}
