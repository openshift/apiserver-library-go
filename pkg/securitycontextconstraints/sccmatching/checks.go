package sccmatching

import (
	"k8s.io/apimachinery/pkg/util/validation/field"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/securitycontext"

	sccapi "github.com/openshift/apiserver-library-go/pkg/securitycontextconstraints/api"
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

type containerMutatorFunc func(sc securitycontext.ContainerSecurityContextMutator) error

func (m containerMutatorFunc) MutateContainer(sc securitycontext.ContainerSecurityContextMutator) error {
	return m(sc)
}

func NewPodBoolChecker(fieldAccessor podBoolFieldAccessor, pathChild string, allowed bool, errorString string) sccapi.PodSecurityValidator {
	return podValidatorFunc(func(fieldPath *field.Path, podSC securitycontext.PodSecurityContextAccessor) field.ErrorList {
		allErrs := field.ErrorList{}

		if val := fieldAccessor(podSC); !allowed && val {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child(pathChild), val, errorString))
		}
		return allErrs
	})
}

func checkPrivileged(privilegedAllowed bool) sccapi.ContainerSecurityValidator {
	return containerValidatorFunc(func(fieldPath *field.Path, sc securitycontext.ContainerSecurityContextAccessor) field.ErrorList {
		allErrs := field.ErrorList{}

		privileged := sc.Privileged()
		if !privilegedAllowed && privileged != nil && *privileged {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("privileged"), *privileged, "Privileged containers are not allowed"))
		}

		return allErrs
	})
}

func readOnlyFileSystemAdmission(readOnlyRootFSRequired bool) (sccapi.ContainerSecurityMutator, sccapi.ContainerSecurityValidator) {
	return containerMutatorFunc(func(sc securitycontext.ContainerSecurityContextMutator) error {
			// if the SCC requires a read only root filesystem and the container has not made a specific
			// request then default ReadOnlyRootFilesystem to true.
			if readOnlyRootFSRequired && sc.ReadOnlyRootFilesystem() == nil {
				readOnlyRootFS := true
				sc.SetReadOnlyRootFilesystem(&readOnlyRootFS)
			}
			return nil
		}),

		containerValidatorFunc(func(fieldPath *field.Path, sc securitycontext.ContainerSecurityContextAccessor) field.ErrorList {
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

// hasHostPort checks the port definitions on the container for HostPort > 0.
func checkHostPort(hostPortAllowed bool, containerPorts []api.ContainerPort, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	if hostPortAllowed {
		return allErrs
	}

	for _, cp := range containerPorts {
		if cp.HostPort > 0 {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("hostPort"), cp.HostPort, "Host ports are not allowed to be used"))
		}
	}
	return allErrs
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
