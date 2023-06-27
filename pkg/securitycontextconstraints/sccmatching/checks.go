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

func NewPodBoolChecker(fieldAccessor podBoolFieldAccessor, pathChild string, allowed bool, errorString string) api.PodSecurityValidator {
	return podValidatorFunc(func(fieldPath *field.Path, podSC securitycontext.PodSecurityContextAccessor) field.ErrorList {
		allErrs := field.ErrorList{}

		if val := fieldAccessor(podSC); !allowed && val {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child(pathChild), val, errorString))
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
