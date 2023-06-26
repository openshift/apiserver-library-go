package api

import (
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/securitycontext"
)

type ContainerSecurityValidator interface {
	ValidateContainer(*field.Path, securitycontext.ContainerSecurityContextAccessor) field.ErrorList
}

type PodSecurityValidator interface {
	ValidatePod(*field.Path, securitycontext.PodSecurityContextAccessor) field.ErrorList
}
