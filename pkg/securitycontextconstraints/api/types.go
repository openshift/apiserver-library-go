package api

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/securitycontext"
)

type ExtendedContainerSecurityValidator interface {
	ValidateContainerDirectly(*field.Path, *corev1.Container)
}

type ContainerSecurityValidator interface {
	ValidateContainer(*field.Path, securitycontext.ContainerSecurityContextAccessor) field.ErrorList
}

type ContainerSecurityMutator interface {
	MutateContainer(securitycontext.ContainerSecurityContextMutator) error
}

type PodSecurityValidator interface {
	ValidatePod(*field.Path, securitycontext.PodSecurityContextAccessor) field.ErrorList
}

type PodSecurityMutator interface {
	MutatePod(securitycontext.PodSecurityContextMutator) error
}
