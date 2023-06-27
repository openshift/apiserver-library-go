package selinux

import (
	"testing"

	securityv1 "github.com/openshift/api/security/v1"
	corev1 "k8s.io/api/core/v1"
	coreapi "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/securitycontext"
)

func TestRunAsAnyOptions(t *testing.T) {
	_, err := NewRunAsAny(nil)
	if err != nil {
		t.Fatalf("unexpected error initializing NewRunAsAny %v", err)
	}
	_, err = NewRunAsAny(&securityv1.SELinuxContextStrategyOptions{})
	if err != nil {
		t.Errorf("unexpected error initializing NewRunAsAny %v", err)
	}
}

func TestRunAsAnyMutateContainer(t *testing.T) {
	s, err := NewRunAsAny(&securityv1.SELinuxContextStrategyOptions{})
	if err != nil {
		t.Fatalf("unexpected error initializing NewRunAsAny %v", err)
	}

	sc := containerMutatorForSELinuxOpts(nil, nil)
	err = s.MutateContainer(sc)
	if opts := sc.SELinuxOptions(); opts != nil {
		t.Errorf("expected nil opts but got %v", *opts)
	}
	if err != nil {
		t.Errorf("unexpected error generating opts %v", err)
	}
}

func TestRunAsAnyValidate(t *testing.T) {
	s, err := NewRunAsAny(&securityv1.SELinuxContextStrategyOptions{
		SELinuxOptions: &corev1.SELinuxOptions{
			Level: "foo",
		},
	},
	)
	if err != nil {
		t.Fatalf("unexpected error initializing NewRunAsAny %v", err)
	}
	errs := s.ValidateContainer(nil, containerAccessorForSELinuxOpts(nil, nil))
	if len(errs) != 0 {
		t.Errorf("unexpected errors validating with ")
	}
	s, err = NewRunAsAny(&securityv1.SELinuxContextStrategyOptions{})
	if err != nil {
		t.Fatalf("unexpected error initializing NewRunAsAny %v", err)
	}
	errs = s.ValidateContainer(nil, containerAccessorForSELinuxOpts(nil, nil))
	if len(errs) != 0 {
		t.Errorf("unexpected errors validating %v", errs)
	}
}

func containerAccessorForSELinuxOpts(podOpts, containerOpts *coreapi.SELinuxOptions) securitycontext.ContainerSecurityContextAccessor {
	return securitycontext.NewEffectiveContainerSecurityContextAccessor(
		securitycontext.NewPodSecurityContextAccessor(
			&coreapi.PodSecurityContext{SELinuxOptions: podOpts},
		),
		securitycontext.NewContainerSecurityContextMutator(
			&coreapi.SecurityContext{SELinuxOptions: containerOpts},
		))
}

func containerMutatorForSELinuxOpts(podOpts, containerOpts *coreapi.SELinuxOptions) securitycontext.ContainerSecurityContextMutator {
	return securitycontext.NewEffectiveContainerSecurityContextMutator(
		securitycontext.NewPodSecurityContextAccessor(&coreapi.PodSecurityContext{
			SELinuxOptions: podOpts,
		}),
		securitycontext.NewContainerSecurityContextMutator(&coreapi.SecurityContext{
			SELinuxOptions: containerOpts,
		}),
	)
}
