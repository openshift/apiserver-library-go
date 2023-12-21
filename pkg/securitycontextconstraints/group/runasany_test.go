package group

import (
	"testing"

	"k8s.io/kubernetes/pkg/securitycontext"
)

func TestRunAsAnyGenerate(t *testing.T) {
	s, err := NewRunAsAny()
	if err != nil {
		t.Fatalf("unexpected error initializing NewRunAsAny %v", err)
	}
	sc := securitycontext.NewPodSecurityContextMutator(nil)

	err = s.MutatePod(sc)
	if err != nil {
		t.Errorf("unexpected error generating groups: %v", err)
	}
}

func TestRunAsAnyValidte(t *testing.T) {
	s, err := NewRunAsAny()
	if err != nil {
		t.Fatalf("unexpected error initializing NewRunAsAny %v", err)
	}
	errs := s.ValidatePod(nil, securitycontext.NewPodSecurityContextAccessor(nil))
	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
}
