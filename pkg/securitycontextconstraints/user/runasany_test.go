package user

import (
	"testing"

	securityv1 "github.com/openshift/api/security/v1"
)

func TestRunAsAnyOptions(t *testing.T) {
	_, err := NewRunAsAny(nil)
	if err != nil {
		t.Fatalf("unexpected error initializing NewRunAsAny %v", err)
	}
	_, err = NewRunAsAny(&securityv1.RunAsUserStrategyOptions{})
	if err != nil {
		t.Errorf("unexpected error initializing NewRunAsAny %v", err)
	}
}

func TestRunAsAnyGenerate(t *testing.T) {
	s, err := NewRunAsAny(&securityv1.RunAsUserStrategyOptions{})
	if err != nil {
		t.Fatalf("unexpected error initializing NewRunAsAny %v", err)
	}
	sc := mutatorForUser(nil, nil)
	err = s.MutateContainer(sc)
	if uid := sc.RunAsUser(); uid != nil {
		t.Errorf("expected nil uid but got %d", *uid)
	}
	if err != nil {
		t.Errorf("unexpected error generating uid %v", err)
	}
}

func TestRunAsAnyValidate(t *testing.T) {
	s, err := NewRunAsAny(&securityv1.RunAsUserStrategyOptions{})
	if err != nil {
		t.Fatalf("unexpected error initializing NewRunAsAny %v", err)
	}
	errs := s.ValidateContainer(nil, nil)
	if len(errs) != 0 {
		t.Errorf("unexpected errors validating with ")
	}
}
