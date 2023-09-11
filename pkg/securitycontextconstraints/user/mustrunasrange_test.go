package user

import (
	"fmt"
	"strings"
	"testing"

	securityv1 "github.com/openshift/api/security/v1"
)

func TestMustRunAsRangeOptions(t *testing.T) {
	var uid int64 = 1
	tests := map[string]struct {
		opts *securityv1.RunAsUserStrategyOptions
		pass bool
	}{
		"invalid opts, required min and max": {
			opts: &securityv1.RunAsUserStrategyOptions{},
			pass: false,
		},
		"invalid opts, required max": {
			opts: &securityv1.RunAsUserStrategyOptions{UIDRangeMin: &uid},
			pass: false,
		},
		"invalid opts, required min": {
			opts: &securityv1.RunAsUserStrategyOptions{UIDRangeMax: &uid},
			pass: false,
		},
		"valid opts": {
			opts: &securityv1.RunAsUserStrategyOptions{UIDRangeMin: &uid, UIDRangeMax: &uid},
			pass: true,
		},
	}
	for name, tc := range tests {
		_, err := NewMustRunAsRange(tc.opts)
		if err != nil && tc.pass {
			t.Errorf("%s expected to pass but received error %v", name, err)
		}
		if err == nil && !tc.pass {
			t.Errorf("%s expected to fail but did not receive an error", name)
		}
	}
}

func TestMustRunAsRangeGenerate(t *testing.T) {
	var uidMin int64 = 1
	var uidMax int64 = 10
	opts := &securityv1.RunAsUserStrategyOptions{UIDRangeMin: &uidMin, UIDRangeMax: &uidMax}
	mustRunAsRange, err := NewMustRunAsRange(opts)
	if err != nil {
		t.Fatalf("unexpected error initializing NewMustRunAsRange %v", err)
	}
	generated, err := mustRunAsRange.Generate(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error generating uid %v", err)
	}
	if *generated != uidMin {
		t.Errorf("generated uid does not equal expected uid")
	}
}

func TestMustRunAsRangeValidate(t *testing.T) {
	var uidMin int64 = 1
	var uidMax int64 = 10
	opts := &securityv1.RunAsUserStrategyOptions{UIDRangeMin: &uidMin, UIDRangeMax: &uidMax}
	mustRunAsRange, err := NewMustRunAsRange(opts)
	if err != nil {
		t.Fatalf("unexpected error initializing NewMustRunAsRange %v", err)
	}

	errs := mustRunAsRange.ValidateContainer(nil, accessorForUser(nil, nil))
	expectedMessage := "runAsUser: Required value"
	if len(errs) == 0 {
		t.Errorf("expected errors from nil runAsUser but got none")
	} else if !strings.Contains(errs[0].Error(), expectedMessage) {
		t.Errorf("expected error to contain %q but it did not: %v", expectedMessage, errs)
	}

	var lowUid int64 = 0
	errs = mustRunAsRange.ValidateContainer(nil, accessorForUser(nil, &lowUid))
	expectedMessage = fmt.Sprintf("runAsUser: Invalid value: %d: must be in the ranges: [%d, %d]", lowUid, uidMin, uidMax)
	if len(errs) == 0 {
		t.Errorf("expected errors from mismatch uid but got none")
	} else if !strings.Contains(errs[0].Error(), expectedMessage) {
		t.Errorf("expected error to contain %q but it did not: %v", expectedMessage, errs)
	}

	var highUid int64 = 11
	errs = mustRunAsRange.ValidateContainer(nil, accessorForUser(nil, &highUid))
	expectedMessage = fmt.Sprintf("runAsUser: Invalid value: %d: must be in the ranges: [%d, %d]", highUid, uidMin, uidMax)
	if len(errs) == 0 {
		t.Errorf("expected errors from mismatch uid but got none")
	} else if !strings.Contains(errs[0].Error(), expectedMessage) {
		t.Errorf("expected error to contain %q but it did not: %v", expectedMessage, errs)
	}

	var goodUid int64 = 5
	errs = mustRunAsRange.ValidateContainer(nil, accessorForUser(nil, &goodUid))
	if len(errs) != 0 {
		t.Errorf("expected no errors from matching uid but got %v", errs)
	}
}
