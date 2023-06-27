package group

import (
	"testing"

	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/securitycontext"

	securityv1 "github.com/openshift/api/security/v1"
)

func TestMustRunAsOptions(t *testing.T) {
	tests := map[string]struct {
		ranges []securityv1.IDRange
		pass   bool
	}{
		"empty": {
			ranges: []securityv1.IDRange{},
		},
		"ranges": {
			ranges: []securityv1.IDRange{
				{Min: 1, Max: 1},
			},
			pass: true,
		},
	}

	for k, v := range tests {
		_, err := NewMustRunAs(v.ranges, "", func(securitycontext.PodSecurityContextAccessor) []int64 { return nil }, nil)
		if v.pass && err != nil {
			t.Errorf("error creating strategy for %s: %v", k, err)
		}
		if !v.pass && err == nil {
			t.Errorf("expected error for %s but got none", k)
		}
	}
}

func TestGenerate(t *testing.T) {
	tests := map[string]struct {
		ranges   []securityv1.IDRange
		expected []int64
	}{
		"multi value": {
			ranges: []securityv1.IDRange{
				{Min: 1, Max: 2},
			},
			expected: []int64{1},
		},
		"single value": {
			ranges: []securityv1.IDRange{
				{Min: 1, Max: 1},
			},
			expected: []int64{1},
		},
		"multi range": {
			ranges: []securityv1.IDRange{
				{Min: 1, Max: 1},
				{Min: 2, Max: 500},
			},
			expected: []int64{1},
		},
	}

	for k, v := range tests {
		s, err := NewMustRunAs(v.ranges, "",
			func(sc securitycontext.PodSecurityContextAccessor) []int64 { return sc.SupplementalGroups() },
			func(pscm securitycontext.PodSecurityContextMutator, val int64) {
				pscm.SetSupplementalGroups([]int64{val})
			})
		if err != nil {
			t.Errorf("error creating strategy for %s: %v", k, err)
		}
		sc := securitycontext.NewPodSecurityContextMutator(&api.PodSecurityContext{})
		err = s.MutatePod(sc)
		if err != nil {
			t.Errorf("unexpected error for %s: %v", k, err)
		}
		actual := sc.SupplementalGroups()
		if len(actual) != len(v.expected) {
			t.Errorf("unexpected generated values.  Expected %v, got %v", v.expected, actual)
			continue
		}
		if len(actual) > 0 && len(v.expected) > 0 {
			if actual[0] != v.expected[0] {
				t.Errorf("unexpected generated values.  Expected %v, got %v", v.expected, actual)
			}
		}
	}
}

func TestValidate(t *testing.T) {
	tests := map[string]struct {
		ranges []securityv1.IDRange
		pod    *api.Pod
		groups []int64
		pass   bool
	}{
		"nil security context": {
			ranges: []securityv1.IDRange{
				{Min: 1, Max: 3},
			},
		},
		"empty groups": {
			ranges: []securityv1.IDRange{
				{Min: 1, Max: 3},
			},
		},
		"not in range": {
			groups: []int64{5},
			ranges: []securityv1.IDRange{
				{Min: 1, Max: 3},
				{Min: 4, Max: 4},
			},
		},
		"in range 1": {
			groups: []int64{2},
			ranges: []securityv1.IDRange{
				{Min: 1, Max: 3},
			},
			pass: true,
		},
		"in range boundry min": {
			groups: []int64{1},
			ranges: []securityv1.IDRange{
				{Min: 1, Max: 3},
			},
			pass: true,
		},
		"in range boundry max": {
			groups: []int64{3},
			ranges: []securityv1.IDRange{
				{Min: 1, Max: 3},
			},
			pass: true,
		},
		"singular range": {
			groups: []int64{4},
			ranges: []securityv1.IDRange{
				{Min: 4, Max: 4},
			},
			pass: true,
		},
	}

	for k, v := range tests {
		s, err := NewMustRunAs(v.ranges, "", func(_ securitycontext.PodSecurityContextAccessor) []int64 { return v.groups }, nil)
		if err != nil {
			t.Errorf("error creating strategy for %s: %v", k, err)
		}
		errs := s.ValidatePod(nil, securitycontext.NewPodSecurityContextAccessor(nil))
		if v.pass && len(errs) > 0 {
			t.Errorf("unexpected errors for %s: %v", k, errs)
		}
		if !v.pass && len(errs) == 0 {
			t.Errorf("expected no errors for %s but got: %v", k, errs)
		}
	}
}
