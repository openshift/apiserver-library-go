package seccomp

import (
	"reflect"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
	api "k8s.io/kubernetes/pkg/apis/core"
)

func TestNewStrategy(t *testing.T) {
	allowAnyNoDefault := []string{"*"}
	allowAnyDefault := []string{"*", "foo"}
	allowAnyDefaultFirst := []string{"foo", "*", "bar"}
	allowSpecificOnly := []string{"bar", "foo"}

	tests := map[string]struct {
		allowedSeccompProfiles  []string
		expectedAllowAny        bool
		expectedAllowedProfiles []string
	}{
		"no seccomp": {
			expectedAllowAny:        false,
			expectedAllowedProfiles: []string{},
		},
		"allow any, no default": {
			allowedSeccompProfiles:  allowAnyNoDefault,
			expectedAllowAny:        true,
			expectedAllowedProfiles: []string{},
		},
		"allow any, default": {
			allowedSeccompProfiles:  allowAnyDefault,
			expectedAllowAny:        true,
			expectedAllowedProfiles: []string{"foo"},
		},
		"allow any and specific, default": {
			allowedSeccompProfiles:  allowAnyDefaultFirst,
			expectedAllowAny:        true,
			expectedAllowedProfiles: []string{"foo", "bar"},
		},
		"allow specific only": {
			allowedSeccompProfiles:  allowSpecificOnly,
			expectedAllowAny:        false,
			expectedAllowedProfiles: []string{"bar", "foo"},
		},
	}
	for k, v := range tests {
		s := NewSeccompStrategy(v.allowedSeccompProfiles)
		internalStrat, _ := s.(*strategy)

		if internalStrat.allowAnyProfile != v.expectedAllowAny {
			t.Errorf("%s expected allowAnyProfile to be %t but found %t", k, v.expectedAllowAny, internalStrat.allowAnyProfile)
		}

		if !reflect.DeepEqual(v.expectedAllowedProfiles, internalStrat.allowedProfiles) {
			t.Errorf("%s expected expectedAllowedProfiles to be %#v but found %#v", k, v.expectedAllowedProfiles, internalStrat.allowedProfiles)
		}
	}
}

func TestGenerate(t *testing.T) {
	tests := map[string]struct {
		podAnnotations  map[string]string
		podProfile      *api.SeccompProfile
		allowedProfiles []string
		expectedProfile string
	}{
		"empty allowed profiles": {
			allowedProfiles: []string{},
			expectedProfile: "",
		},
		"nil allowed profiles": {
			allowedProfiles: nil,
			expectedProfile: "",
		},
		"allow wildcard only": {
			allowedProfiles: []string{allowAnyProfile},
			expectedProfile: "",
		},
		"allow values": {
			allowedProfiles: []string{"foo", "bar"},
			expectedProfile: "foo",
		},
		"allow wildcard and values": {
			allowedProfiles: []string{"*", "foo", "bar"},
			expectedProfile: "foo",
		},
		"pod profile already set - field": {
			allowedProfiles: []string{"foo", "bar"},
			podProfile:      &api.SeccompProfile{Type: api.SeccompProfileTypeRuntimeDefault},
			expectedProfile: "runtime/default",
		},
		"pod profile already set - annotation": {
			allowedProfiles: []string{"foo", "bar"},
			podAnnotations:  map[string]string{v1.SeccompPodAnnotationKey: "baz"},
			expectedProfile: "baz",
		},
		"pod profile already set - both set": {
			allowedProfiles: []string{"foo", "bar"},
			podAnnotations:  map[string]string{v1.SeccompPodAnnotationKey: "baz"},
			podProfile:      &api.SeccompProfile{Type: api.SeccompProfileTypeRuntimeDefault},
			expectedProfile: "baz",
		},
	}

	for k, v := range tests {
		strategy := NewSeccompStrategy(v.allowedProfiles)

		pod := &api.Pod{
			Spec: api.PodSpec{
				SecurityContext: &api.PodSecurityContext{
					SeccompProfile: v.podProfile,
				},
			},
		}

		actualProfile, generationError := strategy.Generate(v.podAnnotations, pod)
		if generationError != nil {
			t.Errorf("%s received generation error %v", k, generationError)
			continue
		}

		if v.expectedProfile != actualProfile {
			t.Errorf("%s expected %s but received %s", k, v.expectedProfile, actualProfile)
		}
	}
}

func TestValidatePod(t *testing.T) {
	newPod := func(annotationProfile string, fieldProfile *api.SeccompProfile) *api.Pod {
		pod := &api.Pod{}

		if annotationProfile != "" {
			pod.Annotations = map[string]string{
				api.SeccompPodAnnotationKey: annotationProfile,
			}
		}
		if fieldProfile != nil {
			pod.Spec.SecurityContext = &api.PodSecurityContext{
				SeccompProfile: fieldProfile,
			}
		}
		return pod
	}

	tests := map[string]struct {
		allowedProfiles []string
		pod             *api.Pod
		expectedMsg     string
	}{
		"empty allowed profiles, no pod profile": {
			allowedProfiles: nil,
			pod:             newPod("", nil),
			expectedMsg:     "",
		},
		"empty allowed profiles, pod profile": {
			allowedProfiles: nil,
			pod:             newPod("foo", nil),
			expectedMsg:     "seccomp may not be set",
		},
		"good pod profile": {
			allowedProfiles: []string{"foo"},
			pod:             newPod("foo", nil),
			expectedMsg:     "",
		},
		"bad pod profile": {
			allowedProfiles: []string{"foo"},
			pod:             newPod("bar", nil),
			expectedMsg:     "Forbidden: bar is not an allowed seccomp profile. Valid values are [foo]",
		},
		"wildcard allows pod profile": {
			allowedProfiles: []string{"*"},
			pod:             newPod("foo", nil),
			expectedMsg:     "",
		},
		"wildcard allows no profile": {
			allowedProfiles: []string{"*"},
			pod:             newPod("", nil),
			expectedMsg:     "",
		},
		"valid profile in both the pod annotations and field": {
			allowedProfiles: []string{"localhost/foo"},
			pod: newPod(
				"localhost/foo",
				&api.SeccompProfile{
					Type:             api.SeccompProfileTypeLocalhost,
					LocalhostProfile: strP("foo"),
				}),
			expectedMsg: "",
		},
		"invalid pod field and no annotation": {
			allowedProfiles: []string{"foo"},
			pod: newPod("", &api.SeccompProfile{
				Type:             api.SeccompProfileTypeLocalhost,
				LocalhostProfile: strP("foo"),
			}),
			expectedMsg: "Forbidden: localhost/foo is not an allowed seccomp profile. Valid values are [foo]",
		},
		"valid pod field and no annotation": {
			allowedProfiles: []string{"localhost/foo"},
			pod: newPod("", &api.SeccompProfile{
				Type:             api.SeccompProfileTypeLocalhost,
				LocalhostProfile: strP("foo"),
			}),
			expectedMsg: "",
		},
		"docker/default policy allows runtime/default in pod annotation": {
			allowedProfiles: []string{"docker/default"},
			pod:             newPod("runtime/default", nil),
			expectedMsg:     "",
		},
		"docker/default policy allows runtime/default in pod field": {
			allowedProfiles: []string{"docker/default"},
			pod:             newPod("", &api.SeccompProfile{Type: api.SeccompProfileTypeRuntimeDefault}),
			expectedMsg:     "",
		},
		"runtime/default policy allows docker/default in pod annotation": {
			allowedProfiles: []string{"runtime/default"},
			pod:             newPod("docker/default", nil),
			expectedMsg:     "",
		},
		"specific profile does not allow any other profiles": {
			allowedProfiles: []string{"runtime/default"},
			pod:             newPod("", &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined}),
			expectedMsg:     "unconfined is not an allowed seccomp profile. Valid values are [runtime/default]",
		},
	}

	for name, tc := range tests {
		strategy := NewSeccompStrategy(tc.allowedProfiles)

		errs := strategy.ValidatePod(tc.pod)

		//should've passed but didn't
		if len(tc.expectedMsg) == 0 && len(errs) > 0 {
			t.Errorf("%s expected no errors but received %v", name, errs)
		}
		//should've failed but didn't
		if len(tc.expectedMsg) != 0 && len(errs) == 0 {
			t.Errorf("%s expected error %s but received no errors", name, tc.expectedMsg)
		}
		//failed with additional messages
		if len(tc.expectedMsg) != 0 && len(errs) > 1 {
			t.Errorf("%s expected error %s but received multiple errors: %v", name, tc.expectedMsg, errs)
		}
		//check that we got the right message
		if len(tc.expectedMsg) != 0 && len(errs) == 1 {
			if !strings.Contains(errs[0].Error(), tc.expectedMsg) {
				t.Errorf("%s expected error to contain %q but it did not: %v", name, tc.expectedMsg, errs)
			}
		}
	}
}

func TestValidateContainer(t *testing.T) {
	newPod := func(annotationProfile string, fieldProfile *api.SeccompProfile) *api.Pod {
		pod := &api.Pod{
			Spec: api.PodSpec{
				Containers: []api.Container{
					{
						Name: "test",
					},
				},
			},
		}

		if annotationProfile != "" {
			pod.Annotations = map[string]string{
				api.SeccompContainerAnnotationKeyPrefix + "test": annotationProfile,
			}
		}

		if fieldProfile != nil {
			pod.Spec.Containers[0].SecurityContext = &api.SecurityContext{
				SeccompProfile: fieldProfile,
			}
		}
		return pod
	}

	tests := map[string]struct {
		allowedProfiles []string
		pod             *api.Pod
		expectedMsg     string
	}{
		"empty allowed profiles, no container profile": {
			allowedProfiles: nil,
			pod:             newPod("", nil),
			expectedMsg:     "",
		},
		"empty allowed profiles, container profile": {
			allowedProfiles: nil,
			pod:             newPod("foo", nil),
			expectedMsg:     "seccomp may not be set",
		},
		"good container profile": {
			allowedProfiles: []string{"foo"},
			pod:             newPod("foo", nil),
			expectedMsg:     "",
		},
		"bad container profile": {
			allowedProfiles: []string{"foo"},
			pod:             newPod("bar", nil),
			expectedMsg:     "Forbidden: bar is not an allowed seccomp profile. Valid values are [foo]",
		},
		"wildcard allows container profile": {
			allowedProfiles: []string{"*"},
			pod:             newPod("foo", nil),
			expectedMsg:     "",
		},
		"wildcard allows no profile": {
			allowedProfiles: []string{"*"},
			pod:             newPod("", nil),
			expectedMsg:     "",
		},
		"valid container field and no annotation": {
			allowedProfiles: []string{"localhost/foo"},
			pod: newPod("", &api.SeccompProfile{
				Type:             api.SeccompProfileTypeLocalhost,
				LocalhostProfile: strP("foo"),
			}),
			expectedMsg: "",
		},
		"invalid container field and no annotation": {
			allowedProfiles: []string{"localhost/foo"},
			pod: newPod("", &api.SeccompProfile{
				Type:             api.SeccompProfileTypeLocalhost,
				LocalhostProfile: strP("bar"),
			}),
			expectedMsg: "Forbidden: localhost/bar is not an allowed seccomp profile. Valid values are [localhost/foo]",
		},
		"runtime/default allows the profile of that type": {
			allowedProfiles: []string{"runtime/default"},
			pod:             newPod("", &api.SeccompProfile{Type: api.SeccompProfileTypeRuntimeDefault}),
			expectedMsg:     "",
		},
		"specific profile does not allow any other profiles": {
			allowedProfiles: []string{"runtime/default"},
			pod:             newPod("", &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined}),
			expectedMsg:     "unconfined is not an allowed seccomp profile. Valid values are [runtime/default]",
		},
	}

	for name, tc := range tests {
		strategy := NewSeccompStrategy(tc.allowedProfiles)

		errs := strategy.ValidateContainer(tc.pod, &tc.pod.Spec.Containers[0])

		//should've passed but didn't
		if len(tc.expectedMsg) == 0 && len(errs) > 0 {
			t.Errorf("%s expected no errors but received %v", name, errs)
		}
		//should've failed but didn't
		if len(tc.expectedMsg) != 0 && len(errs) == 0 {
			t.Errorf("%s expected error %s but received no errors", name, tc.expectedMsg)
		}
		//failed with additional messages
		if len(tc.expectedMsg) != 0 && len(errs) > 1 {
			t.Errorf("%s expected error %s but received multiple errors: %v", name, tc.expectedMsg, errs)
		}
		//check that we got the right message
		if len(tc.expectedMsg) != 0 && len(errs) == 1 {
			if !strings.Contains(errs[0].Error(), tc.expectedMsg) {
				t.Errorf("%s expected error to contain %q but it did not: %v", name, tc.expectedMsg, errs)
			}
		}
	}
}

func strP(s string) *string {
	return &s
}
