package sccadmission

import (
	"context"
	"testing"

	"github.com/openshift/apiserver-library-go/pkg/securitycontextconstraints/sccmatching"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	coreapi "k8s.io/kubernetes/pkg/apis/core"
)

func TestSCCAuthorizationChecker(t *testing.T) {
	userSCC := laxSCC()
	userSCC.Name = "user-scc"
	userSCC.Users = []string{"test-user"}
	userSCC.Groups = []string{}

	saSCC := laxSCC()
	saSCC.Name = "sa-scc"
	saSCC.Users = []string{}
	saSCC.Groups = []string{}

	userName := "test-user"
	saName := "system:serviceaccount:test-ns:default"

	tests := []struct {
		testName  string
		user      string
		namespace string
		scc       string
		expected  string
	}{
		{
			testName:  "user authorization only",
			user:      userName,
			namespace: "test-ns",
			scc:       "user-scc",
			expected:  "user",
		},
		{
			testName:  "service account authorization only",
			user:      saName,
			namespace: "test-ns",
			scc:       "sa-scc",
			expected:  "serviceaccount",
		},
		{
			testName:  "both authorized - should prefer service account",
			user:      saName,
			namespace: "test-ns",
			scc:       "sa-scc",
			expected:  "serviceaccount",
		},
		{
			testName:  "neither authorized",
			user:      "different-user",
			namespace: "test-ns",
			scc:       "sa-scc", // Can't use user-scc, which contains the user. Will lead into SAR fake request.
			expected:  "none",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			testAuthorizer := &sccTestAuthorizer{
				t:         t,
				user:      test.user,
				namespace: test.namespace,
				scc:       test.scc,
			}

			// Only matter in user scenario / where SA isn't authorized.
			userInfo := &user.DefaultInfo{
				Name: userName,
			}

			attr := admission.NewAttributesRecord(
				nil, nil,
				coreapi.Kind("Pod").WithVersion("version"),
				test.namespace, "pod-name",
				coreapi.Resource("pods").WithVersion("version"), "",
				admission.Create, nil,
				false,
				userInfo,
			)

			checker := newSCCAuthorizerChecker(
				testAuthorizer,
				attr,
				"default",
			)

			// Transform SCC into Provider.
			var provider sccmatching.SecurityContextConstraintsProvider
			var err error
			if test.scc == "user-scc" {
				provider, err = sccmatching.NewSimpleProvider(userSCC)
			} else {
				provider, err = sccmatching.NewSimpleProvider(saSCC)
			}
			if err != nil {
				t.Fatalf("Error creating provider: %v", err)
			}

			result := checker.allowedForType(context.Background(), provider)
			if result != test.expected {
				t.Errorf("Expected allowedFor to return %q but got %q", test.expected, result)
			}
		})
	}
}
