package sccadmission

import (
	"context"
	"fmt"
	"testing"

	"github.com/openshift/apiserver-library-go/pkg/securitycontextconstraints/sccmatching"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	corev1listers "k8s.io/client-go/listers/core/v1"
	coreapi "k8s.io/kubernetes/pkg/apis/core"
)

// fakeNodeLister is a simple implementation for testing that returns empty node list
type fakeNodeLister struct{}

func (f *fakeNodeLister) List(selector labels.Selector) ([]*corev1.Node, error) {
	return []*corev1.Node{}, nil
}

func (f *fakeNodeLister) Get(name string) (*corev1.Node, error) {
	return nil, fmt.Errorf("node %s not found", name)
}

var _ corev1listers.NodeLister = &fakeNodeLister{}

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
				provider, err = sccmatching.NewSimpleProvider(userSCC, getTestSysctls())
			} else {
				provider, err = sccmatching.NewSimpleProvider(saSCC, getTestSysctls())
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
