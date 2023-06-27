package sccmatching

import (
	securityv1 "github.com/openshift/api/security/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	api "k8s.io/kubernetes/pkg/apis/core"
)

// SecurityContextConstraintsProvider provides the implementation to generate a new security
// context based on constraints or validate an existing security context against constraints.
type SecurityContextConstraintsProvider interface {
	ApplyToPod(pod *api.Pod) field.ErrorList
	// Get the SCC that this provider was initialized with.
	GetSCC() *securityv1.SecurityContextConstraints
	// Get the name of the SCC that this provider was initialized with.
	GetSCCName() string
	// Get the users associated to the SCC this provider was initialized with
	GetSCCUsers() []string
	// Get the groups associated to the SCC this provider was initialized with
	GetSCCGroups() []string
}
