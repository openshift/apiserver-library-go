package sccadmission

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	coreapi "k8s.io/kubernetes/pkg/apis/core"
	podhelpers "k8s.io/kubernetes/pkg/apis/core/pods"
	"k8s.io/utils/ptr"

	securityv1 "github.com/openshift/api/security/v1"
	securityv1listers "github.com/openshift/client-go/security/listers/security/v1"

	"github.com/openshift/apiserver-library-go/pkg/securitycontextconstraints/sccmatching"
	sccsort "github.com/openshift/apiserver-library-go/pkg/securitycontextconstraints/util/sort"
)

// createSAForTest Build and Initializes a ServiceAccount for tests
func createSAForTest() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default",
			Namespace: "default",
		},
	}
}

// createNamespaceForTest builds and initializes a Namespaces for tests
func createNamespaceForTest() *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
			Annotations: map[string]string{
				securityv1.UIDRangeAnnotation:           "1/3",
				securityv1.MCSAnnotation:                "s0:c1,c0",
				securityv1.SupplementalGroupsAnnotation: "2/3",
			},
		},
	}
}

func newTestAdmission(sccLister securityv1listers.SecurityContextConstraintsLister, nsLister corev1listers.NamespaceLister, authorizer authorizer.Authorizer) admission.Interface {
	return &constraint{
		Handler:         admission.NewHandler(admission.Create),
		namespaceLister: nsLister,
		sccLister:       sccLister,
		listersSynced:   []cache.InformerSynced{func() bool { return true }},
		authorizer:      authorizer,
	}
}

func TestFailClosedOnInvalidPod(t *testing.T) {
	plugin := newTestAdmission(nil, nil, nil)
	pod := &corev1.Pod{}
	attrs := admission.NewAttributesRecord(pod, nil, coreapi.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, coreapi.Resource("pods").WithVersion("version"), "", admission.Create, nil, false, &user.DefaultInfo{})
	err := plugin.(admission.MutationInterface).Admit(context.TODO(), attrs, nil)

	if err == nil {
		t.Fatalf("expected versioned pod object to fail admission")
	}
	if !strings.Contains(err.Error(), "object was marked as kind pod but was unable to be converted") {
		t.Errorf("expected error to be conversion erorr but got: %v", err)
	}
}

func TestAdmitCaps(t *testing.T) {
	createPodWithCaps := func(caps *coreapi.Capabilities) *coreapi.Pod {
		pod := goodPod()
		pod.Spec.Containers[0].SecurityContext.Capabilities = caps
		return pod
	}

	restricted := restrictiveSCC()

	allowsFooInAllowed := restrictiveSCC()
	allowsFooInAllowed.Name = "allowCapInAllowed"
	allowsFooInAllowed.AllowedCapabilities = []corev1.Capability{"foo"}

	allowsFooInRequired := restrictiveSCC()
	allowsFooInRequired.Name = "allowCapInRequired"
	allowsFooInRequired.DefaultAddCapabilities = []corev1.Capability{"foo"}

	requiresFooToBeDropped := restrictiveSCC()
	requiresFooToBeDropped.Name = "requireDrop"
	requiresFooToBeDropped.RequiredDropCapabilities = []corev1.Capability{"foo"}

	allowAllInAllowed := restrictiveSCC()
	allowAllInAllowed.Name = "allowAllCapsInAllowed"
	allowAllInAllowed.AllowedCapabilities = []corev1.Capability{securityv1.AllowAllCapabilities}

	tc := map[string]struct {
		caps                 *coreapi.Capabilities
		sccs                 []*securityv1.SecurityContextConstraints
		shouldPass           bool
		expectedCapabilities *coreapi.Capabilities
	}{
		// UC 1: if an SCC does not define allowed or required caps then a pod requesting a cap
		// should be rejected.
		"should reject cap add when not allowed or required": {
			caps:       &coreapi.Capabilities{Add: []coreapi.Capability{"foo"}},
			sccs:       []*securityv1.SecurityContextConstraints{restricted},
			shouldPass: false,
		},
		// UC 2: if an SCC allows a cap in the allowed field it should accept the pod request
		// to add the cap.
		"should accept cap add when in allowed": {
			caps:       &coreapi.Capabilities{Add: []coreapi.Capability{"foo"}},
			sccs:       []*securityv1.SecurityContextConstraints{restricted, allowsFooInAllowed},
			shouldPass: true,
		},
		// UC 3: if an SCC requires a cap then it should accept the pod request
		// to add the cap.
		"should accept cap add when in required": {
			caps:       &coreapi.Capabilities{Add: []coreapi.Capability{"foo"}},
			sccs:       []*securityv1.SecurityContextConstraints{restricted, allowsFooInRequired},
			shouldPass: true,
		},
		// UC 4: if an SCC requires a cap to be dropped then it should fail both
		// in the verification of adds and verification of drops
		"should reject cap add when requested cap is required to be dropped": {
			caps:       &coreapi.Capabilities{Add: []coreapi.Capability{"foo"}},
			sccs:       []*securityv1.SecurityContextConstraints{restricted, requiresFooToBeDropped},
			shouldPass: false,
		},
		// UC 5: if an SCC requires a cap to be dropped it should accept
		// a manual request to drop the cap.
		"should accept cap drop when cap is required to be dropped": {
			caps:       &coreapi.Capabilities{Drop: []coreapi.Capability{"foo"}},
			sccs:       []*securityv1.SecurityContextConstraints{restricted, requiresFooToBeDropped},
			shouldPass: true,
		},
		// UC 6: required add is defaulted
		"required add is defaulted": {
			sccs:       []*securityv1.SecurityContextConstraints{allowsFooInRequired},
			shouldPass: true,
			expectedCapabilities: &coreapi.Capabilities{
				Add: []coreapi.Capability{"foo"},
			},
		},
		// UC 7: required drop is defaulted
		"required drop is defaulted": {
			sccs:       []*securityv1.SecurityContextConstraints{requiresFooToBeDropped},
			shouldPass: true,
			expectedCapabilities: &coreapi.Capabilities{
				Drop: []coreapi.Capability{"foo"},
			},
		},
		// UC 8: using '*' in allowed caps
		"should accept cap add when all caps are allowed": {
			caps:       &coreapi.Capabilities{Add: []coreapi.Capability{"foo"}},
			sccs:       []*securityv1.SecurityContextConstraints{restricted, allowAllInAllowed},
			shouldPass: true,
		},
	}

	for k, v := range tc {
		for i := 0; i < 3; i++ {
			pod := goodPod()
			if v.caps != nil {
				pod = createPodWithCaps(v.caps)
				switch i {
				case 1:
					// test init containers
					pod.Spec.Containers, pod.Spec.InitContainers = nil, pod.Spec.Containers
				case 2:
					// test ephemeral containers
					for _, c := range pod.Spec.Containers {
						pod.Spec.EphemeralContainers = append(pod.Spec.EphemeralContainers, coreapi.EphemeralContainer{EphemeralContainerCommon: coreapi.EphemeralContainerCommon{SecurityContext: c.SecurityContext}})
					}
					pod.Spec.Containers = nil
				}
			}

			t.Run(fmt.Sprintf("%s-%d", k, i), func(t *testing.T) {
				testSCCAdmit(k, v.sccs, pod, v.shouldPass, t)

				if v.expectedCapabilities != nil {
					podhelpers.VisitContainersWithPath(
						&pod.Spec, field.NewPath("testPodSpec"), func(container *coreapi.Container, path *field.Path) bool {
							if !reflect.DeepEqual(v.expectedCapabilities, container.SecurityContext.Capabilities) {
								t.Errorf("%s resulted in caps that were not expected at path %q - expected: %#v, received: %#v", k, path.String(), v.expectedCapabilities, container.SecurityContext.Capabilities)
							}
							return true
						})
				}
			})
		}
	}
}

func TestShouldIgnore(t *testing.T) {
	podCreationToAttributes := func(p *coreapi.Pod) admission.Attributes {
		return admission.NewAttributesRecord(
			p, nil,
			coreapi.Kind("Pod").WithVersion("version"),
			p.Namespace, p.Name,
			coreapi.Resource("pods").WithVersion("version"),
			"",
			admission.Create,
			nil,
			false,
			&user.DefaultInfo{},
		)
	}

	withUpdate := func(p *coreapi.Pod, subresource string, mutate func(p *coreapi.Pod) *coreapi.Pod) admission.Attributes {
		updatedPod := mutate(p.DeepCopy())

		return admission.NewAttributesRecord(
			updatedPod, p,
			coreapi.Kind("Pod").WithVersion("version"),
			p.Namespace, p.Name,
			coreapi.Resource("pods").WithVersion("version"),
			subresource,
			admission.Update,
			nil,
			false,
			&user.DefaultInfo{},
		)
	}
	withStatusUpdate := func(p *coreapi.Pod) admission.Attributes {
		return withUpdate(p, "status", func(p *coreapi.Pod) *coreapi.Pod {
			p.Status.Message = "The pod is in this state because it got there somehow"
			return p
		})
	}

	type testCase struct {
		description         string
		shouldIgnore        bool
		admissionAttributes admission.Attributes
	}

	tests := []testCase{
		{
			description:         "Windows pod should be ignored",
			shouldIgnore:        true,
			admissionAttributes: podCreationToAttributes(windowsPod()),
		},
		{
			description:         "Linux pod with OS field not set should not be ignored",
			shouldIgnore:        false,
			admissionAttributes: podCreationToAttributes(goodPod()),
		},
		{
			description:         "Linux pod with OS field explicitly set should not be ignored",
			shouldIgnore:        false,
			admissionAttributes: podCreationToAttributes(linuxPod()),
		},
		{
			description:         "status updates are ignored",
			shouldIgnore:        true,
			admissionAttributes: withStatusUpdate(goodPod()),
		},
		{
			description:  "don't ignore normal updates",
			shouldIgnore: false,
			admissionAttributes: withUpdate(goodPod(), "",
				func(p *coreapi.Pod) *coreapi.Pod {
					p.Spec.EphemeralContainers = append(p.Spec.EphemeralContainers, coreapi.EphemeralContainer{EphemeralContainerCommon: coreapi.EphemeralContainerCommon{Name: "another container"}})
					return p
				}),
		},
		{
			description:  "don't ignore subresources outside the ignore list",
			shouldIgnore: false,
			admissionAttributes: withUpdate(goodPod(), "ephemeralcontainers",
				func(p *coreapi.Pod) *coreapi.Pod {
					p.Spec.EphemeralContainers = append(p.Spec.EphemeralContainers, coreapi.EphemeralContainer{EphemeralContainerCommon: coreapi.EphemeralContainerCommon{Name: "another container"}})
					return p
				}),
		},
	}

	for _, annotation := range ignoredAnnotations.List() {
		tests = append(tests, testCase{
			description:  fmt.Sprintf("add ignored annotation %v", annotation),
			shouldIgnore: true,
			admissionAttributes: withUpdate(goodPod(), "annotations",
				func(p *coreapi.Pod) *coreapi.Pod {
					if p.ObjectMeta.Annotations == nil {
						p.ObjectMeta.Annotations = map[string]string{}
					}
					p.ObjectMeta.Annotations[annotation] = "somevalue"
					return p
				}),
		})
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			ignored, err := shouldIgnore(test.admissionAttributes)
			if err != nil {
				t.Errorf("expected the test to not error but it errored with %v", err)
			}
			if ignored != test.shouldIgnore {
				t.Errorf("expected outcome %v but got %v", test.shouldIgnore, ignored)
			}
		})
	}
}

func TestShouldIgnoreMetaChanges(t *testing.T) {
	emptyMeta := metav1.ObjectMeta{}
	emptyAnno := metav1.ObjectMeta{Annotations: map[string]string{}}
	baseMeta := metav1.ObjectMeta{
		Annotations:     map[string]string{"aaa": "aaa", "bbb": "bbb"},
		ManagedFields:   []metav1.ManagedFieldsEntry{{Manager: "manager"}},
		OwnerReferences: []metav1.OwnerReference{{Name: "foo"}},
		Finalizers:      []string{"final"},
	}

	ignoredAnno := metav1.ObjectMeta{Annotations: map[string]string{"k8s.ovn.org/pod-networks": "pod-networks-here", "aaa": "aaa", "bbb": "bbb"}}
	onlyIgnoredAnno := metav1.ObjectMeta{Annotations: map[string]string{"k8s.ovn.org/pod-networks": "pod-networks-here"}}
	changedIgnoredAnno := metav1.ObjectMeta{Annotations: map[string]string{"k8s.ovn.org/pod-networks": "pod-networks-here-indeed", "aaa": "aaa", "bbb": "bbb"}}
	nonIgnoredAnno := metav1.ObjectMeta{Annotations: map[string]string{"aaa": "aaa", "bbb": "bbb", "ccc": "ccc"}}
	changedNonIgnoredAnno := metav1.ObjectMeta{Annotations: map[string]string{"aaa": "aaa", "bbb": "bbb", "ccc": "CCC"}}
	ignoredAndNonIgnoredAnno := metav1.ObjectMeta{Annotations: map[string]string{"k8s.ovn.org/pod-networks": "pod-networks-here", "aaa": "aaa", "bbb": "bbb", "ccc": "ccc"}}
	ignoredAndNonIgnoredAnnoUpdated := metav1.ObjectMeta{Annotations: map[string]string{"k8s.ovn.org/pod-networks": "pod-networks-here-2", "aaa": "AAA", "bbb": "BBB", "ccc": "CCC"}}
	managedFields := metav1.ObjectMeta{ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "manager"}}}
	ownerRef := metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{Name: "foo"}}}
	ownerRefFinalizer := metav1.ObjectMeta{
		OwnerReferences: []metav1.OwnerReference{{Name: "foo"}},
		Finalizers:      []string{"final"},
	}

	labelsMeta := metav1.ObjectMeta{Annotations: map[string]string{"k8s.ovn.org/pod-networks": "net"}, Labels: map[string]string{"label1": "val1", "label2": "val2"}}
	labelsMetaAdded := metav1.ObjectMeta{Annotations: map[string]string{"k8s.ovn.org/pod-networks": "net"}, Labels: map[string]string{"label1": "val1", "label2": "val2", "label3": "val3"}}
	labelsMetaRemoved := metav1.ObjectMeta{Annotations: map[string]string{"k8s.ovn.org/pod-networks": "net"}, Labels: map[string]string{"label1": "val1"}}
	labelsMetaChanged := metav1.ObjectMeta{Annotations: map[string]string{"k8s.ovn.org/pod-networks": "net"}, Labels: map[string]string{"label1": "val1", "label2": "val2-new"}}

	tests := []struct {
		description string
		newMeta     metav1.ObjectMeta
		oldMeta     metav1.ObjectMeta
		want        bool
	}{
		{"nil new and old annotations", emptyMeta, emptyMeta, true},
		{"empty new and old annotations", emptyAnno, emptyAnno, true},
		{"same annotations", baseMeta, baseMeta, true},
		{"different managedFields", emptyMeta, managedFields, true},
		{"only ownerRef", emptyMeta, ownerRef, true},
		{"ownerRef and finalizer", emptyMeta, ownerRefFinalizer, true},
		{"only ignored annotations added on nil old", onlyIgnoredAnno, emptyMeta, true},
		{"only ignored annotations added on empty old", onlyIgnoredAnno, emptyAnno, true},
		{"only ignored annotations removed", emptyMeta, onlyIgnoredAnno, true},
		{"ignored and other annotations added on nil old", ignoredAnno, emptyMeta, false},
		{"ignored and other annotations added on empty old", ignoredAnno, emptyAnno, false},
		{"ignored and other annotations removed", emptyAnno, ignoredAnno, false},
		{"ignored annotations added", ignoredAnno, baseMeta, true},
		{"ignored annotations changed", changedIgnoredAnno, ignoredAnno, true},
		{"ignored annotations removed", baseMeta, ignoredAnno, true},
		{"non-ignored annotations added", nonIgnoredAnno, baseMeta, false},
		{"non-ignored annotations changed", changedNonIgnoredAnno, nonIgnoredAnno, false},
		{"non-ignored annotations removed", baseMeta, nonIgnoredAnno, false},
		{"ignored and other annotations changed", ignoredAndNonIgnoredAnnoUpdated, ignoredAndNonIgnoredAnno, false},
		{"labels added", labelsMetaAdded, labelsMeta, false},
		{"labels removed", labelsMetaRemoved, labelsMeta, false},
		{"labels changed", labelsMetaChanged, labelsMeta, false},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			newPod := &coreapi.Pod{ObjectMeta: test.newMeta}
			oldPod := &coreapi.Pod{ObjectMeta: test.oldMeta}
			if got := shouldIgnoreMetaChanges(newPod, oldPod); got != test.want {
				t.Errorf("got %v; want %v; newMeta: %v; oldMeta: %v", got, test.want, test.newMeta, test.oldMeta)
			}
		})
	}
}

func testSCCAdmit(testCaseName string, sccs []*securityv1.SecurityContextConstraints, pod *coreapi.Pod, shouldPass bool, t *testing.T) {
	t.Helper()

	nsLister := createNamespaceLister(t, createNamespaceForTest())
	sccLister := createSCCLister(t, sccs)
	testAuthorizer := &sccTestAuthorizer{t: t}
	plugin := newTestAdmission(sccLister, nsLister, testAuthorizer)

	attrs := admission.NewAttributesRecord(pod, nil, coreapi.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, coreapi.Resource("pods").WithVersion("version"), "", admission.Create, nil, false, &user.DefaultInfo{})
	err := plugin.(admission.MutationInterface).Admit(context.TODO(), attrs, nil)
	if shouldPass && err != nil {
		t.Errorf("%s expected no mutating admission errors but received %v", testCaseName, err)
	}
	if !shouldPass && err == nil {
		t.Errorf("%s expected mutating admission errors but received none", testCaseName)
	}

	err = plugin.(admission.ValidationInterface).Validate(context.TODO(), attrs, nil)
	if shouldPass && err != nil {
		t.Errorf("%s expected no validating admission errors but received %v", testCaseName, err)
	}
	if !shouldPass && err == nil {
		t.Errorf("%s expected validating admission errors but received none", testCaseName)
	}
}

func TestAdmitSuccess(t *testing.T) {
	// used for cases where things are preallocated
	defaultGroup := int64(2)

	// create scc that requires allocation retrieval
	saSCC := saSCC()

	// create scc that has specific requirements that shouldn't match but is permissioned to
	// service accounts to test that even though this has matching priorities (0) and a
	// lower point value score (which will cause it to be sorted in front of scc-sa) it should not
	// validate the requests so we should try scc-sa.
	saExactSCC := saExactSCC()

	lister := createSCCLister(t, []*securityv1.SecurityContextConstraints{
		saExactSCC,
		saSCC,
	})
	namespace := createNamespaceForTest()
	nsLister := createNamespaceLister(t, namespace)

	testAuthorizer := &sccTestAuthorizer{t: t}

	// create the admission plugin
	p := newTestAdmission(lister, nsLister, testAuthorizer)

	// specifies a UID in the range of the preallocated UID annotation
	specifyUIDInRange := goodPod()
	var goodUID int64 = 3
	specifyUIDInRange.Spec.Containers[0].SecurityContext.RunAsUser = &goodUID

	// specifies an mcs label that matches the preallocated mcs annotation
	specifyLabels := goodPod()
	specifyLabels.Spec.Containers[0].SecurityContext.SELinuxOptions = &coreapi.SELinuxOptions{
		Level: "s0:c1,c0",
	}

	// specifies an FSGroup in the range of preallocated sup group annotation
	specifyFSGroupInRange := goodPod()
	// group in the range of a preallocated fs group which, by default is a single digit range
	// based on the first value of the ns annotation.
	goodFSGroup := int64(2)
	specifyFSGroupInRange.Spec.SecurityContext.FSGroup = &goodFSGroup

	// specifies a sup group in the range of preallocated sup group annotation
	specifySupGroup := goodPod()
	// group is not the default but still in the range
	specifySupGroup.Spec.SecurityContext.SupplementalGroups = []int64{3}

	specifyPodLevelSELinux := goodPod()
	specifyPodLevelSELinux.Spec.SecurityContext.SELinuxOptions = &coreapi.SELinuxOptions{
		Level: "s0:c1,c0",
	}

	seLinuxLevelFromNamespace := namespace.Annotations[securityv1.MCSAnnotation]

	trueVal := true
	testCases := map[string]struct {
		pod                 *coreapi.Pod
		expectedPodSC       *coreapi.PodSecurityContext
		expectedContainerSC *coreapi.SecurityContext
	}{
		"specifyUIDInRange": {
			pod:                 specifyUIDInRange,
			expectedPodSC:       podSC(seLinuxLevelFromNamespace, defaultGroup, defaultGroup),
			expectedContainerSC: containerSC(nil, goodUID, &trueVal),
		},
		"specifyLabels": {
			pod:                 specifyLabels,
			expectedPodSC:       podSC(seLinuxLevelFromNamespace, defaultGroup, defaultGroup),
			expectedContainerSC: containerSC(&seLinuxLevelFromNamespace, 1, &trueVal),
		},
		"specifyFSGroup": {
			pod:                 specifyFSGroupInRange,
			expectedPodSC:       podSC(seLinuxLevelFromNamespace, goodFSGroup, defaultGroup),
			expectedContainerSC: containerSC(nil, 1, &trueVal),
		},
		"specifySupGroup": {
			pod:                 specifySupGroup,
			expectedPodSC:       podSC(seLinuxLevelFromNamespace, defaultGroup, 3),
			expectedContainerSC: containerSC(nil, 1, &trueVal),
		},
		"specifyPodLevelSELinuxLevel": {
			pod:                 specifyPodLevelSELinux,
			expectedPodSC:       podSC(seLinuxLevelFromNamespace, defaultGroup, defaultGroup),
			expectedContainerSC: containerSC(nil, 1, &trueVal),
		},
	}

	for i := 0; i < 2; i++ {
		for k, v := range testCases {
			v.pod.Spec.Containers, v.pod.Spec.InitContainers = v.pod.Spec.InitContainers, v.pod.Spec.Containers

			hasErrors := testSCCAdmission(v.pod, p, saSCC.Name, k, t)
			if hasErrors {
				continue
			}

			containers := v.pod.Spec.Containers
			if i == 0 {
				containers = v.pod.Spec.InitContainers
			}

			if !reflect.DeepEqual(v.expectedPodSC, v.pod.Spec.SecurityContext) {
				t.Errorf("%s unexpected pod SecurityContext diff:\n%s", k, diff.ObjectGoPrintSideBySide(v.expectedPodSC, v.pod.Spec.SecurityContext))
			}

			if !reflect.DeepEqual(v.expectedContainerSC, containers[0].SecurityContext) {
				t.Errorf("%s unexpected container SecurityContext diff:\n%s", k, diff.ObjectGoPrintSideBySide(v.expectedContainerSC, containers[0].SecurityContext))
			}

			// Also verify that the subject type annotation is set correctly
			subjectType, ok := v.pod.Annotations["security.openshift.io/validated-scc-subject-type"]
			if !ok {
				t.Errorf("%s expected to find the validated-scc-subject-type annotation but found none", k)
			} else if subjectType != "serviceaccount" {
				// In the TestAdmitSuccess test, we're using a serviceaccount-based authorization
				t.Errorf("%s expected subject type to be 'serviceaccount' but got %s", k, subjectType)
			}
		}
	}
}

func TestAdmitFailure(t *testing.T) {
	// create scc that requires allocation retrieval
	saSCC := saSCC()

	// create scc that has specific requirements that shouldn't match but is permissioned to
	// service accounts to test that even though this has matching priorities (0) and a
	// lower point value score (which will cause it to be sorted in front of scc-sa) it should not
	// validate the requests so we should try scc-sa.
	saExactSCC := saExactSCC()

	lister, indexer := createSCCListerAndIndexer(t, []*securityv1.SecurityContextConstraints{
		saExactSCC,
		saSCC,
	})
	nsLister := createNamespaceLister(t, createNamespaceForTest())

	testAuthorizer := &sccTestAuthorizer{t: t}

	// create the admission plugin
	p := newTestAdmission(lister, nsLister, testAuthorizer)

	// setup test data
	uidNotInRange := goodPod()
	var uid int64 = 1001
	uidNotInRange.Spec.Containers[0].SecurityContext.RunAsUser = &uid

	invalidMCSLabels := goodPod()
	invalidMCSLabels.Spec.Containers[0].SecurityContext.SELinuxOptions = &coreapi.SELinuxOptions{
		Level: "s1:q0,q1",
	}

	disallowedPriv := goodPod()
	var priv bool = true
	disallowedPriv.Spec.Containers[0].SecurityContext.Privileged = &priv

	requestsHostNetwork := goodPod()
	requestsHostNetwork.Spec.SecurityContext.HostNetwork = true

	requestsHostPorts := goodPod()
	requestsHostPorts.Spec.Containers[0].Ports = []coreapi.ContainerPort{{HostPort: 1}}

	requestsHostPID := goodPod()
	requestsHostPID.Spec.SecurityContext.HostPID = true

	requestsHostIPC := goodPod()
	requestsHostIPC.Spec.SecurityContext.HostIPC = true

	requestsSupplementalGroup := goodPod()
	requestsSupplementalGroup.Spec.SecurityContext.SupplementalGroups = []int64{1}

	requestsFSGroup := goodPod()
	fsGroup := int64(1)
	requestsFSGroup.Spec.SecurityContext.FSGroup = &fsGroup

	requestsPodLevelMCS := goodPod()
	requestsPodLevelMCS.Spec.SecurityContext.SELinuxOptions = &coreapi.SELinuxOptions{
		User:  "user",
		Type:  "type",
		Role:  "role",
		Level: "level",
	}

	testCases := map[string]struct {
		pod *coreapi.Pod
	}{
		"uidNotInRange": {
			pod: uidNotInRange,
		},
		"invalidMCSLabels": {
			pod: invalidMCSLabels,
		},
		"disallowedPriv": {
			pod: disallowedPriv,
		},
		"requestsHostNetwork": {
			pod: requestsHostNetwork,
		},
		"requestsHostPorts": {
			pod: requestsHostPorts,
		},
		"requestsHostPID": {
			pod: requestsHostPID,
		},
		"requestsHostIPC": {
			pod: requestsHostIPC,
		},
		"requestsSupplementalGroup": {
			pod: requestsSupplementalGroup,
		},
		"requestsFSGroup": {
			pod: requestsFSGroup,
		},
		"requestsPodLevelMCS": {
			pod: requestsPodLevelMCS,
		},
	}

	for i := 0; i < 2; i++ {
		for k, v := range testCases {
			v.pod.Spec.Containers, v.pod.Spec.InitContainers = v.pod.Spec.InitContainers, v.pod.Spec.Containers
			attrs := admission.NewAttributesRecord(v.pod, nil, coreapi.Kind("Pod").WithVersion("version"), v.pod.Namespace, v.pod.Name, coreapi.Resource("pods").WithVersion("version"), "", admission.Create, nil, false, &user.DefaultInfo{})
			err := p.(admission.MutationInterface).Admit(context.TODO(), attrs, nil)

			if err == nil {
				t.Errorf("%s expected errors but received none", k)
			}
		}
	}

	// now add an escalated scc to the group and re-run the cases that expected failure, they should
	// now pass by validating against the escalated scc.
	adminSCC := laxSCC()
	adminSCC.Name = "scc-admin"
	indexer.Add(adminSCC)

	for i := 0; i < 2; i++ {
		for k, v := range testCases {
			v.pod.Spec.Containers, v.pod.Spec.InitContainers = v.pod.Spec.InitContainers, v.pod.Spec.Containers

			// pods that were rejected by strict SCC, should pass with relaxed SCC
			testSCCAdmission(v.pod, p, adminSCC.Name, k, t)
		}
	}
}

func TestCreateProvidersFromConstraints(t *testing.T) {
	namespaceValid := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
			Annotations: map[string]string{
				securityv1.UIDRangeAnnotation:           "1/3",
				securityv1.MCSAnnotation:                "s0:c1,c0",
				securityv1.SupplementalGroupsAnnotation: "1/3",
			},
		},
	}
	namespaceNoUID := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
			Annotations: map[string]string{
				securityv1.MCSAnnotation:                "s0:c1,c0",
				securityv1.SupplementalGroupsAnnotation: "1/3",
			},
		},
	}
	namespaceNoMCS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
			Annotations: map[string]string{
				securityv1.UIDRangeAnnotation:           "1/3",
				securityv1.SupplementalGroupsAnnotation: "1/3",
			},
		},
	}

	namespaceNoSupplementalGroupsFallbackToUID := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
			Annotations: map[string]string{
				securityv1.UIDRangeAnnotation: "1/3",
				securityv1.MCSAnnotation:      "s0:c1,c0",
			},
		},
	}

	namespaceBadSupGroups := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
			Annotations: map[string]string{
				securityv1.UIDRangeAnnotation:           "1/3",
				securityv1.MCSAnnotation:                "s0:c1,c0",
				securityv1.SupplementalGroupsAnnotation: "",
			},
		},
	}

	testCases := map[string]struct {
		// use a generating function so we can test for non-mutation
		scc         func() *securityv1.SecurityContextConstraints
		namespace   *corev1.Namespace
		expectedErr string
	}{
		"valid non-preallocated scc": {
			scc: func() *securityv1.SecurityContextConstraints {
				return &securityv1.SecurityContextConstraints{
					ObjectMeta: metav1.ObjectMeta{
						Name: "valid non-preallocated scc",
					},
					SELinuxContext: securityv1.SELinuxContextStrategyOptions{
						Type: securityv1.SELinuxStrategyRunAsAny,
					},
					RunAsUser: securityv1.RunAsUserStrategyOptions{
						Type: securityv1.RunAsUserStrategyRunAsAny,
					},
					FSGroup: securityv1.FSGroupStrategyOptions{
						Type: securityv1.FSGroupStrategyRunAsAny,
					},
					SupplementalGroups: securityv1.SupplementalGroupsStrategyOptions{
						Type: securityv1.SupplementalGroupsStrategyRunAsAny,
					},
				}
			},
			namespace: namespaceValid,
		},
		"valid pre-allocated scc": {
			scc: func() *securityv1.SecurityContextConstraints {
				return &securityv1.SecurityContextConstraints{
					ObjectMeta: metav1.ObjectMeta{
						Name: "valid pre-allocated scc",
					},
					SELinuxContext: securityv1.SELinuxContextStrategyOptions{
						Type:           securityv1.SELinuxStrategyMustRunAs,
						SELinuxOptions: &corev1.SELinuxOptions{User: "myuser"},
					},
					RunAsUser: securityv1.RunAsUserStrategyOptions{
						Type: securityv1.RunAsUserStrategyMustRunAsRange,
					},
					FSGroup: securityv1.FSGroupStrategyOptions{
						Type: securityv1.FSGroupStrategyMustRunAs,
					},
					SupplementalGroups: securityv1.SupplementalGroupsStrategyOptions{
						Type: securityv1.SupplementalGroupsStrategyMustRunAs,
					},
				}
			},
			namespace: namespaceValid,
		},
		"pre-allocated no uid annotation": {
			scc: func() *securityv1.SecurityContextConstraints {
				return &securityv1.SecurityContextConstraints{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pre-allocated no uid annotation",
					},
					SELinuxContext: securityv1.SELinuxContextStrategyOptions{
						Type: securityv1.SELinuxStrategyMustRunAs,
					},
					RunAsUser: securityv1.RunAsUserStrategyOptions{
						Type: securityv1.RunAsUserStrategyMustRunAsRange,
					},
					FSGroup: securityv1.FSGroupStrategyOptions{
						Type: securityv1.FSGroupStrategyRunAsAny,
					},
					SupplementalGroups: securityv1.SupplementalGroupsStrategyOptions{
						Type: securityv1.SupplementalGroupsStrategyRunAsAny,
					},
				}
			},
			namespace:   namespaceNoUID,
			expectedErr: "unable to find annotation openshift.io/sa.scc.uid-range",
		},
		"pre-allocated no mcs annotation": {
			scc: func() *securityv1.SecurityContextConstraints {
				return &securityv1.SecurityContextConstraints{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pre-allocated no mcs annotation",
					},
					SELinuxContext: securityv1.SELinuxContextStrategyOptions{
						Type: securityv1.SELinuxStrategyMustRunAs,
					},
					RunAsUser: securityv1.RunAsUserStrategyOptions{
						Type: securityv1.RunAsUserStrategyMustRunAsRange,
					},
					FSGroup: securityv1.FSGroupStrategyOptions{
						Type: securityv1.FSGroupStrategyRunAsAny,
					},
					SupplementalGroups: securityv1.SupplementalGroupsStrategyOptions{
						Type: securityv1.SupplementalGroupsStrategyRunAsAny,
					},
				}
			},
			namespace:   namespaceNoMCS,
			expectedErr: "unable to find annotation openshift.io/sa.scc.mcs",
		},
		"pre-allocated group falls back to UID annotation": {
			scc: func() *securityv1.SecurityContextConstraints {
				return &securityv1.SecurityContextConstraints{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pre-allocated no sup group annotation",
					},
					SELinuxContext: securityv1.SELinuxContextStrategyOptions{
						Type: securityv1.SELinuxStrategyRunAsAny,
					},
					RunAsUser: securityv1.RunAsUserStrategyOptions{
						Type: securityv1.RunAsUserStrategyRunAsAny,
					},
					FSGroup: securityv1.FSGroupStrategyOptions{
						Type: securityv1.FSGroupStrategyMustRunAs,
					},
					SupplementalGroups: securityv1.SupplementalGroupsStrategyOptions{
						Type: securityv1.SupplementalGroupsStrategyMustRunAs,
					},
				}
			},
			namespace: namespaceNoSupplementalGroupsFallbackToUID,
		},
		"pre-allocated group bad value fails": {
			scc: func() *securityv1.SecurityContextConstraints {
				return &securityv1.SecurityContextConstraints{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pre-allocated no sup group annotation",
					},
					SELinuxContext: securityv1.SELinuxContextStrategyOptions{
						Type: securityv1.SELinuxStrategyRunAsAny,
					},
					RunAsUser: securityv1.RunAsUserStrategyOptions{
						Type: securityv1.RunAsUserStrategyRunAsAny,
					},
					FSGroup: securityv1.FSGroupStrategyOptions{
						Type: securityv1.FSGroupStrategyMustRunAs,
					},
					SupplementalGroups: securityv1.SupplementalGroupsStrategyOptions{
						Type: securityv1.SupplementalGroupsStrategyMustRunAs,
					},
				}
			},
			namespace:   namespaceBadSupGroups,
			expectedErr: "unable to find pre-allocated group annotation",
		},
		"bad scc strategy options": {
			scc: func() *securityv1.SecurityContextConstraints {
				return &securityv1.SecurityContextConstraints{
					ObjectMeta: metav1.ObjectMeta{
						Name: "bad scc user options",
					},
					SELinuxContext: securityv1.SELinuxContextStrategyOptions{
						Type: securityv1.SELinuxStrategyRunAsAny,
					},
					RunAsUser: securityv1.RunAsUserStrategyOptions{
						Type: securityv1.RunAsUserStrategyMustRunAs,
					},
					FSGroup: securityv1.FSGroupStrategyOptions{
						Type: securityv1.FSGroupStrategyRunAsAny,
					},
					SupplementalGroups: securityv1.SupplementalGroupsStrategyOptions{
						Type: securityv1.SupplementalGroupsStrategyRunAsAny,
					},
				}
			},
			namespace:   namespaceValid,
			expectedErr: "MustRunAs requires a UID",
		},
	}

	for k, v := range testCases {
		t.Run(k, func(t *testing.T) {
			// create the admission handler
			nsLister := createNamespaceLister(t, v.namespace)
			scc := v.scc()

			// create the providers, this method only needs the namespace
			attributes := admission.NewAttributesRecord(nil, nil, coreapi.Kind("Pod").WithVersion("version"), v.namespace.Name, "", coreapi.Resource("pods").WithVersion("version"), "", admission.Create, nil, false, nil)
			// let timeout based failures fail fast
			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
			defer cancel()
			_, errs := sccmatching.CreateProvidersFromConstraints(ctx, attributes.GetNamespace(), []*securityv1.SecurityContextConstraints{scc}, nsLister)

			if !reflect.DeepEqual(scc, v.scc()) {
				diff := diff.Diff(scc, v.scc())
				t.Fatalf("%s createProvidersFromConstraints mutated constraints. diff:\n%s", k, diff)
			}
			if len(v.expectedErr) > 0 && len(errs) != 1 {
				t.Fatalf("%s expected a single error '%s' but received %v", k, v.expectedErr, errs)
			}
			if len(v.expectedErr) == 0 && len(errs) != 0 {
				t.Fatalf("%s did not expect an error but received %v", k, errs)
			}

			// check that we got the error we expected
			if len(v.expectedErr) > 0 {
				if !strings.Contains(errs[0].Error(), v.expectedErr) {
					t.Fatalf("%s expected error '%s' but received %v", k, v.expectedErr, errs[0])
				}
			}
		})
	}
}

func TestMatchingSecurityContextConstraints(t *testing.T) {
	sccs := []*securityv1.SecurityContextConstraints{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "match group",
			},
			Groups: []string{"group"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "match user",
			},
			Users: []string{"user"},
		},
	}

	lister := createSCCLister(t, sccs)

	// single match cases
	testCases := map[string]struct {
		userInfo    user.Info
		authorizer  *sccTestAuthorizer
		namespace   string
		expectedSCC string
	}{
		"find none": {
			userInfo: &user.DefaultInfo{
				Name:   "foo",
				Groups: []string{"bar"},
			},
			authorizer: &sccTestAuthorizer{t: t},
		},
		"find user": {
			userInfo: &user.DefaultInfo{
				Name:   "user",
				Groups: []string{"bar"},
			},
			authorizer:  &sccTestAuthorizer{t: t},
			expectedSCC: "match user",
		},
		"find group": {
			userInfo: &user.DefaultInfo{
				Name:   "foo",
				Groups: []string{"group"},
			},
			authorizer:  &sccTestAuthorizer{t: t},
			expectedSCC: "match group",
		},
		"not find user via authz": {
			userInfo: &user.DefaultInfo{
				Name:   "foo",
				Groups: []string{"bar"},
			},
			authorizer: &sccTestAuthorizer{t: t, user: "not-foo", scc: "match user"},
			namespace:  "fancy",
		},
		"find user via authz cluster wide": {
			userInfo: &user.DefaultInfo{
				Name:   "foo",
				Groups: []string{"bar"},
			},
			authorizer:  &sccTestAuthorizer{t: t, user: "foo", scc: "match user"},
			namespace:   "fancy",
			expectedSCC: "match user",
		},
		"find group via authz in namespace": {
			userInfo: &user.DefaultInfo{
				Name:   "foo",
				Groups: []string{"bar"},
			},
			authorizer:  &sccTestAuthorizer{t: t, user: "foo", namespace: "room", scc: "match group"},
			namespace:   "room",
			expectedSCC: "match group",
		},
	}

	for k, v := range testCases {
		sccMatcher := sccmatching.NewDefaultSCCMatcher(lister, v.authorizer)
		sccs, err := sccMatcher.FindApplicableSCCs(context.TODO(), v.namespace, v.userInfo)
		if err != nil {
			t.Errorf("%s received error %v", k, err)
			continue
		}
		if v.expectedSCC == "" {
			if len(sccs) > 0 {
				t.Errorf("%s expected to match 0 sccs but found %d: %#v", k, len(sccs), sccs)
			}
		}
		if v.expectedSCC != "" {
			if len(sccs) != 1 {
				t.Errorf("%s returned more than one scc, use case can not validate: %#v", k, sccs)
				continue
			}
			if v.expectedSCC != sccs[0].Name {
				t.Errorf("%s expected to match %s but found %s", k, v.expectedSCC, sccs[0].Name)
			}
		}
	}

	// check that we can match many at once
	userInfo := &user.DefaultInfo{
		Name:   "user",
		Groups: []string{"group"},
	}
	testAuthorizer := &sccTestAuthorizer{t: t}
	namespace := "does-not-matter"
	sccMatcher := sccmatching.NewDefaultSCCMatcher(lister, testAuthorizer)
	sccs2, err := sccMatcher.FindApplicableSCCs(context.TODO(), namespace, userInfo)
	if err != nil {
		t.Fatalf("matching many sccs returned error %v", err)
	}
	if len(sccs2) != 2 {
		t.Errorf("matching many sccs expected to match 2 sccs but found %d: %#v", len(sccs), sccs)
	}
}

func TestAdmitWithPrioritizedSCC(t *testing.T) {
	// scc with high priority but very restrictive.
	restricted := restrictiveSCC()
	restrictedPriority := int32(100)
	restricted.Priority = &restrictedPriority

	// sccs with matching priorities but one will have a higher point score (by the run as user strategy)
	uidFive := int64(5)
	matchingPrioritySCCOne := laxSCC()
	matchingPrioritySCCOne.Name = "matchingPrioritySCCOne"
	matchingPrioritySCCOne.RunAsUser = securityv1.RunAsUserStrategyOptions{
		Type: securityv1.RunAsUserStrategyMustRunAs,
		UID:  &uidFive,
	}
	matchingPriority := int32(5)
	matchingPrioritySCCOne.Priority = &matchingPriority

	matchingPrioritySCCOneNoAllowedGroups := matchingPrioritySCCOne.DeepCopy()
	matchingPrioritySCCOneNoAllowedGroups.Name = "matchingPrioritySCCOneNoAllowedGroups"
	matchingPrioritySCCOneNoAllowedGroups.Groups = []string{}

	matchingPrioritySCCTwo := laxSCC()
	matchingPrioritySCCTwo.Name = "matchingPrioritySCCTwo"
	matchingPrioritySCCTwo.RunAsUser = securityv1.RunAsUserStrategyOptions{
		Type:        securityv1.RunAsUserStrategyMustRunAsRange,
		UIDRangeMin: &uidFive,
		UIDRangeMax: &uidFive,
	}
	matchingPrioritySCCTwo.Priority = &matchingPriority

	// sccs with matching priorities and scores so should be matched by sorted name
	uidSix := int64(6)
	matchingPriorityAndScoreSCCOne := laxSCC()
	matchingPriorityAndScoreSCCOne.Name = "matchingPriorityAndScoreSCCOne"
	matchingPriorityAndScoreSCCOne.RunAsUser = securityv1.RunAsUserStrategyOptions{
		Type: securityv1.RunAsUserStrategyMustRunAs,
		UID:  &uidSix,
	}
	matchingPriorityAndScorePriority := int32(1)
	matchingPriorityAndScoreSCCOne.Priority = &matchingPriorityAndScorePriority

	matchingPriorityAndScoreSCCTwo := laxSCC()
	matchingPriorityAndScoreSCCTwo.Name = "matchingPriorityAndScoreSCCTwo"
	matchingPriorityAndScoreSCCTwo.RunAsUser = securityv1.RunAsUserStrategyOptions{
		Type: securityv1.RunAsUserStrategyMustRunAs,
		UID:  &uidSix,
	}
	matchingPriorityAndScoreSCCTwo.Priority = &matchingPriorityAndScorePriority

	// we will expect these to sort as:
	expectedSort := []string{
		"restrictive", "matchingPrioritySCCOne", "matchingPrioritySCCOneNoAllowedGroups", "matchingPrioritySCCTwo",
		"matchingPriorityAndScoreSCCOne", "matchingPriorityAndScoreSCCTwo",
	}
	sccsToSort := []*securityv1.SecurityContextConstraints{
		matchingPriorityAndScoreSCCTwo, matchingPriorityAndScoreSCCOne,
		matchingPrioritySCCTwo, matchingPrioritySCCOne, restricted, matchingPrioritySCCOneNoAllowedGroups,
	}

	sort.Sort(sccsort.ByPriority(sccsToSort))

	for i, scc := range sccsToSort {
		if scc.Name != expectedSort[i] {
			t.Fatalf("unexpected sort found %s at element %d but expected %s", scc.Name, i, expectedSort[i])
		}
	}

	// sorting works as we're expecting
	// now, to test we will craft some requests that are targeted to validate against specific
	// SCCs and ensure that they come out with the right annotation.  This means admission
	// is using the sort strategy we expect.

	sccLister := createSCCLister(t, sccsToSort)
	nsLister := createNamespaceLister(t, createNamespaceForTest())
	testAuthorizer := &sccTestAuthorizer{t: t}

	// create the admission plugin
	plugin := newTestAdmission(sccLister, nsLister, testAuthorizer)

	testSCCAdmission(goodPod(), plugin, restricted.Name, "match the restricted SCC", t)

	matchingPrioritySCCOnePod := goodPod()
	matchingPrioritySCCOnePod.Spec.Containers[0].SecurityContext.RunAsUser = &uidFive
	testSCCAdmission(matchingPrioritySCCOnePod, plugin, matchingPrioritySCCOne.Name, "match matchingPrioritySCCOne by setting RunAsUser to 5", t)

	matchingPriorityAndScoreSCCOnePod := goodPod()
	matchingPriorityAndScoreSCCOnePod.Spec.Containers[0].SecurityContext.RunAsUser = &uidSix
	testSCCAdmission(matchingPriorityAndScoreSCCOnePod, plugin, matchingPriorityAndScoreSCCOne.Name, "match matchingPriorityAndScoreSCCOne by setting RunAsUser to 6", t)

	// test forcing the usage of a lower priority SCC
	matchingPrioritySCCOneForcingOtherPod := matchingPrioritySCCOnePod.DeepCopy()
	matchingPrioritySCCOneForcingOtherPod.Annotations[securityv1.RequiredSCCAnnotation] = matchingPrioritySCCTwo.Name
	testSCCAdmission(matchingPrioritySCCOneForcingOtherPod, plugin, matchingPrioritySCCTwo.Name, "match matchingPrioritySCCTwo by annotation", t)

	// test forcing the usage of a lower priority that doesn't match
	matchingPrioritySCCOneForcingOtherPod = matchingPrioritySCCOnePod.DeepCopy()
	matchingPrioritySCCOneForcingOtherPod.Annotations[securityv1.RequiredSCCAnnotation] = matchingPriorityAndScoreSCCOne.Name
	testSCCAdmissionError(matchingPrioritySCCOneForcingOtherPod, plugin, `pods "Unknown" is forbidden: unable to validate against any security context constraint: provider matchingPriorityAndScoreSCCOne: .containers[0].runAsUser: Invalid value: 5: must be: 6`, t)

	// test forcing the usage of scc that doesn't exist
	matchingPrioritySCCOneForcingOtherPod = matchingPrioritySCCOnePod.DeepCopy()
	matchingPrioritySCCOneForcingOtherPod.Annotations[securityv1.RequiredSCCAnnotation] = "does-not-exist"
	testSCCAdmissionError(matchingPrioritySCCOneForcingOtherPod, plugin, `failed to retrieve the required SCC "does-not-exist": securitycontextconstraints.security.openshift.io "does-not-exist" not found`, t)

	// test forcing the usage of scc that the user cannot use
	matchingPrioritySCCOneForcingOtherPod = matchingPrioritySCCOnePod.DeepCopy()
	matchingPrioritySCCOneForcingOtherPod.Annotations[securityv1.RequiredSCCAnnotation] = matchingPrioritySCCOneNoAllowedGroups.Name
	testSCCAdmissionError(matchingPrioritySCCOneForcingOtherPod, plugin, "provider \"matchingPrioritySCCOneNoAllowedGroups\": Forbidden: not usable by user or serviceaccount", t)
}

func TestAdmitSeccomp(t *testing.T) {
	createPodWithSeccomp := func(podAnnotation, containerAnnotation string) *coreapi.Pod {
		pod := goodPod()
		pod.Annotations = map[string]string{}
		if podAnnotation != "" {
			pod.Annotations[coreapi.SeccompPodAnnotationKey] = podAnnotation
		}
		if containerAnnotation != "" {
			pod.Annotations[coreapi.SeccompContainerAnnotationKeyPrefix+"container"] = containerAnnotation
		}
		pod.Spec.Containers[0].Name = "container"
		return pod
	}

	noSeccompSCC := restrictiveSCC()
	noSeccompSCC.Name = "noseccomp"

	seccompSCC := restrictiveSCC()
	seccompSCC.Name = "seccomp"
	seccompSCC.SeccompProfiles = []string{"foo"}

	wildcardSCC := restrictiveSCC()
	wildcardSCC.Name = "wildcard"
	wildcardSCC.SeccompProfiles = []string{"*"}

	tests := map[string]struct {
		pod                   *coreapi.Pod
		sccs                  []*securityv1.SecurityContextConstraints
		shouldPass            bool
		expectedPodAnnotation string
		expectedSCC           string
	}{
		"no seccomp, no requests": {
			pod:         goodPod(),
			sccs:        []*securityv1.SecurityContextConstraints{noSeccompSCC},
			shouldPass:  true,
			expectedSCC: noSeccompSCC.Name,
		},
		"no seccomp, bad container requests": {
			pod:        createPodWithSeccomp("foo", "bar"),
			sccs:       []*securityv1.SecurityContextConstraints{noSeccompSCC},
			shouldPass: false,
		},
		"seccomp, no requests": {
			pod:                   goodPod(),
			sccs:                  []*securityv1.SecurityContextConstraints{seccompSCC},
			shouldPass:            true,
			expectedPodAnnotation: "foo",
			expectedSCC:           seccompSCC.Name,
		},
		"seccomp, valid pod annotation, no container annotation": {
			pod:                   createPodWithSeccomp("foo", ""),
			sccs:                  []*securityv1.SecurityContextConstraints{seccompSCC},
			shouldPass:            true,
			expectedPodAnnotation: "foo",
			expectedSCC:           seccompSCC.Name,
		},
		"seccomp, no pod annotation, valid container annotation": {
			pod:                   createPodWithSeccomp("", "foo"),
			sccs:                  []*securityv1.SecurityContextConstraints{seccompSCC},
			shouldPass:            true,
			expectedPodAnnotation: "foo",
			expectedSCC:           seccompSCC.Name,
		},
		"seccomp, valid pod annotation, invalid container annotation": {
			pod:        createPodWithSeccomp("foo", "bar"),
			sccs:       []*securityv1.SecurityContextConstraints{seccompSCC},
			shouldPass: false,
		},
		"wild card, no requests": {
			pod:         goodPod(),
			sccs:        []*securityv1.SecurityContextConstraints{wildcardSCC},
			shouldPass:  true,
			expectedSCC: wildcardSCC.Name,
		},
		"wild card, requests": {
			pod:                   createPodWithSeccomp("foo", "bar"),
			sccs:                  []*securityv1.SecurityContextConstraints{wildcardSCC},
			shouldPass:            true,
			expectedPodAnnotation: "foo",
			expectedSCC:           wildcardSCC.Name,
		},
	}

	for k, v := range tests {
		testSCCAdmit(k, v.sccs, v.pod, v.shouldPass, t)

		if v.shouldPass {
			validatedSCC, ok := v.pod.Annotations[securityv1.ValidatedSCCAnnotation]
			if !ok {
				t.Errorf("expected to find the validated annotation on the pod for the scc but found none")
				return
			}
			if validatedSCC != v.expectedSCC {
				t.Errorf("should have validated against %s but found %s", v.expectedSCC, validatedSCC)
			}

			if len(v.expectedPodAnnotation) > 0 {
				annotation, found := v.pod.Annotations[coreapi.SeccompPodAnnotationKey]
				if !found {
					t.Errorf("%s expected to have pod annotation for seccomp but found none", k)
				}
				if found && annotation != v.expectedPodAnnotation {
					t.Errorf("%s expected pod annotation to be %s but found %s", k, v.expectedPodAnnotation, annotation)
				}
			}
		}
	}
}

func TestAdmitPreferNonmutatingWhenPossible(t *testing.T) {
	mutatingSCC := restrictiveSCC()
	mutatingSCC.Name = "mutating-scc"

	nonMutatingSCC := laxSCC()
	nonMutatingSCC.Name = "non-mutating-scc"

	restrictiveNonMutatingSCC := laxSCC()
	restrictiveNonMutatingSCC.Name = "restrictive-non-mutating-scc"
	restrictiveNonMutatingSCC.AllowHostPorts = false

	simplePod := goodPod()
	simplePod.Spec.Containers[0].Name = "simple-pod"
	simplePod.Spec.Containers[0].Image = "test-image:0.1"

	simplePodRequiringNotMutatingSCC := simplePod.DeepCopy()
	simplePodRequiringNotMutatingSCC.Annotations = map[string]string{
		securityv1.RequiredSCCAnnotation: nonMutatingSCC.Name,
	}

	modifiedPod := simplePod.DeepCopy()
	modifiedPod.Spec.Containers[0].Image = "test-image:0.2"

	modifiedPodRequiringMutatingSCC := modifiedPod.DeepCopy()
	modifiedPodRequiringMutatingSCC.Annotations = map[string]string{
		securityv1.RequiredSCCAnnotation: mutatingSCC.Name,
	}

	modifiedByEphemeralContainers := simplePod.DeepCopy()
	modifiedByEphemeralContainers.Spec.EphemeralContainers = []coreapi.EphemeralContainer{
		{
			EphemeralContainerCommon: coreapi.EphemeralContainerCommon{
				SecurityContext: &coreapi.SecurityContext{},
			},
		},
	}

	modifiedByHostPortEphemeralContainers := modifiedByEphemeralContainers.DeepCopy()
	modifiedByHostPortEphemeralContainers.Spec.EphemeralContainers[0].Ports = []coreapi.ContainerPort{
		{
			HostPort: 80,
		},
	}

	mutatingProvider, err := sccmatching.NewSimpleProvider(mutatingSCC)
	if err != nil {
		t.Fatalf("failed to create a mutating provider: %v", err)
	}
	mutatedPod := simplePod.DeepCopy()
	mutatedPod.Spec.SecurityContext, mutatedPod.Annotations, err = mutatingProvider.CreatePodSecurityContext(mutatedPod)
	if err != nil {
		t.Fatalf("failed to mutate the pod: %v", err)
	}

	mutatedPod.Spec.Containers[0].SecurityContext, err = mutatingProvider.CreateContainerSecurityContext(
		mutatedPod,
		&mutatedPod.Spec.Containers[0],
	)
	if err != nil {
		t.Fatalf("failed to mutate the container: %v", err)
	}

	mutatedPodModifiedByEpehemeralContainers := mutatedPod.DeepCopy()
	mutatedPodModifiedByEpehemeralContainers.Spec.EphemeralContainers = []coreapi.EphemeralContainer{
		{
			EphemeralContainerCommon: coreapi.EphemeralContainerCommon{
				SecurityContext: &coreapi.SecurityContext{},
			},
		},
	}

	tests := map[string]struct {
		oldPod      *coreapi.Pod
		newPod      *coreapi.Pod
		operation   admission.Operation
		subresource string
		sccs        []*securityv1.SecurityContextConstraints
		shouldPass  bool
		expectedSCC string
	}{
		"creation: most restrictive SCC (even if it mutates) should be used": {
			newPod:      simplePod.DeepCopy(),
			operation:   admission.Create,
			sccs:        []*securityv1.SecurityContextConstraints{restrictiveNonMutatingSCC, mutatingSCC, nonMutatingSCC},
			shouldPass:  true,
			expectedSCC: mutatingSCC.Name,
		},
		"updating: most restrictive non-mutating SCC should be used": {
			oldPod:      simplePod.DeepCopy(),
			newPod:      modifiedPod.DeepCopy(),
			operation:   admission.Update,
			sccs:        []*securityv1.SecurityContextConstraints{mutatingSCC, nonMutatingSCC, restrictiveNonMutatingSCC},
			shouldPass:  true,
			expectedSCC: restrictiveNonMutatingSCC.Name,
		},
		"updating: a pod should be rejected when there are only mutating SCCs": {
			oldPod:     simplePod.DeepCopy(),
			newPod:     modifiedPod.DeepCopy(),
			operation:  admission.Update,
			sccs:       []*securityv1.SecurityContextConstraints{mutatingSCC},
			shouldPass: false,
		},
		"updating ephemeral containers: the first non-mutating SCC should be used": {
			oldPod:      simplePod.DeepCopy(),
			newPod:      modifiedByEphemeralContainers.DeepCopy(),
			operation:   admission.Update,
			subresource: "ephemeralcontainers",
			sccs:        []*securityv1.SecurityContextConstraints{mutatingSCC, nonMutatingSCC},
			shouldPass:  true,
			expectedSCC: nonMutatingSCC.Name,
		},
		"updating ephemeral containers: only an SCC that also mutates the rest of the pod is available": {
			oldPod:      simplePod.DeepCopy(),
			newPod:      modifiedByEphemeralContainers.DeepCopy(),
			operation:   admission.Update,
			subresource: "ephemeralcontainers",
			sccs:        []*securityv1.SecurityContextConstraints{mutatingSCC},
			shouldPass:  false,
		},
		"updating ephemeral containers: only an SCC that would mutate the new container is available": {
			oldPod:      mutatedPod.DeepCopy(),
			newPod:      mutatedPodModifiedByEpehemeralContainers.DeepCopy(),
			operation:   admission.Update,
			subresource: "ephemeralcontainers",
			sccs:        []*securityv1.SecurityContextConstraints{mutatingSCC},
			shouldPass:  true,
			expectedSCC: mutatingSCC.Name,
		},
		"updating ephemeral containers without subresource: only an SCC that would mutate the new container is available": {
			oldPod:     mutatedPod.DeepCopy(),
			newPod:     mutatedPodModifiedByEpehemeralContainers.DeepCopy(),
			operation:  admission.Update,
			sccs:       []*securityv1.SecurityContextConstraints{mutatingSCC},
			shouldPass: false,
		},
		"updating ephemeral containers: only a non-mutating non-matching SCC": {
			oldPod:      simplePod.DeepCopy(),
			newPod:      modifiedByHostPortEphemeralContainers.DeepCopy(),
			operation:   admission.Update,
			subresource: "ephemeralcontainers",
			sccs:        []*securityv1.SecurityContextConstraints{restrictiveNonMutatingSCC},
			shouldPass:  false,
		},
		"updating: changing required SCC must fail": {
			oldPod:     simplePodRequiringNotMutatingSCC.DeepCopy(),
			newPod:     modifiedPodRequiringMutatingSCC.DeepCopy(),
			operation:  admission.Update,
			sccs:       []*securityv1.SecurityContextConstraints{mutatingSCC, nonMutatingSCC},
			shouldPass: false,
		},
		"updating: adding required SCC must fail": {
			oldPod:     simplePod.DeepCopy(),
			newPod:     modifiedPodRequiringMutatingSCC.DeepCopy(),
			operation:  admission.Update,
			sccs:       []*securityv1.SecurityContextConstraints{mutatingSCC, nonMutatingSCC},
			shouldPass: false,
		},
	}

	for testCaseName, testCase := range tests {
		// We can't use testSCCAdmission() here because it doesn't support Update operation.
		// We can't use testSCCAdmit() here because it doesn't support Update operation and doesn't check for the SCC annotation.

		lister := createSCCLister(t, testCase.sccs)
		nsLister := createNamespaceLister(t, createNamespaceForTest())
		testAuthorizer := &sccTestAuthorizer{t: t}
		plugin := newTestAdmission(lister, nsLister, testAuthorizer)

		attrs := admission.NewAttributesRecord(testCase.newPod, testCase.oldPod, coreapi.Kind("Pod").WithVersion("version"), testCase.newPod.Namespace, testCase.newPod.Name, coreapi.Resource("pods").WithVersion("version"), testCase.subresource, testCase.operation, nil, false, &user.DefaultInfo{})
		err := plugin.(admission.MutationInterface).Admit(context.TODO(), attrs, nil)

		if testCase.shouldPass {
			if err != nil {
				t.Errorf("%s expected no errors but received %v", testCaseName, err)
			} else {
				validatedSCC, ok := testCase.newPod.Annotations[securityv1.ValidatedSCCAnnotation]
				if !ok {
					t.Errorf("expected %q to find the validated annotation on the pod for the scc but found none", testCaseName)
				} else if validatedSCC != testCase.expectedSCC {
					t.Errorf("%q should have validated against %q but found %q", testCaseName, testCase.expectedSCC, validatedSCC)
				}
			}
		} else {
			if err == nil {
				t.Errorf("%s expected errors but received none", testCaseName)
			}
		}
	}
}

func TestRestrictedMessage(t *testing.T) {
	usableRestricted := restrictiveSCC()
	usableRestricted.Name = "restricted"

	// restricted must match, but we don't have permissions to use it
	unusableRestricted := restrictiveSCC()
	unusableRestricted.Name = "restricted"
	unusableRestricted.Groups = []string{}

	// restrictedv2 must not match, but we do have permission to use it
	restrictv2 := restrictiveSCC()
	restrictv2.AllowPrivilegeEscalation = ptr.To(false)
	restrictv2.Name = "restricted-v2"

	restrictedv2Pod := goodPod()
	restrictedv2Pod.Spec.Containers[0].Name = "simple-pod"
	restrictedv2Pod.Spec.Containers[0].Image = "test-image:0.1"

	simplePod := goodPod()
	simplePod.Spec.Containers[0].Name = "simple-pod"
	simplePod.Spec.Containers[0].Image = "test-image:0.1"
	simplePod.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = ptr.To(true)

	privilegedPod := goodPod()
	privilegedPod.Spec.Containers[0].Name = "simple-pod"
	privilegedPod.Spec.Containers[0].Image = "test-image:0.1"
	privilegedPod.Spec.Containers[0].SecurityContext.Privileged = ptr.To(true)

	tryRestrictedMessage := "fails to validate against the `restricted-v2` security context constraint, but would validate successfully against the `restricted`"

	tests := map[string]struct {
		oldPod            *coreapi.Pod
		newPod            *coreapi.Pod
		operation         admission.Operation
		sccs              []*securityv1.SecurityContextConstraints
		expectedMessage   string
		notNotHaveMessage string
	}{
		"message about restricted matching": {
			newPod:          simplePod.DeepCopy(),
			operation:       admission.Create,
			sccs:            []*securityv1.SecurityContextConstraints{unusableRestricted, restrictv2},
			expectedMessage: tryRestrictedMessage,
		},
		"no message about restricted if it doesn't match": {
			newPod:            privilegedPod.DeepCopy(),
			operation:         admission.Create,
			sccs:              []*securityv1.SecurityContextConstraints{usableRestricted, restrictv2},
			expectedMessage:   "unable to validate against any security context constraint",
			notNotHaveMessage: tryRestrictedMessage,
		},
		"no message about restricted if restrictedv2 works": {
			newPod:          restrictedv2Pod.DeepCopy(),
			operation:       admission.Create,
			sccs:            []*securityv1.SecurityContextConstraints{usableRestricted, restrictv2},
			expectedMessage: "",
		},
	}

	for testCaseName, testCase := range tests {
		t.Run(testCaseName, func(t *testing.T) {
			lister := createSCCLister(t, testCase.sccs)
			nsLister := createNamespaceLister(t, createNamespaceForTest())
			testAuthorizer := &sccTestAuthorizer{t: t}
			plugin := newTestAdmission(lister, nsLister, testAuthorizer)

			attrs := admission.NewAttributesRecord(
				testCase.newPod,
				testCase.oldPod,
				coreapi.Kind("Pod").WithVersion("version"),
				testCase.newPod.Namespace,
				testCase.newPod.Name,
				coreapi.Resource("pods").WithVersion("version"),
				"",
				testCase.operation,
				nil,
				false,
				&user.DefaultInfo{},
			)
			err := plugin.(admission.MutationInterface).Admit(context.TODO(), attrs, nil)

			if len(testCase.expectedMessage) == 0 && err != nil {
				t.Fatal(err.Error())
			}
			if len(testCase.expectedMessage) == 0 && err == nil {
				return // we pass
			}
			if err == nil {
				t.Fatalf("expected errors but received none")
			}

			if !strings.Contains(err.Error(), testCase.expectedMessage) {
				t.Errorf("cannot find %q in: %v", testCase.expectedMessage, err.Error())
			}
			if len(testCase.notNotHaveMessage) > 0 && strings.Contains(err.Error(), testCase.notNotHaveMessage) {
				t.Errorf("found %q in: %v", testCase.notNotHaveMessage, err.Error())
			}
		})
	}
}

func TestAdmitValidatedSCCSubjectType(t *testing.T) {
	// Create SCCs
	userSCC := laxSCC()
	userSCC.Name = "user-scc"
	userSCC.Users = []string{"test-user"}
	userSCC.Groups = []string{}

	saSCC := laxSCC()
	saSCC.Name = "sa-scc"
	saSCC.Users = []string{}
	saSCC.Groups = []string{}

	// Setup lister for admission controller
	nsLister := createNamespaceLister(t, createNamespaceForTest())
	sccLister := createSCCLister(t, []*securityv1.SecurityContextConstraints{
		userSCC,
		saSCC,
	})

	tests := map[string]struct {
		pod             *coreapi.Pod
		userInfo        user.Info
		authorizer      *sccTestAuthorizer
		expectedSCC     string
		expectedSubject string
	}{
		"user authorization": {
			pod: goodPod(),
			userInfo: &user.DefaultInfo{
				Name: "test-user",
			},
			authorizer: &sccTestAuthorizer{
				t:    t,
				user: "test-user",
				scc:  "user-scc",
			},
			expectedSCC:     "user-scc",
			expectedSubject: "user",
		},
		"serviceaccount authorization": {
			pod: goodPod(),
			userInfo: &user.DefaultInfo{
				Name: "not-in-scc",
			},
			authorizer: &sccTestAuthorizer{
				t:         t,
				user:      "system:serviceaccount:default:default",
				namespace: "default",
				scc:       "sa-scc",
			},
			expectedSCC:     "sa-scc",
			expectedSubject: "serviceaccount",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Create the admission controller
			c := newTestAdmission(sccLister, nsLister, test.authorizer)

			// Create the attributes for the admission request to create a Pod
			createPodAttrs := admission.NewAttributesRecord(
				test.pod, nil,
				coreapi.Kind("Pod").WithVersion("version"),
				test.pod.Namespace, test.pod.Name,
				coreapi.Resource("pods").WithVersion("version"), "",
				admission.Create, nil,
				false,
				test.userInfo,
			)

			// admission.MutationInterface -> mutating admission plugin
			err := c.(admission.MutationInterface).Admit(context.TODO(), createPodAttrs, nil)
			if err != nil {
				t.Errorf("Expected no admission errors but received: %v", err)
				return
			}

			// Verify the validated annotation is set correctly
			validatedSCC, ok := test.pod.Annotations[securityv1.ValidatedSCCAnnotation]
			if !ok {
				t.Errorf("Expected to find the validated SCC annotation but found none")
				return
			}
			if validatedSCC != test.expectedSCC {
				t.Errorf("Expected validatedSCC to be %s but got %s", test.expectedSCC, validatedSCC)
				return
			}

			// Verify the new subject type annotation exists and has the correct value
			subjectType, ok := test.pod.Annotations["security.openshift.io/validated-scc-subject-type"]
			if !ok {
				t.Errorf("Expected to find the validated-scc-subject-type annotation but found none")
				return
			}
			if subjectType != test.expectedSubject {
				t.Errorf("Expected subject type to be %s but got %s", test.expectedSubject, subjectType)
			}
		})
	}
}

func TestListOrderedSCCs(t *testing.T) {
	sccLow := &securityv1.SecurityContextConstraints{
		ObjectMeta: metav1.ObjectMeta{Name: "low-priority"},
		Priority:   ptr.To[int32](10),
	}

	sccMedium := &securityv1.SecurityContextConstraints{
		ObjectMeta: metav1.ObjectMeta{Name: "medium-priority"},
		Priority:   ptr.To[int32](20),
	}

	sccHigh := &securityv1.SecurityContextConstraints{
		ObjectMeta: metav1.ObjectMeta{Name: "high-priority"},
		Priority:   ptr.To[int32](30),
	}

	sccHighest := &securityv1.SecurityContextConstraints{
		ObjectMeta: metav1.ObjectMeta{Name: "highest-priority"},
		Priority:   ptr.To[int32](40),
	}

	allSCCs := []*securityv1.SecurityContextConstraints{sccLow, sccMedium, sccHigh, sccHighest}

	tests := []struct {
		name                string
		requiredSCCName     string
		validatedSCCHint    string
		specMutationAllowed bool
		mockLister          securityv1listers.SecurityContextConstraintsLister
		expectedSCCs        []*securityv1.SecurityContextConstraints
		expectError         bool
		errorContains       string
	}{
		{
			name:                "list all SCCs and sort by priority",
			requiredSCCName:     "",
			validatedSCCHint:    "",
			specMutationAllowed: true,
			mockLister:          newMockSCCLister(allSCCs, nil),
			expectedSCCs:        []*securityv1.SecurityContextConstraints{sccHighest, sccHigh, sccMedium, sccLow},
			expectError:         false,
		},
		{
			name:                "get specific required SCC",
			requiredSCCName:     "medium-priority",
			validatedSCCHint:    "",
			specMutationAllowed: true,
			mockLister:          newMockSCCLister(allSCCs, nil),
			expectedSCCs:        []*securityv1.SecurityContextConstraints{sccMedium},
			expectError:         false,
		},
		{
			name:                "error when required SCC not found",
			requiredSCCName:     "non-existent",
			validatedSCCHint:    "",
			specMutationAllowed: true,
			mockLister:          newMockSCCLister(allSCCs, nil),
			expectedSCCs:        nil,
			expectError:         true,
			errorContains:       "failed to retrieve the required SCC",
		},
		{
			name:                "error when no SCCs found",
			requiredSCCName:     "",
			validatedSCCHint:    "",
			specMutationAllowed: true,
			mockLister:          newMockSCCLister([]*securityv1.SecurityContextConstraints{}, nil),
			expectedSCCs:        nil,
			expectError:         true,
			errorContains:       "no SecurityContextConstraints found in cluster",
		},
		{
			name:                "prioritize validatedSCCHint when specMutationAllowed is false",
			requiredSCCName:     "",
			validatedSCCHint:    "low-priority",
			specMutationAllowed: false,
			mockLister:          newMockSCCLister(allSCCs, nil),
			// low-priority should come first despite having lowest priority
			expectedSCCs: []*securityv1.SecurityContextConstraints{sccLow, sccHighest, sccHigh, sccMedium},
			expectError:  false,
		},
		{
			name:                "validatedSCCHint ignored when specMutationAllowed is true",
			requiredSCCName:     "",
			validatedSCCHint:    "low-priority",
			specMutationAllowed: true,
			mockLister:          newMockSCCLister(allSCCs, nil),
			// Normal priority order when specMutationAllowed is true
			expectedSCCs: []*securityv1.SecurityContextConstraints{sccHighest, sccHigh, sccMedium, sccLow},
			expectError:  false,
		},
		{
			name:                "error from lister.List",
			requiredSCCName:     "",
			validatedSCCHint:    "",
			specMutationAllowed: true,
			mockLister:          newMockSCCLister(nil, fmt.Errorf("lister error")),
			expectedSCCs:        nil,
			expectError:         true,
			errorContains:       "lister error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &constraint{sccLister: tc.mockLister}

			result, err := c.listSortedSCCs(tc.requiredSCCName, tc.validatedSCCHint, tc.specMutationAllowed)

			// Check error expectations
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				} else if tc.errorContains != "" && !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("Expected error containing %q but got %q", tc.errorContains, err.Error())
				}
				return
			}

			// No error expected but got one
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Check result expectations
			if !reflect.DeepEqual(result, tc.expectedSCCs) {
				t.Errorf("Expected SCCs order: %v, got: %v", getSCCNames(tc.expectedSCCs), getSCCNames(result))
			}
		})
	}
}

// Helper to compare SCC lists in error messages
func getSCCNames(sccs []*securityv1.SecurityContextConstraints) []string {
	names := make([]string, len(sccs))
	for i, scc := range sccs {
		names[i] = scc.Name
	}
	return names
}

// Mock SCC lister for testing
type mockSCCLister struct {
	sccs []*securityv1.SecurityContextConstraints
	err  error
}

func newMockSCCLister(sccs []*securityv1.SecurityContextConstraints, err error) securityv1listers.SecurityContextConstraintsLister {
	return &mockSCCLister{sccs: sccs, err: err}
}

func (m *mockSCCLister) List(selector labels.Selector) ([]*securityv1.SecurityContextConstraints, error) {
	if m.err != nil {
		return nil, m.err
	}

	return m.sccs, nil
}

func (m *mockSCCLister) Get(name string) (*securityv1.SecurityContextConstraints, error) {
	if m.err != nil {
		return nil, m.err
	}

	for _, scc := range m.sccs {
		if scc.Name == name {
			return scc, nil
		}
	}

	return nil, fmt.Errorf("%s not found", name)
}

// testSCCAdmission is a helper to admit the pod and ensure it was validated against the expected
// SCC. Returns true when errors have been encountered.
func testSCCAdmission(pod *coreapi.Pod, plugin admission.Interface, expectedSCC, testName string, t *testing.T) bool {
	t.Helper()
	attrs := admission.NewAttributesRecord(pod, nil, coreapi.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, coreapi.Resource("pods").WithVersion("version"), "", admission.Create, nil, false, &user.DefaultInfo{})
	err := plugin.(admission.MutationInterface).Admit(context.TODO(), attrs, nil)
	if err != nil {
		t.Errorf("%s error admitting pod: %v", testName, err)
		return true
	}

	validatedSCC, ok := pod.Annotations[securityv1.ValidatedSCCAnnotation]
	if !ok {
		t.Errorf("expected %q to find the validated annotation on the pod for the scc but found none", testName)
		return true
	}
	if validatedSCC != expectedSCC {
		t.Errorf("%q should have validated against %s but found %s", testName, expectedSCC, validatedSCC)
		return true
	}
	return false
}

func testSCCAdmissionError(pod *coreapi.Pod, plugin admission.Interface, expectedError string, t *testing.T) {
	t.Helper()
	attrs := admission.NewAttributesRecord(pod, nil, coreapi.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, coreapi.Resource("pods").WithVersion("version"), "", admission.Create, nil, false, &user.DefaultInfo{})
	err := plugin.(admission.MutationInterface).Admit(context.TODO(), attrs, nil)
	if err == nil {
		t.Errorf("missing any error")
		return
	}
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("missing expected error %q in: %v", expectedError, err.Error())
		return
	}
}

func laxSCC() *securityv1.SecurityContextConstraints {
	return &securityv1.SecurityContextConstraints{
		ObjectMeta: metav1.ObjectMeta{
			Name: "lax",
		},
		AllowPrivilegedContainer: true,
		AllowHostNetwork:         true,
		AllowHostPorts:           true,
		AllowHostPID:             true,
		AllowHostIPC:             true,
		RunAsUser: securityv1.RunAsUserStrategyOptions{
			Type: securityv1.RunAsUserStrategyRunAsAny,
		},
		SELinuxContext: securityv1.SELinuxContextStrategyOptions{
			Type: securityv1.SELinuxStrategyRunAsAny,
		},
		FSGroup: securityv1.FSGroupStrategyOptions{
			Type: securityv1.FSGroupStrategyRunAsAny,
		},
		SupplementalGroups: securityv1.SupplementalGroupsStrategyOptions{
			Type: securityv1.SupplementalGroupsStrategyRunAsAny,
		},
		Groups: []string{"system:serviceaccounts"},
	}
}

func restrictiveSCC() *securityv1.SecurityContextConstraints {
	var exactUID int64 = 999
	return &securityv1.SecurityContextConstraints{
		ObjectMeta: metav1.ObjectMeta{
			Name: "restrictive",
		},
		RunAsUser: securityv1.RunAsUserStrategyOptions{
			Type: securityv1.RunAsUserStrategyMustRunAs,
			UID:  &exactUID,
		},
		SELinuxContext: securityv1.SELinuxContextStrategyOptions{
			Type: securityv1.SELinuxStrategyMustRunAs,
			SELinuxOptions: &corev1.SELinuxOptions{
				Level: "s9:z0,z1",
			},
		},
		FSGroup: securityv1.FSGroupStrategyOptions{
			Type: securityv1.FSGroupStrategyMustRunAs,
			Ranges: []securityv1.IDRange{
				{Min: 999, Max: 999},
			},
		},
		SupplementalGroups: securityv1.SupplementalGroupsStrategyOptions{
			Type: securityv1.SupplementalGroupsStrategyMustRunAs,
			Ranges: []securityv1.IDRange{
				{Min: 999, Max: 999},
			},
		},
		Groups: []string{"system:serviceaccounts"},
	}
}

// this method does not create functional SCCs, it only creates entries with the requirednames
func requiredSCCForNames() []*securityv1.SecurityContextConstraints {
	ret := []*securityv1.SecurityContextConstraints{}
	for _, name := range standardSCCNames.List() {
		ret = append(ret, &securityv1.SecurityContextConstraints{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			SELinuxContext: securityv1.SELinuxContextStrategyOptions{
				Type: securityv1.SELinuxStrategyRunAsAny,
			},
			RunAsUser: securityv1.RunAsUserStrategyOptions{
				Type: securityv1.RunAsUserStrategyRunAsAny,
			},
			FSGroup: securityv1.FSGroupStrategyOptions{
				Type: securityv1.FSGroupStrategyRunAsAny,
			},
			SupplementalGroups: securityv1.SupplementalGroupsStrategyOptions{
				Type: securityv1.SupplementalGroupsStrategyRunAsAny,
			},
		})
	}
	return ret
}

func saSCC() *securityv1.SecurityContextConstraints {
	return &securityv1.SecurityContextConstraints{
		ObjectMeta: metav1.ObjectMeta{
			Name: "scc-sa",
		},
		RunAsUser: securityv1.RunAsUserStrategyOptions{
			Type: securityv1.RunAsUserStrategyMustRunAsRange,
		},
		SELinuxContext: securityv1.SELinuxContextStrategyOptions{
			Type: securityv1.SELinuxStrategyMustRunAs,
		},
		FSGroup: securityv1.FSGroupStrategyOptions{
			Type: securityv1.FSGroupStrategyMustRunAs,
		},
		SupplementalGroups: securityv1.SupplementalGroupsStrategyOptions{
			Type: securityv1.SupplementalGroupsStrategyMustRunAs,
		},
		Groups: []string{"system:serviceaccounts"},
	}
}

func saExactSCC() *securityv1.SecurityContextConstraints {
	var exactUID int64 = 999
	return &securityv1.SecurityContextConstraints{
		ObjectMeta: metav1.ObjectMeta{
			Name: "scc-sa-exact",
		},
		RunAsUser: securityv1.RunAsUserStrategyOptions{
			Type: securityv1.RunAsUserStrategyMustRunAs,
			UID:  &exactUID,
		},
		SELinuxContext: securityv1.SELinuxContextStrategyOptions{
			Type: securityv1.SELinuxStrategyMustRunAs,
			SELinuxOptions: &corev1.SELinuxOptions{
				Level: "s9:z0,z1",
			},
		},
		FSGroup: securityv1.FSGroupStrategyOptions{
			Type: securityv1.FSGroupStrategyMustRunAs,
			Ranges: []securityv1.IDRange{
				{Min: 999, Max: 999},
			},
		},
		SupplementalGroups: securityv1.SupplementalGroupsStrategyOptions{
			Type: securityv1.SupplementalGroupsStrategyMustRunAs,
			Ranges: []securityv1.IDRange{
				{Min: 999, Max: 999},
			},
		},
		Groups: []string{"system:serviceaccounts"},
	}
}

// goodPod is empty and should not be used directly for testing since we're providing
// two different SCCs.  Since no values are specified it would be allowed to match any
// SCC when defaults are filled in.
func goodPod() *coreapi.Pod {
	return &coreapi.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
		},
		Spec: coreapi.PodSpec{
			ServiceAccountName: "default",
			SecurityContext:    &coreapi.PodSecurityContext{},
			Containers: []coreapi.Container{
				{
					SecurityContext: &coreapi.SecurityContext{},
				},
			},
		},
	}
}

// windowsPod returns windows pod without any SCCs which are specific to Linux. The admission of Windows pod
// should be safely ignored.
func windowsPod() *coreapi.Pod {
	return &coreapi.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
		},
		Spec: coreapi.PodSpec{
			OS: &coreapi.PodOS{
				Name: coreapi.Windows,
			},
			ServiceAccountName: "default",
		},
	}
}

// linuxPod returns linux pod without any SCCs but with OS field explicitly set
func linuxPod() *coreapi.Pod {
	return &coreapi.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
		},
		Spec: coreapi.PodSpec{
			OS: &coreapi.PodOS{
				Name: coreapi.Linux,
			},
			ServiceAccountName: "default",
		},
	}
}

func containerSC(seLinuxLevel *string, uid int64, runAsNonRoot *bool) *coreapi.SecurityContext {
	sc := &coreapi.SecurityContext{
		RunAsUser:    &uid,
		RunAsNonRoot: runAsNonRoot,
	}
	if seLinuxLevel != nil {
		sc.SELinuxOptions = &coreapi.SELinuxOptions{
			Level: *seLinuxLevel,
		}
	}
	return sc
}

func podSC(seLinuxLevel string, fsGroup, supGroup int64) *coreapi.PodSecurityContext {
	return &coreapi.PodSecurityContext{
		SELinuxOptions: &coreapi.SELinuxOptions{
			Level: seLinuxLevel,
		},
		SupplementalGroups: []int64{supGroup},
		FSGroup:            &fsGroup,
	}
}

func setupClientSet(namespace *corev1.Namespace) *fake.Clientset {
	// create the annotated namespace and add it to the fake client
	serviceAccount := createSAForTest()
	serviceAccount.Namespace = namespace.Name

	return fake.NewSimpleClientset(serviceAccount)
}

func createSCCListerAndIndexer(t *testing.T, sccs []*securityv1.SecurityContextConstraints) (securityv1listers.SecurityContextConstraintsLister, cache.Indexer) {
	t.Helper()

	// add the required SCC so admission runs
	sccsForLister := []*securityv1.SecurityContextConstraints{}
	sccsForLister = append(sccsForLister, sccs...)
	requiredSCCs := requiredSCCForNames()
	for i := range requiredSCCs {
		requiredSCC := requiredSCCs[i]
		found := false
		for _, curr := range sccsForLister {
			if curr.Name == requiredSCC.Name {
				found = true
				break
			}
		}
		if !found {
			sccsForLister = append(sccsForLister, requiredSCC)
		}
	}

	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	lister := securityv1listers.NewSecurityContextConstraintsLister(indexer)
	for _, scc := range sccsForLister {
		if err := indexer.Add(scc); err != nil {
			t.Fatalf("error adding SCC to store: %v", err)
		}
	}
	return lister, indexer
}

func createSCCLister(t *testing.T, sccs []*securityv1.SecurityContextConstraints) securityv1listers.SecurityContextConstraintsLister {
	t.Helper()

	lister, _ := createSCCListerAndIndexer(t, sccs)
	return lister
}

func createNamespaceListerAndIndexer(t *testing.T, namespaces ...*corev1.Namespace) (corev1listers.NamespaceLister, cache.Indexer) {
	t.Helper()

	// add the required SCC so admission runs
	nsForLister := []*corev1.Namespace{}
	nsForLister = append(nsForLister, namespaces...)

	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	lister := corev1listers.NewNamespaceLister(indexer)
	for _, namespace := range nsForLister {
		if err := indexer.Add(namespace); err != nil {
			t.Fatalf("error adding namespace to store: %v", err)
		}
	}
	return lister, indexer
}

func createNamespaceLister(t *testing.T, namespaces ...*corev1.Namespace) corev1listers.NamespaceLister {
	t.Helper()

	lister, _ := createNamespaceListerAndIndexer(t, namespaces...)
	return lister
}

type sccTestAuthorizer struct {
	t *testing.T

	// this user, in this namespace, can use this SCC
	user      string
	namespace string
	scc       string
}

func (s *sccTestAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
	s.t.Helper()
	if !isValidSCCAttributes(a) {
		s.t.Errorf("invalid attributes seen: %#v", a)
		return authorizer.DecisionDeny, "", nil
	}

	allowedNamespace := len(s.namespace) == 0 || s.namespace == a.GetNamespace()
	if s.user == a.GetUser().GetName() && allowedNamespace && s.scc == a.GetName() {
		return authorizer.DecisionAllow, "", nil
	}

	return authorizer.DecisionNoOpinion, "", nil
}

func isValidSCCAttributes(a authorizer.Attributes) bool {
	return a.GetVerb() == "use" &&
		a.GetAPIGroup() == "security.openshift.io" &&
		a.GetResource() == "securitycontextconstraints" &&
		a.IsResourceRequest()
}
