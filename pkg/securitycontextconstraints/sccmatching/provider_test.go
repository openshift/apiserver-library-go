package sccmatching

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apimachinery/pkg/util/validation/field"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/utils/pointer"

	securityv1 "github.com/openshift/api/security/v1"
	sccutil "github.com/openshift/apiserver-library-go/pkg/securitycontextconstraints/util"
)

func TestCreatePodSecurityContextNonmutating(t *testing.T) {
	// Create a pod with a security context that needs filling in
	createPod := func() *api.Pod {
		return &api.Pod{
			Spec: api.PodSpec{
				SecurityContext: &api.PodSecurityContext{},
			},
		}
	}

	// Create an SCC with strategies that will populate a blank psc
	createSCC := func() *securityv1.SecurityContextConstraints {
		return &securityv1.SecurityContextConstraints{
			ObjectMeta: metav1.ObjectMeta{
				Name: "scc-sa",
			},
			SeccompProfiles: []string{"foo"},
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
			UserNamespaceLevel: securityv1.NamespaceLevelAllowHost,
		}
	}

	pod := createPod()
	scc := createSCC()

	provider, err := NewSimpleProvider(scc)
	if err != nil {
		t.Fatalf("unable to create provider %v", err)
	}
	_, _, err = provider.CreatePodSecurityContext(pod)
	if err != nil {
		t.Fatalf("unable to create psc %v", err)
	}

	// Creating the provider or the security context should not have mutated the scc or pod
	// since all the strategies were permissive
	if !reflect.DeepEqual(createPod(), pod) {
		diff := diff.Diff(createPod(), pod)
		t.Errorf("pod was mutated by CreatePodSecurityContext. diff:\n%s", diff)
	}
	if !reflect.DeepEqual(createSCC(), scc) {
		t.Error("scc was mutated by CreatePodSecurityContext")
	}
}

func TestCreateContainerSecurityContextNonmutating(t *testing.T) {
	// Create a pod with a security context that needs filling in
	createPod := func() *api.Pod {
		return &api.Pod{
			Spec: api.PodSpec{
				Containers: []api.Container{{
					SecurityContext: &api.SecurityContext{},
				}},
			},
		}
	}

	// Create an SCC with strategies that will populate a blank security context
	createSCC := func() *securityv1.SecurityContextConstraints {
		return &securityv1.SecurityContextConstraints{
			ObjectMeta: metav1.ObjectMeta{
				Name: "scc-sa",
			},
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
			UserNamespaceLevel: securityv1.NamespaceLevelAllowHost,
		}
	}

	pod := createPod()
	scc := createSCC()

	provider, err := NewSimpleProvider(scc)
	if err != nil {
		t.Fatalf("unable to create provider %v", err)
	}
	_, err = provider.CreateContainerSecurityContext(pod, &pod.Spec.Containers[0])
	if err != nil {
		t.Fatalf("unable to create container security context %v", err)
	}

	// Creating the provider or the security context should not have mutated the scc or pod
	// since all the strategies were permissive
	if !reflect.DeepEqual(createPod(), pod) {
		diff := diff.Diff(createPod(), pod)
		t.Errorf("pod was mutated by CreateContainerSecurityContext. diff:\n%s", diff)
	}
	if !reflect.DeepEqual(createSCC(), scc) {
		t.Error("scc was mutated by CreateContainerSecurityContext")
	}
}

func TestValidatePodSecurityContextFailures(t *testing.T) {
	failHostNetworkPod := defaultPod()
	failHostNetworkPod.Spec.SecurityContext.HostNetwork = true

	failHostPIDPod := defaultPod()
	failHostPIDPod.Spec.SecurityContext.HostPID = true

	failHostIPCPod := defaultPod()
	failHostIPCPod.Spec.SecurityContext.HostIPC = true

	failSupplementalGroupPod := defaultPod()
	failSupplementalGroupPod.Spec.SecurityContext.SupplementalGroups = []int64{999}
	failSupplementalGroupSCC := defaultSCC()
	failSupplementalGroupSCC.SupplementalGroups = securityv1.SupplementalGroupsStrategyOptions{
		Type: securityv1.SupplementalGroupsStrategyMustRunAs,
		Ranges: []securityv1.IDRange{
			{Min: 1, Max: 1},
		},
	}

	failFSGroupPod := defaultPod()
	fsGroup := int64(999)
	failFSGroupPod.Spec.SecurityContext.FSGroup = &fsGroup
	failFSGroupSCC := defaultSCC()
	failFSGroupSCC.FSGroup = securityv1.FSGroupStrategyOptions{
		Type: securityv1.FSGroupStrategyMustRunAs,
		Ranges: []securityv1.IDRange{
			{Min: 1, Max: 1},
		},
	}

	failNilSELinuxPod := defaultPod()
	failSELinuxSCC := defaultSCC()
	failSELinuxSCC.SELinuxContext.Type = securityv1.SELinuxStrategyMustRunAs
	failSELinuxSCC.SELinuxContext.SELinuxOptions = &corev1.SELinuxOptions{
		Level: "foo",
	}

	failInvalidSELinuxPod := defaultPod()
	failInvalidSELinuxPod.Spec.SecurityContext.SELinuxOptions = &api.SELinuxOptions{
		Level: "bar",
	}

	failNoSeccompAllowed := defaultPod()
	failNoSeccompAllowed.Annotations[api.SeccompPodAnnotationKey] = "bar"

	failInvalidSeccompProfile := defaultPod()
	failInvalidSeccompProfile.Annotations[api.SeccompPodAnnotationKey] = "bar"

	failInvalidSeccompProfileSCC := defaultSCC()
	failInvalidSeccompProfileSCC.SeccompProfiles = []string{"foo"}

	failHostDirPod := defaultPod()
	failHostDirPod.Spec.Volumes = []api.Volume{
		{
			Name: "bad volume",
			VolumeSource: api.VolumeSource{
				HostPath: &api.HostPathVolumeSource{},
			},
		},
	}

	podWithInvalidFlexVolumeDriver := defaultPod()
	podWithInvalidFlexVolumeDriver.Spec.Volumes = []api.Volume{
		{
			Name: "flex-volume",
			VolumeSource: api.VolumeSource{
				FlexVolume: &api.FlexVolumeSource{
					Driver: "example/unknown",
				},
			},
		},
	}

	failSysctlDisallowedSCC := defaultSCC()
	failSysctlDisallowedSCC.ForbiddenSysctls = []string{"kernel.shm_rmid_forced"}

	failNoSafeSysctlAllowedSCC := defaultSCC()
	failNoSafeSysctlAllowedSCC.ForbiddenSysctls = []string{"*"}

	failAllUnsafeSysctlsSCC := defaultSCC()
	failAllUnsafeSysctlsSCC.AllowedUnsafeSysctls = []string{}

	failUserNamespaceSCC := defaultSCC()
	failUserNamespaceSCC.UserNamespaceLevel = securityv1.NamespaceLevelRequirePod

	failSafeSysctlKernelPod := defaultPod()
	failSafeSysctlKernelPod.Spec.SecurityContext.Sysctls = []api.Sysctl{
		{
			Name:  "kernel.shm_rmid_forced",
			Value: "1",
		},
	}

	failUnsafeSysctlPod := defaultPod()
	failUnsafeSysctlPod.Spec.SecurityContext.Sysctls = []api.Sysctl{
		{
			Name:  "kernel.sem",
			Value: "32000",
		},
	}

	failSeccompProfilePod := defaultPod()
	failSeccompProfilePod.Annotations = map[string]string{api.SeccompPodAnnotationKey: "foo"}

	failUserNamespacePod := defaultPod()
	trueVar := true
	failUserNamespacePod.Spec.SecurityContext.HostUsers = &trueVar

	errorCases := map[string]struct {
		pod           *api.Pod
		scc           *securityv1.SecurityContextConstraints
		expectedError string
	}{
		"failHostNetworkSCC": {
			pod:           failHostNetworkPod,
			scc:           defaultSCC(),
			expectedError: "Host network is not allowed to be used",
		},
		"failHostPIDSCC": {
			pod:           failHostPIDPod,
			scc:           defaultSCC(),
			expectedError: "Host PID is not allowed to be used",
		},
		"failHostIPCSCC": {
			pod:           failHostIPCPod,
			scc:           defaultSCC(),
			expectedError: "Host IPC is not allowed to be used",
		},
		"failSupplementalGroupOutOfRange": {
			pod:           failSupplementalGroupPod,
			scc:           failSupplementalGroupSCC,
			expectedError: "999 is not an allowed group",
		},
		"failSupplementalGroupEmpty": {
			pod:           defaultPod(),
			scc:           failSupplementalGroupSCC,
			expectedError: "unable to validate empty groups against required ranges",
		},
		"failFSGroupOutOfRange": {
			pod:           failFSGroupPod,
			scc:           failFSGroupSCC,
			expectedError: "999 is not an allowed group",
		},
		"failFSGroupEmpty": {
			pod:           defaultPod(),
			scc:           failFSGroupSCC,
			expectedError: "unable to validate empty groups against required ranges",
		},
		"failNilSELinux": {
			pod:           failNilSELinuxPod,
			scc:           failSELinuxSCC,
			expectedError: "seLinuxOptions: Required",
		},
		"failInvalidSELinux": {
			pod:           failInvalidSELinuxPod,
			scc:           failSELinuxSCC,
			expectedError: "seLinuxOptions.level: Invalid value",
		},
		"failNoSeccomp": {
			pod:           failNoSeccompAllowed,
			scc:           defaultSCC(),
			expectedError: "seccomp may not be set",
		},
		"failInvalidSeccompPod": {
			pod:           failInvalidSeccompProfile,
			scc:           failInvalidSeccompProfileSCC,
			expectedError: "Forbidden: bar is not an allowed seccomp profile. Valid values are [foo]",
		},
		"failHostDirSCC": {
			pod:           failHostDirPod,
			scc:           defaultSCC(),
			expectedError: "hostPath volumes are not allowed to be used",
		},
		"fail pod with disallowed flexVolume when flex volumes are allowed": {
			pod:           podWithInvalidFlexVolumeDriver,
			scc:           allowFlexVolumesSCC(false, false),
			expectedError: "Flexvolume driver is not allowed to be used",
		},
		"fail pod with disallowed flexVolume when all volumes are allowed": {
			pod:           podWithInvalidFlexVolumeDriver,
			scc:           allowFlexVolumesSCC(false, true),
			expectedError: "Flexvolume driver is not allowed to be used",
		},
		"failSafeSysctlKernelPod with failNoSafeSysctlAllowedSCC": {
			pod:           failSafeSysctlKernelPod,
			scc:           failNoSafeSysctlAllowedSCC,
			expectedError: "sysctl \"kernel.shm_rmid_forced\" is not allowed",
		},
		"failSafeSysctlKernelPod with failSysctlDisallowedSCC": {
			pod:           failSafeSysctlKernelPod,
			scc:           failSysctlDisallowedSCC,
			expectedError: "sysctl \"kernel.shm_rmid_forced\" is not allowed",
		},
		"failUnsafeSysctlPod with failAllUnsafeSysctlsSCC": {
			pod:           failUnsafeSysctlPod,
			scc:           failAllUnsafeSysctlsSCC,
			expectedError: "unsafe sysctl \"kernel.sem\" is not allowed",
		},
		"failInvalidSeccomp": {
			pod:           failSeccompProfilePod,
			scc:           defaultSCC(),
			expectedError: "Forbidden: seccomp may not be set",
		},
		"failRequireHostUser": {
			pod:           failUserNamespacePod,
			scc:           failUserNamespaceSCC,
			expectedError: "spec.hostUsers: Invalid value: true: Host Users must be set to false",
		},
		"failUnsetRequireHostUser": {
			pod:           defaultPod(),
			scc:           failUserNamespaceSCC,
			expectedError: `spec.hostUsers: Invalid value: null: Host Users must be set to false`,
		},
	}
	for k, v := range errorCases {
		provider, err := NewSimpleProvider(v.scc)
		if err != nil {
			t.Fatalf("unable to create provider %v", err)
		}
		errs := provider.ValidatePodSecurityContext(v.pod, field.NewPath("spec"))
		if len(errs) == 0 {
			t.Errorf("%s expected validation failure but did not receive errors", k)
			continue
		}
		if !strings.Contains(errs[0].Error(), v.expectedError) {
			t.Errorf("%s received unexpected error %v", k, errs)
		}
	}
}

func TestValidateContainerSecurityContextFailures(t *testing.T) {
	// fail user strat
	failUserSCC := defaultSCC()
	var uid int64 = 999
	var badUID int64 = 1
	failUserSCC.RunAsUser = securityv1.RunAsUserStrategyOptions{
		Type: securityv1.RunAsUserStrategyMustRunAs,
		UID:  &uid,
	}
	failUserPod := defaultPod()
	failUserPod.Spec.Containers[0].SecurityContext.RunAsUser = &badUID

	// fail selinux strat
	failSELinuxSCC := defaultSCC()
	failSELinuxSCC.SELinuxContext = securityv1.SELinuxContextStrategyOptions{
		Type: securityv1.SELinuxStrategyMustRunAs,
		SELinuxOptions: &corev1.SELinuxOptions{
			Level: "foo",
		},
	}
	failSELinuxPod := defaultPod()
	failSELinuxPod.Spec.Containers[0].SecurityContext.SELinuxOptions = &api.SELinuxOptions{
		Level: "bar",
	}

	failPrivPod := defaultPod()
	var priv bool = true
	failPrivPod.Spec.Containers[0].SecurityContext.Privileged = &priv

	failCapsPod := defaultPod()
	failCapsPod.Spec.Containers[0].SecurityContext.Capabilities = &api.Capabilities{
		Add: []api.Capability{"foo"},
	}

	failHostPortPod := defaultPod()
	failHostPortPod.Spec.Containers[0].Ports = []api.ContainerPort{{HostPort: 1}}

	readOnlyRootFSSCC := defaultSCC()
	readOnlyRootFSSCC.ReadOnlyRootFilesystem = true

	readOnlyRootFSPodFalse := defaultPod()
	readOnlyRootFS := false
	readOnlyRootFSPodFalse.Spec.Containers[0].SecurityContext.ReadOnlyRootFilesystem = &readOnlyRootFS

	failNoSeccompAllowed := defaultPod()
	failNoSeccompAllowed.Annotations[api.SeccompContainerAnnotationKeyPrefix+failNoSeccompAllowed.Spec.Containers[0].Name] = "bar"
	failNoSeccompAllowedSCC := defaultSCC()
	failNoSeccompAllowedSCC.SeccompProfiles = nil

	failInvalidSeccompProfile := defaultPod()
	failInvalidSeccompProfile.Annotations[api.SeccompContainerAnnotationKeyPrefix+failNoSeccompAllowed.Spec.Containers[0].Name] = "bar"
	failInvalidSeccompProfileSCC := defaultSCC()
	failInvalidSeccompProfileSCC.SeccompProfiles = []string{"foo"}

	failSeccompPod := defaultPod()
	failSeccompPod.Annotations = map[string]string{
		api.SeccompContainerAnnotationKeyPrefix + failSeccompPod.Spec.Containers[0].Name: "foo",
	}

	failSeccompPodInheritPodAnnotation := defaultPod()
	failSeccompPodInheritPodAnnotation.Annotations = map[string]string{
		api.SeccompPodAnnotationKey: "foo",
	}

	errorCases := map[string]struct {
		pod           *api.Pod
		scc           *securityv1.SecurityContextConstraints
		expectedError string
	}{
		"failUserSCC": {
			pod:           failUserPod,
			scc:           failUserSCC,
			expectedError: "runAsUser: Invalid value",
		},
		"failSELinuxSCC": {
			pod:           failSELinuxPod,
			scc:           failSELinuxSCC,
			expectedError: "seLinuxOptions.level: Invalid value",
		},
		"failPrivSCC": {
			pod:           failPrivPod,
			scc:           defaultSCC(),
			expectedError: "Privileged containers are not allowed",
		},
		"failCapsSCC": {
			pod:           failCapsPod,
			scc:           defaultSCC(),
			expectedError: "capability may not be added",
		},
		"failHostPortSCC": {
			pod:           failHostPortPod,
			scc:           defaultSCC(),
			expectedError: "Host ports are not allowed to be used",
		},
		"failReadOnlyRootFS - nil": {
			pod:           defaultPod(),
			scc:           readOnlyRootFSSCC,
			expectedError: "ReadOnlyRootFilesystem may not be nil and must be set to true",
		},
		"failReadOnlyRootFS - false": {
			pod:           readOnlyRootFSPodFalse,
			scc:           readOnlyRootFSSCC,
			expectedError: "ReadOnlyRootFilesystem must be set to true",
		},
		"failNoSeccompAllowed": {
			pod:           failNoSeccompAllowed,
			scc:           failNoSeccompAllowedSCC,
			expectedError: "seccomp may not be set",
		},
		"failInvalidSeccompPod": {
			pod:           failInvalidSeccompProfile,
			scc:           failInvalidSeccompProfileSCC,
			expectedError: "Forbidden: bar is not an allowed seccomp profile. Valid values are [foo]",
		},
		"failSeccompContainerAnnotation": {
			pod:           failSeccompPod,
			scc:           defaultSCC(),
			expectedError: "Forbidden: seccomp may not be set",
		},
		"failSeccompContainerPodAnnotation": {
			pod:           failSeccompPodInheritPodAnnotation,
			scc:           defaultSCC(),
			expectedError: "Forbidden: seccomp may not be set",
		},
	}

	for k, v := range errorCases {
		provider, err := NewSimpleProvider(v.scc)
		if err != nil {
			t.Fatalf("unable to create provider %v", err)
		}
		errs := provider.ValidateContainerSecurityContext(v.pod, &v.pod.Spec.Containers[0], field.NewPath(""))
		if len(errs) == 0 {
			t.Errorf("%s expected validation failure but did not receive errors", k)
			continue
		}
		if !strings.Contains(errs[0].Error(), v.expectedError) {
			t.Errorf("%s received unexpected error %v", k, errs)
		}
	}
}

func TestValidatePodSecurityContextSuccess(t *testing.T) {
	hostNetworkSCC := defaultSCC()
	hostNetworkSCC.AllowHostNetwork = true
	hostNetworkPod := defaultPod()
	hostNetworkPod.Spec.SecurityContext.HostNetwork = true

	hostPIDSCC := defaultSCC()
	hostPIDSCC.AllowHostPID = true
	hostPIDPod := defaultPod()
	hostPIDPod.Spec.SecurityContext.HostPID = true

	hostIPCSCC := defaultSCC()
	hostIPCSCC.AllowHostIPC = true
	hostIPCPod := defaultPod()
	hostIPCPod.Spec.SecurityContext.HostIPC = true

	supGroupSCC := defaultSCC()
	supGroupSCC.SupplementalGroups = securityv1.SupplementalGroupsStrategyOptions{
		Type: securityv1.SupplementalGroupsStrategyMustRunAs,
		Ranges: []securityv1.IDRange{
			{Min: 1, Max: 5},
		},
	}
	supGroupPod := defaultPod()
	supGroupPod.Spec.SecurityContext.SupplementalGroups = []int64{3}

	fsGroupSCC := defaultSCC()
	fsGroupSCC.FSGroup = securityv1.FSGroupStrategyOptions{
		Type: securityv1.FSGroupStrategyMustRunAs,
		Ranges: []securityv1.IDRange{
			{Min: 1, Max: 5},
		},
	}
	fsGroupPod := defaultPod()
	fsGroup := int64(3)
	fsGroupPod.Spec.SecurityContext.FSGroup = &fsGroup

	seLinuxPod := defaultPod()
	seLinuxPod.Spec.SecurityContext.SELinuxOptions = &api.SELinuxOptions{
		User:  "user",
		Role:  "role",
		Type:  "type",
		Level: "level",
	}
	seLinuxSCC := defaultSCC()
	seLinuxSCC.SELinuxContext.Type = securityv1.SELinuxStrategyMustRunAs
	seLinuxSCC.SELinuxContext.SELinuxOptions = &corev1.SELinuxOptions{
		User:  "user",
		Role:  "role",
		Type:  "type",
		Level: "level",
	}

	seccompNilWithNoProfiles := defaultPod()
	seccompNilWithNoProfilesSCC := defaultSCC()
	seccompNilWithNoProfilesSCC.SeccompProfiles = nil

	seccompEmpty := defaultPod()
	seccompEmpty.Annotations[api.SeccompPodAnnotationKey] = ""

	seccompAllowAnySCC := defaultSCC()
	seccompAllowAnySCC.SeccompProfiles = []string{"*"}

	seccompAllowFooSCC := defaultSCC()
	seccompAllowFooSCC.SeccompProfiles = []string{"foo"}

	seccompFooPod := defaultPod()
	seccompFooPod.Annotations[api.SeccompPodAnnotationKey] = "foo"

	flexVolumePod := defaultPod()
	flexVolumePod.Spec.Volumes = []api.Volume{
		{
			Name: "flex-volume",
			VolumeSource: api.VolumeSource{
				FlexVolume: &api.FlexVolumeSource{
					Driver: "example/bar",
				},
			},
		},
	}

	sysctlAllowAllSCC := defaultSCC()
	sysctlAllowAllSCC.ForbiddenSysctls = []string{}
	sysctlAllowAllSCC.AllowedUnsafeSysctls = []string{"*"}

	safeSysctlKernelPod := defaultPod()
	safeSysctlKernelPod.Spec.SecurityContext.Sysctls = []api.Sysctl{
		{
			Name:  "kernel.shm_rmid_forced",
			Value: "1",
		},
	}

	unsafeSysctlKernelPod := defaultPod()
	unsafeSysctlKernelPod.Spec.SecurityContext.Sysctls = []api.Sysctl{
		{
			Name:  "kernel.sem",
			Value: "32000",
		},
	}

	seccompSCC := defaultSCC()
	seccompSCC.SeccompProfiles = []string{"foo"}

	seccompPod := defaultPod()
	seccompPod.Annotations = map[string]string{
		api.SeccompPodAnnotationKey: "foo",
	}

	userNamespaceOnSCC := defaultSCC()
	userNamespaceOnSCC.UserNamespaceLevel = securityv1.NamespaceLevelRequirePod

	userNamespaceOnPod := defaultPod()
	falseVar := false
	userNamespaceOnPod.Spec.SecurityContext.HostUsers = &falseVar

	userNamespaceOffSCC := defaultSCC()
	userNamespaceOffSCC.UserNamespaceLevel = securityv1.NamespaceLevelAllowHost

	userNamespaceOffPod := defaultPod()
	trueVar := true
	userNamespaceOffPod.Spec.SecurityContext.HostUsers = &trueVar

	successCases := map[string]struct {
		pod *api.Pod
		scc *securityv1.SecurityContextConstraints
	}{
		"pass hostNetwork validating SCC": {
			pod: hostNetworkPod,
			scc: hostNetworkSCC,
		},
		"pass hostPID validating SCC": {
			pod: hostPIDPod,
			scc: hostPIDSCC,
		},
		"pass hostIPC validating SCC": {
			pod: hostIPCPod,
			scc: hostIPCSCC,
		},
		"pass supplemental group validating SCC": {
			pod: supGroupPod,
			scc: supGroupSCC,
		},
		"pass fs group validating SCC": {
			pod: fsGroupPod,
			scc: fsGroupSCC,
		},
		"pass selinux validating SCC": {
			pod: seLinuxPod,
			scc: seLinuxSCC,
		},
		"pass seccomp nil with no profiles": {
			pod: seccompNilWithNoProfiles,
			scc: seccompNilWithNoProfilesSCC,
		},
		"pass seccomp empty with no profiles": {
			pod: seccompEmpty,
			scc: seccompNilWithNoProfilesSCC,
		},
		"pass seccomp wild card": {
			pod: seccompFooPod,
			scc: seccompAllowAnySCC,
		},
		"pass seccomp specific profile": {
			pod: seccompFooPod,
			scc: seccompAllowFooSCC,
		},
		"flex volume driver in a whitelist (all volumes are allowed)": {
			pod: flexVolumePod,
			scc: allowFlexVolumesSCC(false, true),
		},
		"flex volume driver with empty whitelist (all volumes are allowed)": {
			pod: flexVolumePod,
			scc: allowFlexVolumesSCC(true, true),
		},
		"flex volume driver in a whitelist (only flex volumes are allowed)": {
			pod: flexVolumePod,
			scc: allowFlexVolumesSCC(false, false),
		},
		"flex volume driver with empty whitelist (only flex volumes volumes are allowed)": {
			pod: flexVolumePod,
			scc: allowFlexVolumesSCC(true, false),
		},
		"pass sysctl specific profile with safe kernel sysctl": {
			pod: safeSysctlKernelPod,
			scc: sysctlAllowAllSCC,
		},
		"pass sysctl specific profile with unsafe kernel sysctl": {
			pod: unsafeSysctlKernelPod,
			scc: sysctlAllowAllSCC,
		},
		"pass seccomp validating SCC": {
			pod: seccompPod,
			scc: seccompSCC,
		},
		"pass user namespace on validating SCC": {
			pod: userNamespaceOnPod,
			scc: userNamespaceOnSCC,
		},
		"pass user namespace off validating SCC": {
			pod: userNamespaceOffPod,
			scc: userNamespaceOffSCC,
		},
	}

	for k, v := range successCases {
		provider, err := NewSimpleProvider(v.scc)
		if err != nil {
			t.Fatalf("unable to create provider %v", err)
		}
		errs := provider.ValidatePodSecurityContext(v.pod, field.NewPath(""))
		if len(errs) != 0 {
			t.Errorf("%s expected validation pass but received errors %v", k, errs)
			continue
		}
	}
}

func TestValidateContainerSecurityContextSuccess(t *testing.T) {
	// fail user strat
	userSCC := defaultSCC()
	var uid int64 = 999
	userSCC.RunAsUser = securityv1.RunAsUserStrategyOptions{
		Type: securityv1.RunAsUserStrategyMustRunAs,
		UID:  &uid,
	}
	userPod := defaultPod()
	userPod.Spec.Containers[0].SecurityContext.RunAsUser = &uid

	// fail selinux strat
	seLinuxSCC := defaultSCC()
	seLinuxSCC.SELinuxContext = securityv1.SELinuxContextStrategyOptions{
		Type: securityv1.SELinuxStrategyMustRunAs,
		SELinuxOptions: &corev1.SELinuxOptions{
			Level: "foo",
		},
	}
	seLinuxPod := defaultPod()
	seLinuxPod.Spec.Containers[0].SecurityContext.SELinuxOptions = &api.SELinuxOptions{
		Level: "foo",
	}

	privSCC := defaultSCC()
	privSCC.AllowPrivilegedContainer = true
	privPod := defaultPod()
	var priv bool = true
	privPod.Spec.Containers[0].SecurityContext.Privileged = &priv

	capsSCC := defaultSCC()
	capsSCC.AllowedCapabilities = []corev1.Capability{"foo"}
	capsPod := defaultPod()
	capsPod.Spec.Containers[0].SecurityContext.Capabilities = &api.Capabilities{
		Add: []api.Capability{"foo"},
	}

	// pod should be able to request caps that are in the required set even if not specified in the allowed set
	requiredCapsSCC := defaultSCC()
	requiredCapsSCC.DefaultAddCapabilities = []corev1.Capability{"foo"}
	requiredCapsPod := defaultPod()
	requiredCapsPod.Spec.Containers[0].SecurityContext.Capabilities = &api.Capabilities{
		Add: []api.Capability{"foo"},
	}

	hostDirSCC := defaultSCC()
	hostDirSCC.Volumes = []securityv1.FSType{securityv1.FSTypeHostPath}
	hostDirPod := defaultPod()
	hostDirPod.Spec.Volumes = []api.Volume{
		{
			Name: "bad volume",
			VolumeSource: api.VolumeSource{
				HostPath: &api.HostPathVolumeSource{},
			},
		},
	}

	hostPortSCC := defaultSCC()
	hostPortSCC.AllowHostPorts = true
	hostPortPod := defaultPod()
	hostPortPod.Spec.Containers[0].Ports = []api.ContainerPort{{HostPort: 1}}

	readOnlyRootFSPodFalse := defaultPod()
	readOnlyRootFSFalse := false
	readOnlyRootFSPodFalse.Spec.Containers[0].SecurityContext.ReadOnlyRootFilesystem = &readOnlyRootFSFalse

	readOnlyRootFSPodTrue := defaultPod()
	readOnlyRootFSTrue := true
	readOnlyRootFSPodTrue.Spec.Containers[0].SecurityContext.ReadOnlyRootFilesystem = &readOnlyRootFSTrue

	seccompNilWithNoProfiles := defaultPod()
	seccompNilWithNoProfilesSCC := defaultSCC()
	seccompNilWithNoProfilesSCC.SeccompProfiles = nil

	seccompEmptyWithNoProfiles := defaultPod()
	seccompEmptyWithNoProfiles.Annotations[api.SeccompContainerAnnotationKeyPrefix+seccompEmptyWithNoProfiles.Spec.Containers[0].Name] = ""

	seccompAllowAnySCC := defaultSCC()
	seccompAllowAnySCC.SeccompProfiles = []string{"*"}

	seccompAllowFooSCC := defaultSCC()
	seccompAllowFooSCC.SeccompProfiles = []string{"foo"}

	seccompFooPod := defaultPod()
	seccompFooPod.Annotations[api.SeccompContainerAnnotationKeyPrefix+seccompFooPod.Spec.Containers[0].Name] = "foo"

	seccompPod := defaultPod()
	seccompPod.Annotations = map[string]string{
		api.SeccompPodAnnotationKey: "foo",
		api.SeccompContainerAnnotationKeyPrefix + seccompPod.Spec.Containers[0].Name: "foo",
	}

	seccompPodInherit := defaultPod()
	seccompPodInherit.Annotations = map[string]string{
		api.SeccompPodAnnotationKey: "foo",
	}

	successCases := map[string]struct {
		pod *api.Pod
		scc *securityv1.SecurityContextConstraints
	}{
		"pass user must run as SCC": {
			pod: userPod,
			scc: userSCC,
		},
		"pass seLinux must run as SCC": {
			pod: seLinuxPod,
			scc: seLinuxSCC,
		},
		"pass priv validating SCC": {
			pod: privPod,
			scc: privSCC,
		},
		"pass allowed caps validating SCC": {
			pod: capsPod,
			scc: capsSCC,
		},
		"pass required caps validating SCC": {
			pod: requiredCapsPod,
			scc: requiredCapsSCC,
		},
		"pass hostDir validating SCC": {
			pod: hostDirPod,
			scc: hostDirSCC,
		},
		"pass hostPort validating SCC": {
			pod: hostPortPod,
			scc: hostPortSCC,
		},
		"pass read only root fs - nil": {
			pod: defaultPod(),
			scc: defaultSCC(),
		},
		"pass read only root fs - false": {
			pod: readOnlyRootFSPodFalse,
			scc: defaultSCC(),
		},
		"pass read only root fs - true": {
			pod: readOnlyRootFSPodTrue,
			scc: defaultSCC(),
		},
		"pass seccomp nil with no profiles": {
			pod: seccompNilWithNoProfiles,
			scc: seccompNilWithNoProfilesSCC,
		},
		"pass seccomp empty with no profiles": {
			pod: seccompEmptyWithNoProfiles,
			scc: seccompNilWithNoProfilesSCC,
		},
		"pass seccomp wild card": {
			pod: seccompFooPod,
			scc: seccompAllowAnySCC,
		},
		"pass seccomp specific profile": {
			pod: seccompFooPod,
			scc: seccompAllowFooSCC,
		},
	}

	for k, v := range successCases {
		provider, err := NewSimpleProvider(v.scc)
		if err != nil {
			t.Fatalf("unable to create provider %v", err)
		}
		errs := provider.ValidateContainerSecurityContext(v.pod, &v.pod.Spec.Containers[0], field.NewPath(""))
		if len(errs) != 0 {
			t.Errorf("%s expected validation pass but received errors %v", k, errs)
			continue
		}
	}
}

func TestGenerateContainerSecurityContextReadOnlyRootFS(t *testing.T) {
	trueSCC := defaultSCC()
	trueSCC.ReadOnlyRootFilesystem = true

	trueVal := true
	expectTrue := &trueVal
	falseVal := false
	expectFalse := &falseVal

	falsePod := defaultPod()
	falsePod.Spec.Containers[0].SecurityContext.ReadOnlyRootFilesystem = expectFalse

	truePod := defaultPod()
	truePod.Spec.Containers[0].SecurityContext.ReadOnlyRootFilesystem = expectTrue

	tests := map[string]struct {
		pod      *api.Pod
		scc      *securityv1.SecurityContextConstraints
		expected *bool
	}{
		"false scc, nil sc": {
			scc:      defaultSCC(),
			pod:      defaultPod(),
			expected: nil,
		},
		"false scc, false sc": {
			scc:      defaultSCC(),
			pod:      falsePod,
			expected: expectFalse,
		},
		"false scc, true sc": {
			scc:      defaultSCC(),
			pod:      truePod,
			expected: expectTrue,
		},
		"true scc, nil sc": {
			scc:      trueSCC,
			pod:      defaultPod(),
			expected: expectTrue,
		},
		"true scc, false sc": {
			scc: trueSCC,
			pod: falsePod,
			// expect false even though it defaults to true to ensure it doesn't change set values
			// validation catches the mismatch, not generation
			expected: expectFalse,
		},
		"true scc, true sc": {
			scc:      trueSCC,
			pod:      truePod,
			expected: expectTrue,
		},
	}

	for k, v := range tests {
		provider, err := NewSimpleProvider(v.scc)
		if err != nil {
			t.Errorf("%s unable to create provider %v", k, err)
			continue
		}
		sc, err := provider.CreateContainerSecurityContext(v.pod, &v.pod.Spec.Containers[0])
		if err != nil {
			t.Errorf("%s unable to create container security context %v", k, err)
			continue
		}

		if v.expected == nil && sc.ReadOnlyRootFilesystem != nil {
			t.Errorf("%s expected a nil ReadOnlyRootFilesystem but got %t", k, *sc.ReadOnlyRootFilesystem)
		}
		if v.expected != nil && sc.ReadOnlyRootFilesystem == nil {
			t.Errorf("%s expected a non nil ReadOnlyRootFilesystem but recieved nil", k)
		}
		if v.expected != nil && sc.ReadOnlyRootFilesystem != nil && (*v.expected != *sc.ReadOnlyRootFilesystem) {
			t.Errorf("%s expected a non nil ReadOnlyRootFilesystem set to %t but got %t", k, *v.expected, *sc.ReadOnlyRootFilesystem)
		}

	}
}

func TestGenerateNonRootSecurityContextOnNonZeroRunAsUser(t *testing.T) {
	userSCC := defaultSCC()
	var minRange int64 = 100
	var maxRange int64 = 900
	userSCC.RunAsUser = securityv1.RunAsUserStrategyOptions{
		Type:        securityv1.RunAsUserStrategyMustRunAsRange,
		UIDRangeMin: &minRange,
		UIDRangeMax: &maxRange,
	}

	rootMinSCC := defaultSCC()
	var rootUID int64 = 0
	rootMinSCC.RunAsUser = securityv1.RunAsUserStrategyOptions{
		Type:        securityv1.RunAsUserStrategyMustRunAsRange,
		UIDRangeMin: &rootUID,
		UIDRangeMax: &maxRange,
	}

	nonRootSCC := defaultSCC()
	nonRootSCC.RunAsUser = securityv1.RunAsUserStrategyOptions{
		Type: securityv1.RunAsUserStrategyMustRunAsNonRoot,
	}

	var useruid int64 = 500
	containerUserPod := defaultPod()
	containerUserPod.Spec.Containers[0].SecurityContext.RunAsUser = &useruid

	podUserPod := defaultPod()
	podUserPod.Spec.SecurityContext.RunAsUser = &useruid

	zeroPodUserPod := defaultPod()
	zeroPodUserPod.Spec.SecurityContext.RunAsUser = &rootUID

	zeroContainerUserPod := defaultPod()
	zeroContainerUserPod.Spec.Containers[0].SecurityContext.RunAsUser = &rootUID

	zeroPodUserPodNonRootSCC := zeroPodUserPod.DeepCopy()
	zeroContainerUserPodNonRootSCC := zeroContainerUserPod.DeepCopy()

	falseVal := false
	trueVal := true
	tests := map[string]struct {
		pod        *api.Pod
		scc        *securityv1.SecurityContextConstraints
		expectedSC *api.SecurityContext
	}{
		"generate non-zero user": {
			pod: defaultPod(),
			scc: userSCC,
			expectedSC: &api.SecurityContext{
				RunAsUser:    &minRange,
				RunAsNonRoot: &trueVal,
				Privileged:   &falseVal,
			},
		},
		"generate zero user": {
			pod: defaultPod(),
			scc: rootMinSCC,
			expectedSC: &api.SecurityContext{
				RunAsUser:    &rootUID,
				RunAsNonRoot: nil,
				Privileged:   &falseVal,
			},
		},
		"nonzero user set on pod level": {
			pod: podUserPod,
			scc: userSCC,
			expectedSC: &api.SecurityContext{
				RunAsUser:    nil,
				RunAsNonRoot: &trueVal,
				Privileged:   &falseVal,
			},
		},
		"nonzero user set on container level": {
			pod: containerUserPod,
			scc: userSCC,
			expectedSC: &api.SecurityContext{
				RunAsUser:    &useruid,
				RunAsNonRoot: &trueVal,
				Privileged:   &falseVal,
			},
		},
		"zero user set on pod level": {
			pod: zeroPodUserPod,
			scc: rootMinSCC,
			expectedSC: &api.SecurityContext{
				RunAsUser:    nil,
				RunAsNonRoot: nil,
				Privileged:   &falseVal,
			},
		},
		"zero user set on container level": {
			pod: zeroContainerUserPod,
			scc: rootMinSCC,
			expectedSC: &api.SecurityContext{
				RunAsUser:    &rootUID,
				RunAsNonRoot: nil,
				Privileged:   &falseVal,
			},
		},
		"no user set, nonroot SCC": {
			pod: defaultPod(),
			scc: nonRootSCC,
			expectedSC: &api.SecurityContext{
				RunAsUser:    nil,
				RunAsNonRoot: &trueVal,
				Privileged:   &falseVal,
			},
		},
		"zero user set on pod level, nonroot SCC": {
			pod: zeroPodUserPodNonRootSCC,
			scc: nonRootSCC,
			expectedSC: &api.SecurityContext{
				RunAsUser:    nil,
				RunAsNonRoot: nil,
				Privileged:   &falseVal,
			},
		},
		"zero user set on container level, nonroot SCC": {
			pod: zeroContainerUserPodNonRootSCC,
			scc: nonRootSCC,
			expectedSC: &api.SecurityContext{
				RunAsUser:    &rootUID,
				RunAsNonRoot: nil,
				Privileged:   &falseVal,
			},
		},
	}

	for k, v := range tests {
		provider, err := NewSimpleProvider(v.scc)
		if err != nil {
			t.Errorf("%s unable to create provider %v", k, err)
			continue
		}
		sc, err := provider.CreateContainerSecurityContext(v.pod, &v.pod.Spec.Containers[0])
		if err != nil {
			t.Errorf("%s unable to create container security context %v", k, err)
			continue
		}

		if !equality.Semantic.DeepEqual(v.expectedSC, sc) {
			t.Errorf("%s expected security context does not match the actual: %s", k, diff.Diff(v.expectedSC, sc))
		}

	}
}

func defaultSCC() *securityv1.SecurityContextConstraints {
	return &securityv1.SecurityContextConstraints{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "scc-sa",
			Annotations: map[string]string{},
		},
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
	}
}

func defaultPod() *api.Pod {
	var notPriv bool = false
	return &api.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec: api.PodSpec{
			SecurityContext: &api.PodSecurityContext{
				// fill in for test cases
			},
			Containers: []api.Container{
				{
					SecurityContext: &api.SecurityContext{
						// expected to be set by defaulting mechanisms
						Privileged: &notPriv,
						// fill in the rest for test cases
					},
				},
			},
		},
	}
}

func allowFlexVolumesSCC(allowAllFlexVolumes, allowAllVolumes bool) *securityv1.SecurityContextConstraints {
	scc := defaultSCC()

	allowedVolumes := []securityv1.AllowedFlexVolume{
		{Driver: "example/foo"},
		{Driver: "example/bar"},
	}
	if allowAllFlexVolumes {
		allowedVolumes = []securityv1.AllowedFlexVolume{}
	}

	allowedVolumeType := securityv1.FSTypeFlexVolume
	if allowAllVolumes {
		allowedVolumeType = securityv1.FSTypeAll
	}

	scc.AllowedFlexVolumes = allowedVolumes
	scc.Volumes = []securityv1.FSType{allowedVolumeType}

	return scc
}

// TestValidateAllowedVolumes will test that for every field of VolumeSource we can create
// a pod with that type of volume and deny it, accept it explicitly, or accept it with
// the FSTypeAll wildcard.
func TestValidateAllowedVolumes(t *testing.T) {
	val := reflect.ValueOf(api.VolumeSource{})

	for i := 0; i < val.NumField(); i++ {
		// reflectively create the volume source
		fieldVal := val.Type().Field(i)

		volumeSource := api.VolumeSource{}
		volumeSourceVolume := reflect.New(fieldVal.Type.Elem())

		reflect.ValueOf(&volumeSource).Elem().FieldByName(fieldVal.Name).Set(volumeSourceVolume)
		volume := api.Volume{VolumeSource: volumeSource}

		// sanity check before moving on
		fsType, err := sccutil.GetVolumeFSType(volume)
		if err != nil {
			t.Errorf("error getting FSType for %s: %s", fieldVal.Name, err.Error())
			continue
		}

		// add the volume to the pod
		pod := defaultPod()
		pod.Spec.Volumes = []api.Volume{volume}

		// create an SCC that allows no volumes
		scc := defaultSCC()

		provider, err := NewSimpleProvider(scc)
		if err != nil {
			t.Errorf("error creating provider for %s: %s", fieldVal.Name, err.Error())
			continue
		}

		// expect a denial for this SCC and test the error message to ensure it's related to the volumesource
		errs := provider.ValidatePodSecurityContext(pod, field.NewPath(""))
		if len(errs) != 1 {
			t.Errorf("expected exactly 1 error for %s but got %v", fieldVal.Name, errs)
		} else {
			if !strings.Contains(errs.ToAggregate().Error(), fmt.Sprintf("%s volumes are not allowed to be used", fsType)) {
				t.Errorf("did not find the expected error, received: %v", errs)
			}
		}

		// now add the fstype directly to the scc and it should validate
		scc.Volumes = []securityv1.FSType{fsType}
		errs = provider.ValidatePodSecurityContext(pod, field.NewPath(""))
		if len(errs) != 0 {
			t.Errorf("directly allowing volume expected no errors for %s but got %v", fieldVal.Name, errs)
		}

		// now change the scc to allow any volumes and the pod should still validate
		scc.Volumes = []securityv1.FSType{securityv1.FSTypeAll}
		errs = provider.ValidatePodSecurityContext(pod, field.NewPath(""))
		if len(errs) != 0 {
			t.Errorf("wildcard volume expected no errors for %s but got %v", fieldVal.Name, errs)
		}
	}
}

func TestValidateProjectedVolume(t *testing.T) {
	pod := defaultPod()
	scc := defaultSCC()
	provider, err := NewSimpleProvider(scc)
	require.NoError(t, err, "error creating provider")

	tests := []struct {
		desc                  string
		allowedFSTypes        []securityv1.FSType
		projectedVolumeSource *api.ProjectedVolumeSource
		wantAllow             bool
	}{
		{
			desc:                  "deny if secret is not allowed",
			allowedFSTypes:        []securityv1.FSType{securityv1.FSTypeEmptyDir},
			projectedVolumeSource: newProjectedVolumeCreator().FullValid().ToVolumeSource(),
			wantAllow:             false,
		},
		{
			desc:           "deny if the projected volume has volume source other than the ones in projected volume injected by service account token admission plugin",
			allowedFSTypes: []securityv1.FSType{securityv1.FSTypeSecret},
			projectedVolumeSource: &api.ProjectedVolumeSource{
				Sources: []api.VolumeProjection{
					{
						ConfigMap: &api.ConfigMapProjection{
							LocalObjectReference: api.LocalObjectReference{
								Name: "foo-ca.crt",
							},
							Items: []api.KeyToPath{
								{
									Key:  "ca.crt",
									Path: "ca.crt",
								},
							},
						},
					},
				}},
			wantAllow: false,
		},
		{
			desc:                  "allow if secret is allowed and the projected volume sources equals to the ones injected by service account admission plugin",
			allowedFSTypes:        []securityv1.FSType{securityv1.FSTypeSecret},
			projectedVolumeSource: newProjectedVolumeCreator().FullValid().ToVolumeSource(),
			wantAllow:             true,
		},
		{
			desc:                  "deny if the SA has a slightly different path",
			allowedFSTypes:        []securityv1.FSType{securityv1.FSTypeSecret},
			projectedVolumeSource: newProjectedVolumeCreator().FullValid().WithSA("notAToken").ToVolumeSource(),
			wantAllow:             false,
		},
		{
			desc:           "deny if there's an unknown CM",
			allowedFSTypes: []securityv1.FSType{securityv1.FSTypeSecret},
			projectedVolumeSource: newProjectedVolumeCreator().FullValid().
				WithCM("random-key",
					"unknown-local-reference",
					api.KeyToPath{
						Key:  "ca.crt",
						Path: "ca.crt",
					}).ToVolumeSource(),
			wantAllow: false,
		},
		{
			desc:           "deny if the kube-root-ca has wrong paths",
			allowedFSTypes: []securityv1.FSType{securityv1.FSTypeSecret},
			projectedVolumeSource: newProjectedVolumeCreator().FullValid().
				WithKubeRootCA("openshift-service-ca.crt", api.KeyToPath{
					Key:  "allow-all.crt",
					Path: "ca.crt",
				}).ToVolumeSource(),
			wantAllow: false,
		},
		{
			desc:           "deny if the openshift-ca has wrong paths",
			allowedFSTypes: []securityv1.FSType{securityv1.FSTypeSecret},
			projectedVolumeSource: newProjectedVolumeCreator().FullValid().
				WithOpenShiftServiceCA("openshift-service-ca.crt", api.KeyToPath{
					Key:  "malicious.crt",
					Path: "service-ca.crt",
				}).ToVolumeSource(),
			wantAllow: false,
		},
		{
			desc:           "deny if the downward API sets an unknown fieldPath",
			allowedFSTypes: []securityv1.FSType{securityv1.FSTypeSecret},
			projectedVolumeSource: newProjectedVolumeCreator().FullValid().
				WithDownwardAPI("namespace", &api.ObjectFieldSelector{
					APIVersion: "v1",
					FieldPath:  "spec.serviceAccount",
				}).ToVolumeSource(),
			wantAllow: false,
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			pod.Spec.Volumes = []api.Volume{{VolumeSource: api.VolumeSource{Projected: test.projectedVolumeSource}}}
			scc.Volumes = test.allowedFSTypes
			errs := provider.ValidatePodSecurityContext(pod, field.NewPath(""))
			if test.wantAllow {
				require.Empty(t, errs, "projected volumes are allowed if secret volumes is allowed and BoundServiceAccountTokenVolume is enabled")
			} else {
				require.Greaterf(t, len(errs), 0, "expected errors but got none")
				require.Contains(t, errs.ToAggregate().Error(), "projected volumes are not allowed to be used", "did not find the expected error")
			}
		})
	}
}

// TestValidateAllowPrivilegeEscalation will test that when the SecurityContextConstraints
// AllowPrivilegeEscalation is false we cannot set a container's securityContext
// to allowPrivilegeEscalation, but when it is true we can.
func TestValidateAllowPrivilegeEscalation(t *testing.T) {
	yes := true
	no := false

	pod := defaultPod()
	pod.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = &yes

	// create a SCC that does not allow privilege escalation
	scc := defaultSCC()
	scc.AllowPrivilegeEscalation = &no

	provider, err := NewSimpleProvider(scc)
	if err != nil {
		t.Errorf("error creating provider: %v", err.Error())
	}

	// expect a denial for this SCC and test the error message to ensure it's related to allowPrivilegeEscalation
	errs := provider.ValidateContainerSecurityContext(pod, &pod.Spec.Containers[0], field.NewPath(""))
	if len(errs) != 1 {
		t.Errorf("expected exactly 1 error but got %v", errs)
	} else {
		if !strings.Contains(errs.ToAggregate().Error(), "Allowing privilege escalation for containers is not allowed") {
			t.Errorf("did not find the expected error, received: %v", errs)
		}
	}

	// Now set AllowPrivilegeEscalation
	scc.AllowPrivilegeEscalation = &yes
	errs = provider.ValidateContainerSecurityContext(pod, &pod.Spec.Containers[0], field.NewPath(""))
	if len(errs) != 0 {
		t.Errorf("directly allowing privilege escalation expected no errors but got %v", errs)
	}

	// Now set the scc spec to false and reset AllowPrivilegeEscalation
	scc.AllowPrivilegeEscalation = &no
	pod.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = nil
	errs = provider.ValidateContainerSecurityContext(pod, &pod.Spec.Containers[0], field.NewPath(""))
	if len(errs) != 1 {
		t.Errorf("expected exactly 1 error but got %v", errs)
	} else {
		if !strings.Contains(errs.ToAggregate().Error(), "Allowing privilege escalation for containers is not allowed") {
			t.Errorf("did not find the expected error, received: %v", errs)
		}
	}

	// Now unset both AllowPrivilegeEscalation
	scc.AllowPrivilegeEscalation = &yes
	pod.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = nil
	errs = provider.ValidateContainerSecurityContext(pod, &pod.Spec.Containers[0], field.NewPath(""))
	if len(errs) != 0 {
		t.Errorf("resetting allowing privilege escalation expected no errors but got %v", errs)
	}
}

func TestSeccompAnnotationsFieldsGeneration(t *testing.T) {
	noSeccompProvider, err := NewSimpleProvider(defaultSCC())
	require.NoError(t, err)

	sccWildcardSeccomp := defaultSCC()
	sccWildcardSeccomp.SeccompProfiles = []string{"*"}
	wildcardSeccompProvider, err := NewSimpleProvider(sccWildcardSeccomp)
	require.NoError(t, err)

	sccGenerateSeccomp := defaultSCC()
	sccGenerateSeccomp.SeccompProfiles = []string{corev1.SeccompProfileRuntimeDefault}
	generateSeccompProvider, err := NewSimpleProvider(sccGenerateSeccomp)
	require.NoError(t, err)

	podPodSeccompAnnotation := defaultPod()
	podPodSeccompAnnotation.Annotations = map[string]string{
		api.SeccompPodAnnotationKey: corev1.SeccompProfileRuntimeDefault,
	}

	podPodSeccompField := defaultPod()
	podPodSeccompField.Spec.SecurityContext.SeccompProfile = &api.SeccompProfile{Type: api.SeccompProfileTypeRuntimeDefault}

	for _, tt := range []struct {
		name                     string
		sccProvider              SecurityContextConstraintsProvider
		pod                      *api.Pod
		expectedPodAnnotations   map[string]string
		expectedPodSeccomp       *api.SeccompProfile
		expectedContainerSeccomp *api.SeccompProfile
	}{
		{
			name:                   "pod - no seccomp, SCC - no seccomp",
			pod:                    defaultPod(),
			sccProvider:            noSeccompProvider,
			expectedPodAnnotations: map[string]string{},
		},
		{
			name:                   "pod - no seccomp, SCC - wildcard seccomp",
			pod:                    defaultPod(),
			sccProvider:            wildcardSeccompProvider,
			expectedPodAnnotations: map[string]string{},
		},
		{
			name:        "pod - no seccomp, SCC - generate seccomp",
			pod:         defaultPod(),
			sccProvider: generateSeccompProvider,
			expectedPodAnnotations: map[string]string{
				api.SeccompPodAnnotationKey: "runtime/default",
			},
			expectedPodSeccomp: &api.SeccompProfile{Type: api.SeccompProfileTypeRuntimeDefault},
		},
		{
			name:                   "pod - pod annotation, SCC - no seccomp",
			pod:                    withAnnotations(defaultPod(), map[string]string{api.SeccompPodAnnotationKey: "unconfined"}),
			sccProvider:            noSeccompProvider,
			expectedPodAnnotations: map[string]string{api.SeccompPodAnnotationKey: "unconfined"},
			expectedPodSeccomp:     &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined},
		},
		{
			name:                   "pod - pod annotation, SCC - wildcard seccomp",
			pod:                    withAnnotations(defaultPod(), map[string]string{api.SeccompPodAnnotationKey: "unconfined"}),
			sccProvider:            wildcardSeccompProvider,
			expectedPodAnnotations: map[string]string{api.SeccompPodAnnotationKey: "unconfined"},
			expectedPodSeccomp:     &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined},
		},
		{
			name:                   "pod - pod annotation, SCC - generate seccomp",
			pod:                    withAnnotations(defaultPod(), map[string]string{api.SeccompPodAnnotationKey: "unconfined"}),
			sccProvider:            generateSeccompProvider,
			expectedPodAnnotations: map[string]string{api.SeccompPodAnnotationKey: "unconfined"},
			expectedPodSeccomp:     &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined},
		},
		{
			name:                   "pod - pod field, SCC - no seccomp",
			pod:                    withPodSeccomp(defaultPod(), &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined}),
			sccProvider:            noSeccompProvider,
			expectedPodAnnotations: map[string]string{api.SeccompPodAnnotationKey: "unconfined"},
			expectedPodSeccomp:     &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined},
		},
		{
			name:                   "pod - pod field, SCC - wildcard seccomp",
			pod:                    withPodSeccomp(defaultPod(), &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined}),
			sccProvider:            wildcardSeccompProvider,
			expectedPodAnnotations: map[string]string{api.SeccompPodAnnotationKey: "unconfined"},
			expectedPodSeccomp:     &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined},
		},
		{
			name:                   "pod - pod field, SCC - generate seccomp",
			pod:                    withPodSeccomp(defaultPod(), &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined}),
			sccProvider:            generateSeccompProvider,
			expectedPodAnnotations: map[string]string{api.SeccompPodAnnotationKey: "unconfined"},
			expectedPodSeccomp:     &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined},
		},
		{
			name:                     "pod - container annotation, SCC - no seccomp",
			pod:                      withAnnotations(defaultPod(), map[string]string{api.SeccompContainerAnnotationKeyPrefix + "": "unconfined"}),
			sccProvider:              noSeccompProvider,
			expectedPodAnnotations:   map[string]string{api.SeccompContainerAnnotationKeyPrefix + "": "unconfined"},
			expectedContainerSeccomp: &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined},
		},
		{
			name:                     "pod - container annotation, SCC - wildcard seccomp",
			pod:                      withAnnotations(defaultPod(), map[string]string{api.SeccompContainerAnnotationKeyPrefix + "": "unconfined"}),
			sccProvider:              wildcardSeccompProvider,
			expectedPodAnnotations:   map[string]string{api.SeccompContainerAnnotationKeyPrefix + "": "unconfined"},
			expectedContainerSeccomp: &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined},
		},
		{
			name:        "pod - container annotation, SCC - generate seccomp",
			pod:         withAnnotations(defaultPod(), map[string]string{api.SeccompContainerAnnotationKeyPrefix + "": "unconfined"}),
			sccProvider: generateSeccompProvider,
			expectedPodAnnotations: map[string]string{
				api.SeccompPodAnnotationKey:                  "runtime/default",
				api.SeccompContainerAnnotationKeyPrefix + "": "unconfined",
			},
			expectedPodSeccomp:       &api.SeccompProfile{Type: api.SeccompProfileTypeRuntimeDefault},
			expectedContainerSeccomp: &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined},
		},
		{
			name:                     "pod - container field, SCC - no seccomp",
			pod:                      withContainerSeccomp(defaultPod(), &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined}),
			sccProvider:              noSeccompProvider,
			expectedPodAnnotations:   map[string]string{},
			expectedContainerSeccomp: &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined},
		},
		{
			name:                     "pod - container field, SCC - wildcard seccomp",
			pod:                      withContainerSeccomp(defaultPod(), &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined}),
			sccProvider:              wildcardSeccompProvider,
			expectedPodAnnotations:   map[string]string{},
			expectedContainerSeccomp: &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined},
		},
		{
			name:        "pod - container field, SCC - generate seccomp",
			pod:         withContainerSeccomp(defaultPod(), &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined}),
			sccProvider: generateSeccompProvider,
			expectedPodAnnotations: map[string]string{
				api.SeccompPodAnnotationKey: "runtime/default",
			},
			expectedPodSeccomp:       &api.SeccompProfile{Type: api.SeccompProfileTypeRuntimeDefault},
			expectedContainerSeccomp: &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined},
		},
		{
			name:                   "pod - pod field and annotation different, SCC - generate seccomp",
			pod:                    withPodSeccomp(withAnnotations(defaultPod(), map[string]string{api.SeccompPodAnnotationKey: "unconfined"}), &api.SeccompProfile{Type: api.SeccompProfileTypeLocalhost, LocalhostProfile: pointer.String("somelocal")}),
			sccProvider:            generateSeccompProvider,
			expectedPodAnnotations: map[string]string{api.SeccompPodAnnotationKey: "unconfined"},
			expectedPodSeccomp:     &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined},
		},
		{
			name:        "pod - container field and annotation different, SCC - generate seccomp",
			pod:         withContainerSeccomp(withAnnotations(defaultPod(), map[string]string{api.SeccompContainerAnnotationKeyPrefix + "": "unconfined"}), &api.SeccompProfile{Type: api.SeccompProfileTypeLocalhost, LocalhostProfile: pointer.String("somelocal")}),
			sccProvider: generateSeccompProvider,
			expectedPodAnnotations: map[string]string{
				api.SeccompContainerAnnotationKeyPrefix + "": "unconfined",
				api.SeccompPodAnnotationKey:                  "runtime/default",
			},
			expectedPodSeccomp:       &api.SeccompProfile{Type: api.SeccompProfileTypeRuntimeDefault},
			expectedContainerSeccomp: &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			podSecurityContext, podAnnotations, err := tt.sccProvider.CreatePodSecurityContext(tt.pod)
			require.NoError(t, err)

			if !reflect.DeepEqual(tt.expectedPodAnnotations, podAnnotations) {
				t.Errorf("pod annotations differ: %s", cmp.Diff(tt.expectedPodAnnotations, podAnnotations))
			}

			if !reflect.DeepEqual(tt.expectedPodSeccomp, podSecurityContext.SeccompProfile) {
				t.Errorf("pod seccomp profiles differ - expected %v; got %v", tt.expectedPodSeccomp, podSecurityContext.SeccompProfile)
			}

			containerSecurityContext, err := tt.sccProvider.CreateContainerSecurityContext(tt.pod, &tt.pod.Spec.Containers[0])
			require.NoError(t, err)

			if !reflect.DeepEqual(tt.expectedContainerSeccomp, containerSecurityContext.SeccompProfile) {
				t.Errorf("container seccomp profiles differ - expected %v; got %v", tt.expectedContainerSeccomp, containerSecurityContext.SeccompProfile)
			}
		})
	}
}

func withAnnotations(pod *api.Pod, annotations map[string]string) *api.Pod {
	pod.Annotations = annotations
	return pod
}

func withPodSeccomp(pod *api.Pod, seccompProfile *api.SeccompProfile) *api.Pod {
	pod.Spec.SecurityContext.SeccompProfile = seccompProfile
	return pod
}

func withContainerSeccomp(pod *api.Pod, seccompProfile *api.SeccompProfile) *api.Pod {
	pod.Spec.Containers[0].SecurityContext.SeccompProfile = seccompProfile
	return pod
}

type projectedVolumeCreator struct {
	volumes map[string]api.VolumeProjection
}

func newProjectedVolumeCreator() *projectedVolumeCreator {
	return &projectedVolumeCreator{
		volumes: map[string]api.VolumeProjection{},
	}
}

func (p *projectedVolumeCreator) FullValid() *projectedVolumeCreator {
	return p.WithSA("token").
		WithKubeRootCA("kube-root-ca.crt", api.KeyToPath{
			Key:  "ca.crt",
			Path: "ca.crt",
		}).
		WithOpenShiftServiceCA("openshift-service-ca.crt", api.KeyToPath{
			Key:  "service-ca.crt",
			Path: "service-ca.crt",
		}).
		WithDownwardAPI("namespace", &api.ObjectFieldSelector{
			APIVersion: "v1",
			FieldPath:  "metadata.namespace",
		})
}

func (p *projectedVolumeCreator) ToVolumeSource() *api.ProjectedVolumeSource {
	ret := &api.ProjectedVolumeSource{
		Sources: []api.VolumeProjection{},
	}

	for _, v := range p.volumes {
		ret.Sources = append(ret.Sources, v)
	}

	return ret
}

func (p *projectedVolumeCreator) WithSA(path string) *projectedVolumeCreator {
	p.volumes["sa"] = api.VolumeProjection{
		ServiceAccountToken: &api.ServiceAccountTokenProjection{
			Path:              path,
			ExpirationSeconds: 3607,
		},
	}
	return p
}

func (p *projectedVolumeCreator) WithOpenShiftServiceCA(refName string, paths ...api.KeyToPath) *projectedVolumeCreator {
	return p.WithCM("openshift-service-ca", refName, paths...)
}

func (p *projectedVolumeCreator) WithKubeRootCA(refName string, paths ...api.KeyToPath) *projectedVolumeCreator {
	return p.WithCM("kube-root-ca", refName, paths...)
}

func (p *projectedVolumeCreator) WithCM(key, refName string, paths ...api.KeyToPath) *projectedVolumeCreator {
	p.volumes[key] = api.VolumeProjection{
		ConfigMap: &api.ConfigMapProjection{
			LocalObjectReference: api.LocalObjectReference{
				Name: refName,
			},
			Items: paths,
		},
	}

	return p
}

func (p *projectedVolumeCreator) WithDownwardAPI(path string, fieldRef *api.ObjectFieldSelector) *projectedVolumeCreator {
	p.volumes["downward-api"] = api.VolumeProjection{
		DownwardAPI: &api.DownwardAPIProjection{
			Items: []api.DownwardAPIVolumeFile{
				{
					Path:     path,
					FieldRef: fieldRef,
				},
			},
		},
	}
	return p
}
