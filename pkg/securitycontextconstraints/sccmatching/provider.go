package sccmatching

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	api "k8s.io/kubernetes/pkg/apis/core"
	podhelpers "k8s.io/kubernetes/pkg/apis/core/pods"
	"k8s.io/kubernetes/pkg/securitycontext"

	securityv1 "github.com/openshift/api/security/v1"
	sccapi "github.com/openshift/apiserver-library-go/pkg/securitycontextconstraints/api"
	"github.com/openshift/apiserver-library-go/pkg/securitycontextconstraints/capabilities"
	"github.com/openshift/apiserver-library-go/pkg/securitycontextconstraints/group"
	"github.com/openshift/apiserver-library-go/pkg/securitycontextconstraints/seccomp"
	"github.com/openshift/apiserver-library-go/pkg/securitycontextconstraints/selinux"
	"github.com/openshift/apiserver-library-go/pkg/securitycontextconstraints/sysctl"
	"github.com/openshift/apiserver-library-go/pkg/securitycontextconstraints/user"
	sccutil "github.com/openshift/apiserver-library-go/pkg/securitycontextconstraints/util"
)

// used to pass in the field being validated for reusable group strategies so they
// can create informative error messages.
const (
	fsGroupField            = "fsGroup"
	supplementalGroupsField = "supplementalGroups"
)

// simpleProvider is the default implementation of SecurityContextConstraintsProvider
type simpleProvider struct {
	scc                       *securityv1.SecurityContextConstraints
	runAsUserStrategy         user.RunAsUserSecurityContextConstraintsStrategy
	seLinuxStrategy           selinux.SELinuxSecurityContextConstraintsStrategy
	fsGroupStrategy           group.GroupSecurityContextConstraintsStrategy
	supplementalGroupStrategy group.GroupSecurityContextConstraintsStrategy
	capabilitiesStrategy      capabilities.CapabilitiesSecurityContextConstraintsStrategy
	seccompStrategy           seccomp.SeccompStrategy
	sysctlsStrategy           sysctl.SysctlsStrategy

	podValidators       []sccapi.PodSecurityValidator
	containerValidators []sccapi.ContainerSecurityValidator
}

// ensure we implement the interface correctly.
var _ SecurityContextConstraintsProvider = &simpleProvider{}

// NewSimpleProvider creates a new SecurityContextConstraintsProvider instance.
func NewSimpleProvider(scc *securityv1.SecurityContextConstraints) (*simpleProvider, error) {
	if scc == nil {
		return nil, fmt.Errorf("NewSimpleProvider requires a SecurityContextConstraint")
	}

	var err error
	provider := &simpleProvider{
		scc: scc,
		podValidators: []sccapi.PodSecurityValidator{
			NewPodBoolChecker(getPodHostPID, "hostPID", scc.AllowHostPID, "Host PID is not allowed to be used"),
			NewPodBoolChecker(getPodHostNetwork, "hostNetwork", scc.AllowHostNetwork, "Host network is not allowed to be used"),
			NewPodBoolChecker(getPodHostIPC, "hostIPC", scc.AllowHostIPC, "Host IPC is not allowed to be used"),
		},
		containerValidators: []sccapi.ContainerSecurityValidator{
			checkPrivileged(scc.AllowPrivilegedContainer),
			checkReadOnlyFileSystem(scc.ReadOnlyRootFilesystem),
			checkAllowPrivilegeEscalation(scc.AllowPrivilegeEscalation),
		},
	}

	provider.runAsUserStrategy, err = user.CreateUserStrategy(&scc.RunAsUser)
	if err != nil {
		return nil, err
	}
	provider.containerValidators = append(provider.containerValidators, provider.runAsUserStrategy)

	provider.seLinuxStrategy, err = selinux.CreateSELinuxStrategy(&scc.SELinuxContext)
	if err != nil {
		return nil, err
	}
	provider.podValidators = append(provider.podValidators, provider.seLinuxStrategy)
	provider.containerValidators = append(provider.containerValidators, provider.seLinuxStrategy)

	provider.fsGroupStrategy, err = createFSGroupStrategy(&scc.FSGroup)
	if err != nil {
		return nil, err
	}
	provider.podValidators = append(provider.podValidators, provider.fsGroupStrategy)

	provider.supplementalGroupStrategy, err = createSupplementalGroupStrategy(&scc.SupplementalGroups)
	if err != nil {
		return nil, err
	}
	provider.podValidators = append(provider.podValidators, provider.supplementalGroupStrategy)

	provider.capabilitiesStrategy, err = capabilities.NewDefaultCapabilities(scc.DefaultAddCapabilities, scc.RequiredDropCapabilities, scc.AllowedCapabilities)
	if err != nil {
		return nil, err
	}
	provider.containerValidators = append(provider.containerValidators, provider.capabilitiesStrategy)

	// Seccomp strategy is special. We should get rid of the annotations ASAP.
	provider.seccompStrategy = seccomp.NewSeccompStrategy(scc.SeccompProfiles)

	// Sysctls are not available in the generic pod accessor
	provider.sysctlsStrategy = sysctl.NewMustMatchPatterns(sysctl.SafeSysctlAllowlist(), scc.AllowedUnsafeSysctls, scc.ForbiddenSysctls)

	return provider, nil
}

func (s *simpleProvider) ApplyToPod(pod *api.Pod) field.ErrorList {
	// AssignSecurityContext creates a security context for each container in the pod
	// and validates that the sc falls within the scc constraints.  All containers must validate against
	// the same scc or is not considered valid.
	errs := field.ErrorList{}

	fldPath := field.NewPath("spec")
	psc, generatedAnnotations, err := s.createPodSecurityContext(pod)
	if err != nil {
		errs = append(errs, field.Invalid(fldPath.Child("securityContext"), pod.Spec.SecurityContext, err.Error()))
	}

	pod.Spec.SecurityContext = psc
	pod.Annotations = generatedAnnotations
	errs = append(errs, s.validatePodSecurityContext(pod, fldPath.Child("securityContext"))...)

	podhelpers.VisitContainersWithPath(&pod.Spec, fldPath, func(container *api.Container, path *field.Path) bool {
		errs = append(errs, s.assignContainerSecurityContext(pod, container, path)...)
		return true
	})

	if len(errs) > 0 {
		return errs
	}

	return nil
}

func (s *simpleProvider) assignContainerSecurityContext(pod *api.Pod, container *api.Container, fldPath *field.Path) field.ErrorList {
	errs := field.ErrorList{}
	sc, err := s.createContainerSecurityContext(pod, container)
	if err != nil {
		errs = append(errs, field.Invalid(fldPath, "", err.Error()))
		return errs
	}
	container.SecurityContext = sc
	errs = append(errs, s.validateContainerSecurityContext(pod, container, fldPath)...)

	if len(errs) > 0 {
		return errs
	}

	return nil
}

// Create a PodSecurityContext based on the given constraints.  If a setting is already set
// on the PodSecurityContext it will not be changed.  Validate should be used after the context
// is created to ensure it complies with the required restrictions.
func (s *simpleProvider) createPodSecurityContext(pod *api.Pod) (*api.PodSecurityContext, map[string]string, error) {
	sc := securitycontext.NewPodSecurityContextMutator(pod.Spec.SecurityContext)

	annotationsCopy := copySS(pod.Annotations)

	if sc.SupplementalGroups() == nil {
		supGroups, err := s.supplementalGroupStrategy.Generate(pod)
		if err != nil {
			return nil, nil, err
		}
		sc.SetSupplementalGroups(supGroups)
	}

	if sc.FSGroup() == nil {
		fsGroup, err := s.fsGroupStrategy.GenerateSingle(pod)
		if err != nil {
			return nil, nil, err
		}
		sc.SetFSGroup(fsGroup)
	}

	if sc.SELinuxOptions() == nil {
		seLinux, err := s.seLinuxStrategy.Generate(pod, nil)
		if err != nil {
			return nil, nil, err
		}
		sc.SetSELinuxOptions(seLinux)
	}

	// This is only generated on the pod level.  Containers inherit the pod's profile.  If the
	// container has a specific profile set then it will be caught in the validation step.
	seccompProfile, err := s.seccompStrategy.Generate(pod.Annotations, pod)
	if err != nil {
		return nil, nil, err
	}
	if seccompProfile != "" {
		if annotationsCopy == nil {
			annotationsCopy = map[string]string{}
		}
		annotationsCopy[api.SeccompPodAnnotationKey] = seccompProfile
		sc.SetSeccompProfile(seccompFieldForAnnotation(seccompProfile))
	}

	return sc.PodSecurityContext(), annotationsCopy, nil
}

// Create a SecurityContext based on the given constraints.  If a setting is already set on the
// container's security context then it will not be changed.  Validation should be used after
// the context is created to ensure it complies with the required restrictions.
func (s *simpleProvider) createContainerSecurityContext(pod *api.Pod, container *api.Container) (*api.SecurityContext, error) {
	sc := securitycontext.NewEffectiveContainerSecurityContextMutator(
		securitycontext.NewPodSecurityContextAccessor(pod.Spec.SecurityContext),
		securitycontext.NewContainerSecurityContextMutator(container.SecurityContext),
	)
	if sc.RunAsUser() == nil {
		uid, err := s.runAsUserStrategy.Generate(pod, container)
		if err != nil {
			return nil, err
		}
		sc.SetRunAsUser(uid)
	}

	if sc.SELinuxOptions() == nil {
		seLinux, err := s.seLinuxStrategy.Generate(pod, container)
		if err != nil {
			return nil, err
		}
		sc.SetSELinuxOptions(seLinux)
	}

	// if we're using the non-root strategy set the marker that this container should not be
	// run as root which will signal to the kubelet to do a final check either on the runAsUser
	// or, if runAsUser is not set, the image
	// Alternatively, also set the RunAsNonRoot to true in case the UID value is non-nil and non-zero
	// to more easily satisfy the requirements of upstream PodSecurity admission "restricted" profile
	// which currently requires all containers to have runAsNonRoot set to true, or to have this set
	// in the whole pod's security context
	if sc.RunAsNonRoot() == nil {
		nonRoot := false
		switch runAsUser := sc.RunAsUser(); {
		case runAsUser == nil:
			if s.scc.RunAsUser.Type == securityv1.RunAsUserStrategyMustRunAsNonRoot {
				nonRoot = true
			}
		case *runAsUser > 0:
			nonRoot = true
		}

		if nonRoot {
			sc.SetRunAsNonRoot(&nonRoot)
		}
	}

	caps, err := s.capabilitiesStrategy.Generate(pod, container)
	if err != nil {
		return nil, err
	}
	sc.SetCapabilities(caps)

	// if the SCC requires a read only root filesystem and the container has not made a specific
	// request then default ReadOnlyRootFilesystem to true.
	if s.scc.ReadOnlyRootFilesystem && sc.ReadOnlyRootFilesystem() == nil {
		readOnlyRootFS := true
		sc.SetReadOnlyRootFilesystem(&readOnlyRootFS)
	}

	isPrivileged := sc.Privileged() != nil && *sc.Privileged()
	addCapSysAdmin := false
	if caps != nil {
		for _, cap := range caps.Add {
			if string(cap) == "CAP_SYS_ADMIN" {
				addCapSysAdmin = true
				break
			}
		}
	}

	containerSeccomp, ok := pod.Annotations[api.SeccompContainerAnnotationKeyPrefix+container.Name]
	if ok {
		sc.SetSeccompProfile(seccompFieldForAnnotation(containerSeccomp))
	}

	// if the SCC sets DefaultAllowPrivilegeEscalation and the container security context
	// allowPrivilegeEscalation is not set, then default to that set by the SCC.
	//
	// Exception: privileged pods and CAP_SYS_ADMIN capability
	//
	// This corresponds to Kube's pod validation:
	//
	//     if sc.AllowPrivilegeEscalation != nil && !*sc.AllowPrivilegeEscalation {
	//        if sc.Privileged != nil && *sc.Privileged {
	//            allErrs = append(allErrs, field.Invalid(fldPath, sc, "cannot set `allowPrivilegeEscalation` to false and `privileged` to true"))
	//        }
	//
	//        if sc.Capabilities != nil {
	//            for _, cap := range sc.Capabilities.Add {
	//                if string(cap) == "CAP_SYS_ADMIN" {
	//                    allErrs = append(allErrs, field.Invalid(fldPath, sc, "cannot set `allowPrivilegeEscalation` to false and `capabilities.Add` CAP_SYS_ADMIN"))
	//                }
	//            }
	//        }
	//    }
	if s.scc.DefaultAllowPrivilegeEscalation != nil && sc.AllowPrivilegeEscalation() == nil && !isPrivileged && !addCapSysAdmin {
		sc.SetAllowPrivilegeEscalation(s.scc.DefaultAllowPrivilegeEscalation)
	}

	// if the SCC sets AllowPrivilegeEscalation to false set that as the default
	if s.scc.AllowPrivilegeEscalation != nil && !*s.scc.AllowPrivilegeEscalation && sc.AllowPrivilegeEscalation() == nil {
		sc.SetAllowPrivilegeEscalation(s.scc.AllowPrivilegeEscalation)
	}

	return sc.ContainerSecurityContext(), nil
}

// Ensure a pod's SecurityContext is in compliance with the given constraints.
func (s *simpleProvider) validatePodSecurityContext(pod *api.Pod, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	sc := securitycontext.NewPodSecurityContextAccessor(pod.Spec.SecurityContext)

	for _, validator := range s.podValidators {
		allErrs = append(allErrs, validator.ValidatePod(fldPath, sc)...)
	}

	allErrs = append(allErrs, s.seccompStrategy.ValidatePod(pod)...)
	allErrs = append(allErrs, s.sysctlsStrategy.Validate(pod)...)

	if len(pod.Spec.Volumes) > 0 && !sccutil.SCCAllowsAllVolumes(s.scc) {
		allowedVolumes := sccutil.FSTypeToStringSetInternal(s.scc.Volumes)
		for i, v := range pod.Spec.Volumes {
			fsType, err := sccutil.GetVolumeFSType(v)
			if err != nil {
				allErrs = append(allErrs, field.Invalid(field.NewPath("spec", "volumes").Index(i), string(fsType), err.Error()))
				continue
			}

			if !allowsVolumeType(allowedVolumes, fsType, v.VolumeSource) {
				allErrs = append(allErrs, field.Invalid(
					field.NewPath("spec", "volumes").Index(i), string(fsType),
					fmt.Sprintf("%s volumes are not allowed to be used", string(fsType))))
			}
		}
	}

	if len(pod.Spec.Volumes) > 0 && len(s.scc.AllowedFlexVolumes) > 0 && sccutil.SCCAllowsFSTypeInternal(s.scc, securityv1.FSTypeFlexVolume) {
		for i, v := range pod.Spec.Volumes {
			if v.FlexVolume == nil {
				continue
			}

			found := false
			driver := v.FlexVolume.Driver
			for _, allowedFlexVolume := range s.scc.AllowedFlexVolumes {
				if driver == allowedFlexVolume.Driver {
					found = true
					break
				}
			}
			if !found {
				allErrs = append(allErrs,
					field.Invalid(fldPath.Child("volumes").Index(i).Child("driver"), driver,
						"Flexvolume driver is not allowed to be used"))
			}
		}
	}

	return allErrs
}

// Ensure a container's SecurityContext is in compliance with the given constraints
func (s *simpleProvider) validateContainerSecurityContext(pod *api.Pod, container *api.Container, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	podSC := securitycontext.NewPodSecurityContextAccessor(pod.Spec.SecurityContext)
	sc := securitycontext.NewEffectiveContainerSecurityContextAccessor(podSC, securitycontext.NewContainerSecurityContextMutator(container.SecurityContext))

	for _, validator := range s.containerValidators {
		allErrs = append(allErrs, validator.ValidateContainer(fldPath, sc)...)
	}
	allErrs = append(allErrs, s.seccompStrategy.ValidateContainer(pod, container)...)

	if !s.scc.AllowHostPorts {
		allErrs = append(allErrs, s.hasHostPort(container, fldPath)...)
	}

	return allErrs
}

// hasHostPort checks the port definitions on the container for HostPort > 0.
func (s *simpleProvider) hasHostPort(container *api.Container, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	for _, cp := range container.Ports {
		if cp.HostPort > 0 {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("hostPort"), cp.HostPort, "Host ports are not allowed to be used"))
		}
	}
	return allErrs
}

func (s *simpleProvider) GetSCC() *securityv1.SecurityContextConstraints {
	return s.scc
}

// Get the name of the SCC that this provider was initialized with.
func (s *simpleProvider) GetSCCName() string {
	return s.scc.Name
}

func (s *simpleProvider) GetSCCUsers() []string {
	return s.scc.Users
}

func (s *simpleProvider) GetSCCGroups() []string {
	return s.scc.Groups
}

// createFSGroupStrategy creates a new fsgroup strategy
func createFSGroupStrategy(opts *securityv1.FSGroupStrategyOptions) (group.GroupSecurityContextConstraintsStrategy, error) {
	switch opts.Type {
	case securityv1.FSGroupStrategyRunAsAny:
		return group.NewRunAsAny()
	case securityv1.FSGroupStrategyMustRunAs:
		return group.NewMustRunAs(opts.Ranges, fsGroupField, getFSGroups)
	default:
		return nil, fmt.Errorf("Unrecognized FSGroup strategy type %s", opts.Type)
	}
}

func getFSGroups(podSC securitycontext.PodSecurityContextAccessor) []int64 {
	if fsGroup := podSC.FSGroup(); fsGroup != nil {
		return []int64{*fsGroup}
	}
	return nil
}

// createSupplementalGroupStrategy creates a new supplemental group strategy
func createSupplementalGroupStrategy(opts *securityv1.SupplementalGroupsStrategyOptions) (group.GroupSecurityContextConstraintsStrategy, error) {
	switch opts.Type {
	case securityv1.SupplementalGroupsStrategyRunAsAny:
		return group.NewRunAsAny()
	case securityv1.SupplementalGroupsStrategyMustRunAs:
		return group.NewMustRunAs(opts.Ranges, supplementalGroupsField, getSupplementalGroups)
	default:
		return nil, fmt.Errorf("Unrecognized SupplementalGroups strategy type %s", opts.Type)
	}
}

func getSupplementalGroups(podSC securitycontext.PodSecurityContextAccessor) []int64 {
	return podSC.SupplementalGroups()

}

// allowsVolumeType determines whether the type and volume are valid
// given the volumes allowed by an scc.
//
// This function was derived from a psp function of the same name in
// pkg/security/podsecuritypolicy/provider.go and updated for scc
// compatibility.
func allowsVolumeType(allowedVolumes sets.String, fsType securityv1.FSType, volumeSource api.VolumeSource) bool {
	if allowedVolumes.Has(string(fsType)) {
		return true
	}

	// If secret volumes are allowed by the scc, allow the projected
	// volume sources that bound service account token volumes expose.
	return allowedVolumes.Has(string(securityv1.FSTypeSecret)) &&
		fsType == securityv1.FSProjected &&
		sccutil.IsOnlyServiceAccountTokenSources(volumeSource.Projected)
}

// seccompFieldForAnnotation takes a pod annotation and returns the converted
// seccomp profile field.
// SeccompAnnotations removal is planned for Kube 1.27, remove this logic afterwards
func seccompFieldForAnnotation(annotation string) *api.SeccompProfile {
	// If only seccomp annotations are specified, copy the values into the
	// corresponding fields. This ensures that existing applications continue
	// to enforce seccomp, and prevents the kubelet from needing to resolve
	// annotations & fields.
	if annotation == corev1.SeccompProfileNameUnconfined {
		return &api.SeccompProfile{Type: api.SeccompProfileTypeUnconfined}
	}

	if annotation == api.SeccompProfileRuntimeDefault || annotation == api.DeprecatedSeccompProfileDockerDefault {
		return &api.SeccompProfile{Type: api.SeccompProfileTypeRuntimeDefault}
	}

	if strings.HasPrefix(annotation, corev1.SeccompLocalhostProfileNamePrefix) {
		localhostProfile := strings.TrimPrefix(annotation, corev1.SeccompLocalhostProfileNamePrefix)
		if localhostProfile != "" {
			return &api.SeccompProfile{
				Type:             api.SeccompProfileTypeLocalhost,
				LocalhostProfile: &localhostProfile,
			}
		}
	}

	// we can only reach this code path if the localhostProfile name has a zero
	// length or if the annotation has an unrecognized value
	return nil
}

// CopySS makes a shallow copy of a map.
func copySS(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	copy := make(map[string]string, len(m))
	for k, v := range m {
		copy[k] = v
	}
	return copy
}
