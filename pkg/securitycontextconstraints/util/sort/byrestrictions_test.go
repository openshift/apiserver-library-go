package sort

import (
	"math/rand"
	"testing"

	corev1 "k8s.io/api/core/v1"

	securityv1 "github.com/openshift/api/security/v1"
)

func TestPointValue(t *testing.T) {
	newSCC := func(priv bool, seLinuxStrategy securityv1.SELinuxContextStrategyType, userStrategy securityv1.RunAsUserStrategyType) *securityv1.SecurityContextConstraints {
		return &securityv1.SecurityContextConstraints{
			AllowPrivilegedContainer: priv,
			SELinuxContext: securityv1.SELinuxContextStrategyOptions{
				Type: seLinuxStrategy,
			},
			RunAsUser: securityv1.RunAsUserStrategyOptions{
				Type: userStrategy,
			},
		}
	}

	seLinuxStrategies := map[securityv1.SELinuxContextStrategyType]points{
		securityv1.SELinuxStrategyRunAsAny:  runAsAnyUserPoints,
		securityv1.SELinuxStrategyMustRunAs: runAsUserPoints,
	}
	userStrategies := map[securityv1.RunAsUserStrategyType]points{
		securityv1.RunAsUserStrategyRunAsAny:         runAsAnyUserPoints,
		securityv1.RunAsUserStrategyMustRunAsNonRoot: runAsNonRootPoints,
		securityv1.RunAsUserStrategyMustRunAsRange:   runAsRangePoints,
		securityv1.RunAsUserStrategyMustRunAs:        runAsUserPoints,
	}

	// run through all combos of user strategy + seLinux strategy + priv
	for userStrategy, userStrategyPoints := range userStrategies {
		for seLinuxStrategy, seLinuxStrategyPoints := range seLinuxStrategies {
			expectedPoints := privilegedPoints + userStrategyPoints + seLinuxStrategyPoints + capDefaultPoints
			scc := newSCC(true, seLinuxStrategy, userStrategy)
			actualPoints := pointValue(scc)

			if actualPoints != expectedPoints {
				t.Errorf("privileged, user: %v, seLinux %v expected %d score but got %d", userStrategy, seLinuxStrategy, expectedPoints, actualPoints)
			}

			expectedPoints = userStrategyPoints + seLinuxStrategyPoints + capDefaultPoints
			scc = newSCC(false, seLinuxStrategy, userStrategy)
			actualPoints = pointValue(scc)

			if actualPoints != expectedPoints {
				t.Errorf("non privileged, user: %v, seLinux %v expected %d score but got %d", userStrategy, seLinuxStrategy, expectedPoints, actualPoints)
			}
		}
	}

	// sanity check to ensure volume and capabilities scores are added (specific volumes
	// and capabilities scores are tested below)
	scc := newSCC(false, securityv1.SELinuxStrategyMustRunAs, securityv1.RunAsUserStrategyMustRunAs)
	scc.Volumes = []securityv1.FSType{securityv1.FSTypeHostPath}
	actualPoints := pointValue(scc)
	// SELinux + User + host path volume + default capabilities
	expectedPoints := runAsUserPoints + runAsUserPoints + hostVolumePoints + capDefaultPoints
	if actualPoints != expectedPoints {
		t.Errorf("volume score was not added to the scc point value correctly, got %d!", actualPoints)
	}
}

func TestVolumePointValue(t *testing.T) {
	newSCC := func(host, nonTrivial, trivial bool) *securityv1.SecurityContextConstraints {
		volumes := []securityv1.FSType{}
		if host {
			volumes = append(volumes, securityv1.FSTypeHostPath)
		}
		if nonTrivial {
			volumes = append(volumes, securityv1.FSTypeAWSElasticBlockStore)
		}
		if trivial {
			volumes = append(volumes, securityv1.FSTypeSecret)
		}
		return &securityv1.SecurityContextConstraints{
			Volumes: volumes,
		}
	}

	allowAllSCC := &securityv1.SecurityContextConstraints{
		Volumes: []securityv1.FSType{securityv1.FSTypeAll},
	}
	nilVolumeSCC := &securityv1.SecurityContextConstraints{}

	tests := map[string]struct {
		scc            *securityv1.SecurityContextConstraints
		expectedPoints points
	}{
		"all volumes": {
			scc:            allowAllSCC,
			expectedPoints: hostVolumePoints,
		},
		"host volume": {
			scc:            newSCC(true, false, false),
			expectedPoints: hostVolumePoints,
		},
		"host volume and non trivial volumes": {
			scc:            newSCC(true, true, false),
			expectedPoints: hostVolumePoints,
		},
		"host volume, non trivial, and trivial": {
			scc:            newSCC(true, true, true),
			expectedPoints: hostVolumePoints,
		},
		"non trivial": {
			scc:            newSCC(false, true, false),
			expectedPoints: nonTrivialVolumePoints,
		},
		"non trivial and trivial": {
			scc:            newSCC(false, true, true),
			expectedPoints: nonTrivialVolumePoints,
		},
		"trivial": {
			scc:            newSCC(false, false, true),
			expectedPoints: noPoints,
		},
		"trivial - secret": {
			scc: &securityv1.SecurityContextConstraints{
				Volumes: []securityv1.FSType{securityv1.FSTypeSecret},
			},
			expectedPoints: noPoints,
		},
		"trivial - configMap": {
			scc: &securityv1.SecurityContextConstraints{
				Volumes: []securityv1.FSType{securityv1.FSTypeConfigMap},
			},
			expectedPoints: noPoints,
		},
		"trivial - emptyDir": {
			scc: &securityv1.SecurityContextConstraints{
				Volumes: []securityv1.FSType{securityv1.FSTypeEmptyDir},
			},
			expectedPoints: noPoints,
		},
		"trivial - downwardAPI": {
			scc: &securityv1.SecurityContextConstraints{
				Volumes: []securityv1.FSType{securityv1.FSTypeDownwardAPI},
			},
			expectedPoints: noPoints,
		},
		"trivial - projected": {
			scc: &securityv1.SecurityContextConstraints{
				Volumes: []securityv1.FSType{securityv1.FSProjected},
			},
			expectedPoints: noPoints,
		},
		"trivial - none": {
			scc: &securityv1.SecurityContextConstraints{
				Volumes: []securityv1.FSType{securityv1.FSTypeNone},
			},
			expectedPoints: noPoints,
		},
		"no volumes allowed": {
			scc:            newSCC(false, false, false),
			expectedPoints: noPoints,
		},
		"nil volumes": {
			scc:            nilVolumeSCC,
			expectedPoints: noPoints,
		},
	}
	for k, v := range tests {
		actualPoints := volumePointValue(v.scc)
		if actualPoints != v.expectedPoints {
			t.Errorf("%s expected %d volume score but got %d", k, v.expectedPoints, actualPoints)
		}
	}
}

func TestCapabilitiesPointValue(t *testing.T) {
	newSCC := func(def []corev1.Capability, allow []corev1.Capability, drop []corev1.Capability) *securityv1.SecurityContextConstraints {
		return &securityv1.SecurityContextConstraints{
			DefaultAddCapabilities:   def,
			AllowedCapabilities:      allow,
			RequiredDropCapabilities: drop,
		}
	}

	tests := map[string]struct {
		defaultAdd     []corev1.Capability
		allowed        []corev1.Capability
		requiredDrop   []corev1.Capability
		expectedPoints points
	}{
		"nothing specified": {
			defaultAdd:     nil,
			allowed:        nil,
			requiredDrop:   nil,
			expectedPoints: capDefaultPoints,
		},
		"default": {
			defaultAdd:     []corev1.Capability{"KILL", "MKNOD"},
			allowed:        nil,
			requiredDrop:   nil,
			expectedPoints: capDefaultPoints + 2*capAddOnePoints,
		},
		"allow": {
			defaultAdd:     nil,
			allowed:        []corev1.Capability{"KILL", "MKNOD"},
			requiredDrop:   nil,
			expectedPoints: capDefaultPoints + 2*capAllowOnePoints,
		},
		"allow star": {
			defaultAdd:     nil,
			allowed:        []corev1.Capability{"*"},
			requiredDrop:   nil,
			expectedPoints: capDefaultPoints + capAllowAllPoints,
		},
		"allow all": {
			defaultAdd:     nil,
			allowed:        []corev1.Capability{"ALL"},
			requiredDrop:   nil,
			expectedPoints: capDefaultPoints + capAllowAllPoints,
		},
		"allow all case": {
			defaultAdd:     nil,
			allowed:        []corev1.Capability{"All"},
			requiredDrop:   nil,
			expectedPoints: capDefaultPoints + capAllowAllPoints,
		},
		"drop": {
			defaultAdd:     nil,
			allowed:        nil,
			requiredDrop:   []corev1.Capability{"KILL", "MKNOD"},
			expectedPoints: capDefaultPoints + 2*capDropOnePoints,
		},
		"drop all": {
			defaultAdd:     nil,
			allowed:        nil,
			requiredDrop:   []corev1.Capability{"ALL"},
			expectedPoints: capDefaultPoints + capDropAllPoints,
		},
		"drop all case": {
			defaultAdd:     nil,
			allowed:        nil,
			requiredDrop:   []corev1.Capability{"all"},
			expectedPoints: capDefaultPoints + capDropAllPoints,
		},
		"drop star": {
			defaultAdd:     nil,
			allowed:        nil,
			requiredDrop:   []corev1.Capability{"*"},
			expectedPoints: capDefaultPoints + capDropOnePoints,
		},
		"mixture": {
			defaultAdd:     []corev1.Capability{"SETUID", "SETGID"},
			allowed:        []corev1.Capability{"*"},
			requiredDrop:   []corev1.Capability{"SYS_CHROOT"},
			expectedPoints: capDefaultPoints + 2*capAddOnePoints + capAllowAllPoints + capDropOnePoints,
		},
	}
	for k, v := range tests {
		scc := newSCC(v.defaultAdd, v.allowed, v.requiredDrop)
		actualPoints := capabilitiesPointValue(scc)
		if actualPoints != v.expectedPoints {
			t.Errorf("%s expected %d capability score but got %d", k, v.expectedPoints, actualPoints)
		}
	}
}

func TestMoreRestrictiveReason(t *testing.T) {
	orderedSubScorers := []struct {
		test            string
		expectedMessage string
		nonZeroScore    func() points
	}{
		{"privileged", "forbids privileged", func() points { return privilegedPoints }},
		{"host ports", "forbids host ports", func() points { return hostPortsPoints }},
		{"host network", "forbids host networking", func() points { return hostNetworkPoints }},
		{"host volumes", "forbids host volume mounts", func() points { return hostVolumePoints }},
		{"non-trivial mounts", "forbids non-trivial volume mounts", func() points { return nonTrivialVolumePoints }},
		{"selinux", "permits less runAs strategies", func() points {
			switch rand.Intn(4) {
			case 0:
				return runAsAnyUserPoints
			case 1:
				return runAsNonRootPoints
			case 2:
				return runAsRangePoints
			default:
				return runAsUserPoints
			}
		}},
		{"runasuser", "permits less runAs strategies", func() points {
			switch rand.Intn(4) {
			case 0:
				return runAsAnyUserPoints
			case 1:
				return runAsNonRootPoints
			case 2:
				return runAsRangePoints
			default:
				return runAsUserPoints
			}
		}},
		{"caps", "permits less capabilities", func() points {
			return points(1 + rand.Intn(9999))
		}},
	}

	nonZeroScore := func(i, j int) points {
		var p points
		for x := i; x < j; x++ {
			if rand.Intn(2) == 1 {
				p += orderedSubScorers[x].nonZeroScore()
			}
		}
		return p
	}

	for i, s := range orderedSubScorers {
		t.Run(s.test, func(t *testing.T) {
			for n := 0; n < 1000; n++ {
				above := nonZeroScore(0, i)

				a := s.nonZeroScore()
				b := s.nonZeroScore()
				if a > b {
					a, b = b, a
				}

				below1 := nonZeroScore(i+1, len(orderedSubScorers))
				below2 := nonZeroScore(i+1, len(orderedSubScorers))
				if below1 > below2 {
					below1, below2 = below2, below1
				}

				p, q := above+below1, above+a+below2
				if got, expected := moreRestrictiveReason(p, q), s.expectedMessage; got != expected {
					t.Errorf("for %d < %d got %q, expected %q", p, q, got, expected)
				}

				if a < b {
					p, q := above+a+below1, above+b+below2
					if got, expected := moreRestrictiveReason(p, q), s.expectedMessage; got != expected {
						t.Errorf("for %d < %d got %q, expected %q", p, q, got, expected)
					}
				}
			}
		})
	}
}
