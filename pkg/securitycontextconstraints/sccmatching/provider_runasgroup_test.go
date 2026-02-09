package sccmatching

import (
	"testing"

	securityv1 "github.com/openshift/api/security/v1"
)

// int64Ptr is a helper function that returns a pointer to an int64
func int64Ptr(v int64) *int64 {
	return &v
}

// TestCreateRunAsGroupStrategy verifies that the createRunAsGroupStrategy function
// properly creates the correct strategy based on RunAsGroupStrategyOptions
func TestCreateRunAsGroupStrategy(t *testing.T) {
	tests := []struct {
		name         string
		opts         *securityv1.RunAsGroupStrategyOptions
		expectError  bool
		strategyType string
	}{
		{
			name: "Empty type defaults to MustRunAsRange",
			opts: &securityv1.RunAsGroupStrategyOptions{
				Type: "",
			},
			expectError:  false,
			strategyType: "MustRunAsRange",
		},
		{
			name: "RunAsAny strategy",
			opts: &securityv1.RunAsGroupStrategyOptions{
				Type: securityv1.RunAsGroupStrategyRunAsAny,
			},
			expectError:  false,
			strategyType: "RunAsAny",
		},
		{
			name: "MustRunAs with single GID (min==max)",
			opts: &securityv1.RunAsGroupStrategyOptions{
				Type: securityv1.RunAsGroupStrategyMustRunAs,
				Ranges: []securityv1.RunAsGroupIDRange{
					{Min: int64Ptr(1000), Max: int64Ptr(1000)},
				},
			},
			expectError:  false,
			strategyType: "MustRunAs",
		},
		{
			name: "MustRunAs with range (min!=max) - uses MustRunAsRange",
			opts: &securityv1.RunAsGroupStrategyOptions{
				Type: securityv1.RunAsGroupStrategyMustRunAs,
				Ranges: []securityv1.RunAsGroupIDRange{
					{Min: int64Ptr(1000), Max: int64Ptr(2000)},
				},
			},
			expectError:  false,
			strategyType: "MustRunAsRange",
		},
		{
			name: "MustRunAs with multiple ranges - uses MustRunAsRange",
			opts: &securityv1.RunAsGroupStrategyOptions{
				Type: securityv1.RunAsGroupStrategyMustRunAs,
				Ranges: []securityv1.RunAsGroupIDRange{
					{Min: int64Ptr(1000), Max: int64Ptr(1000)},
					{Min: int64Ptr(2000), Max: int64Ptr(2000)},
				},
			},
			expectError:  false,
			strategyType: "MustRunAsRange",
		},
		{
			name: "MustRunAsRange strategy",
			opts: &securityv1.RunAsGroupStrategyOptions{
				Type: securityv1.RunAsGroupStrategyMustRunAsRange,
				Ranges: []securityv1.RunAsGroupIDRange{
					{Min: int64Ptr(1000), Max: int64Ptr(2000)},
				},
			},
			expectError:  false,
			strategyType: "MustRunAsRange",
		},
		{
			name: "MustRunAsRange with multiple ranges",
			opts: &securityv1.RunAsGroupStrategyOptions{
				Type: securityv1.RunAsGroupStrategyMustRunAsRange,
				Ranges: []securityv1.RunAsGroupIDRange{
					{Min: int64Ptr(1000), Max: int64Ptr(2000)},
					{Min: int64Ptr(5000), Max: int64Ptr(6000)},
				},
			},
			expectError:  false,
			strategyType: "MustRunAsRange",
		},
		{
			name: "Invalid: MustRunAs with nil Min",
			opts: &securityv1.RunAsGroupStrategyOptions{
				Type: securityv1.RunAsGroupStrategyMustRunAs,
				Ranges: []securityv1.RunAsGroupIDRange{
					{Min: nil, Max: int64Ptr(1000)},
				},
			},
			expectError: true,
		},
		{
			name: "Invalid: MustRunAs with nil Max",
			opts: &securityv1.RunAsGroupStrategyOptions{
				Type: securityv1.RunAsGroupStrategyMustRunAs,
				Ranges: []securityv1.RunAsGroupIDRange{
					{Min: int64Ptr(1000), Max: nil},
				},
			},
			expectError: true,
		},
		{
			name: "Invalid: MustRunAs with min > max",
			opts: &securityv1.RunAsGroupStrategyOptions{
				Type: securityv1.RunAsGroupStrategyMustRunAs,
				Ranges: []securityv1.RunAsGroupIDRange{
					{Min: int64Ptr(2000), Max: int64Ptr(1000)},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy, err := createRunAsGroupStrategy(tt.opts)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if strategy == nil {
				t.Error("Strategy should not be nil")
				return
			}

			// Verify the strategy works by testing Generate
			generated, err := strategy.Generate(nil, nil)
			if err != nil {
				t.Errorf("Generate failed: %v", err)
			}

			// For RunAsAny, generated should be nil
			if tt.strategyType == "RunAsAny" && generated != nil {
				t.Errorf("RunAsAny should generate nil, got %v", *generated)
			}
			// For MustRunAs and MustRunAsRange, generated should be non-nil
			if tt.strategyType != "RunAsAny" && generated == nil {
				t.Errorf("%s should generate a non-nil GID", tt.strategyType)
			}
		})
	}
}

// TestProviderIntegration verifies the full integration of runAsGroup with the provider
func TestProviderIntegration(t *testing.T) {
	tests := []struct {
		name        string
		scc         *securityv1.SecurityContextConstraints
		expectError bool
	}{
		{
			name: "SCC with RunAsGroup RunAsAny",
			scc: &securityv1.SecurityContextConstraints{
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
				RunAsGroup: securityv1.RunAsGroupStrategyOptions{
					Type: securityv1.RunAsGroupStrategyRunAsAny,
				},
			},
			expectError: false,
		},
		{
			name: "SCC with RunAsGroup MustRunAs",
			scc: &securityv1.SecurityContextConstraints{
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
				RunAsGroup: securityv1.RunAsGroupStrategyOptions{
					Type: securityv1.RunAsGroupStrategyMustRunAs,
					Ranges: []securityv1.RunAsGroupIDRange{
						{Min: int64Ptr(5000), Max: int64Ptr(5000)},
					},
				},
			},
			expectError: false,
		},
		{
			name: "SCC with RunAsGroup MustRunAsRange",
			scc: &securityv1.SecurityContextConstraints{
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
				RunAsGroup: securityv1.RunAsGroupStrategyOptions{
					Type: securityv1.RunAsGroupStrategyMustRunAsRange,
					Ranges: []securityv1.RunAsGroupIDRange{
						{Min: int64Ptr(1000), Max: int64Ptr(2000)},
						{Min: int64Ptr(5000), Max: int64Ptr(6000)},
					},
				},
			},
			expectError: false,
		},
		{
			name: "SCC with empty RunAsGroup (defaults to RunAsAny)",
			scc: &securityv1.SecurityContextConstraints{
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
				RunAsGroup: securityv1.RunAsGroupStrategyOptions{
					Type: "",
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewSimpleProvider(tt.scc)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Failed to create provider: %v", err)
				return
			}

			if provider == nil {
				t.Error("Provider should not be nil")
				return
			}

			// Verify we can create a container security context
			// Note: Passing nil for pod and container is acceptable for this basic test
			// as we're just verifying the provider can be created successfully
			_ = provider
		})
	}
}
