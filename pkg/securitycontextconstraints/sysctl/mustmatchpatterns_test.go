/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sysctl

import (
	"fmt"
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/util/version"
	api "k8s.io/kubernetes/pkg/apis/core"
)

func TestValidate(t *testing.T) {
	tests := map[string]struct {
		allowlist     []string
		forbiddenSafe []string
		allowedUnsafe []string
		allowed       []string
		disallowed    []string
	}{
		// no container requests
		"with allow all": {
			allowlist: []string{"foo"},
			allowed:   []string{"foo"},
		},
		"empty": {
			allowlist:     []string{"foo"},
			forbiddenSafe: []string{"*"},
			disallowed:    []string{"foo"},
		},
		"without wildcard": {
			allowlist:  []string{"a", "a.b"},
			allowed:    []string{"a", "a.b"},
			disallowed: []string{"b"},
		},
		"with catch-all wildcard and non-wildcard": {
			allowedUnsafe: []string{"a.b.c", "*"},
			allowed:       []string{"a", "a.b", "a.b.c", "b"},
		},
		"without catch-all wildcard": {
			allowedUnsafe: []string{"a.*", "b.*", "c.d.e", "d.e.f.*"},
			allowed:       []string{"a.b", "b.c", "c.d.e", "d.e.f.g.h"},
			disallowed:    []string{"a", "b", "c", "c.d", "d.e", "d.e.f"},
		},
	}

	for k, v := range tests {
		strategy := NewMustMatchPatterns(v.allowlist, v.allowedUnsafe, v.forbiddenSafe)

		pod := &api.Pod{}
		errs := strategy.Validate(pod)
		if len(errs) != 0 {
			t.Errorf("%s: unexpected validaton errors for empty sysctls: %v", k, errs)
		}

		testAllowed := func() {
			sysctls := []api.Sysctl{}
			for _, s := range v.allowed {
				sysctls = append(sysctls, api.Sysctl{
					Name:  s,
					Value: "dummy",
				})
			}
			pod.Spec.SecurityContext = &api.PodSecurityContext{
				Sysctls: sysctls,
			}
			errs = strategy.Validate(pod)
			if len(errs) != 0 {
				t.Errorf("%s: unexpected validaton errors for sysctls: %v", k, errs)
			}
		}
		testDisallowed := func() {
			for _, s := range v.disallowed {
				pod.Spec.SecurityContext = &api.PodSecurityContext{
					Sysctls: []api.Sysctl{
						{
							Name:  s,
							Value: "dummy",
						},
					},
				}
				errs = strategy.Validate(pod)
				if len(errs) == 0 {
					t.Errorf("%s: expected error for sysctl %q", k, s)
				}
			}
		}

		testAllowed()
		testDisallowed()
	}
}

func TestGetSafeSysctlAllowlist(t *testing.T) {
	var legacySafeSysctls = []string{
		"kernel.shm_rmid_forced",
		"net.ipv4.ip_local_port_range",
		"net.ipv4.tcp_syncookies",
		"net.ipv4.ping_group_range",
		"net.ipv4.ip_unprivileged_port_start",
		"net.ipv4.tcp_keepalive_time",
		"net.ipv4.tcp_fin_timeout",
		"net.ipv4.tcp_keepalive_intvl",
		"net.ipv4.tcp_keepalive_probes",
	}

	tests := []struct {
		name       string
		getVersion func() (*version.Version, error)
		want       []string
	}{
		{
			name: "failed to get kernelVersion, only return the legacy safeSysctls list",
			getVersion: func() (*version.Version, error) {
				return nil, fmt.Errorf("fork error")
			},
			want: legacySafeSysctls,
		},
		{
			name: "kernelVersion is 3.18.0, return the legacy safeSysctls list and net.ipv4.ip_local_reserved_ports",
			getVersion: func() (*version.Version, error) {
				kernelVersionStr := "3.18.0-957.27.2.el7.x86_64"
				return version.ParseGeneric(kernelVersionStr)
			},
			want: append(
				legacySafeSysctls,
				"net.ipv4.ip_local_reserved_ports",
			),
		},
		{
			name: "kernelVersion is 5.15.0, return the legacy safeSysctls list and safeSysctls with kernelVersion below 5.15.0",
			getVersion: func() (*version.Version, error) {
				kernelVersionStr := "5.15.0-75-generic"
				return version.ParseGeneric(kernelVersionStr)
			},
			want: append(
				legacySafeSysctls,
				"net.ipv4.ip_local_reserved_ports",
				"net.ipv4.tcp_rmem",
				"net.ipv4.tcp_wmem",
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getSafeSysctlAllowlist(tt.getVersion); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getSafeSysctlAllowlist() = %v, want %v", got, tt.want)
			}
		})
	}
}
