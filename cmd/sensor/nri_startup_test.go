//go:build linux

package main

import "testing"

// TestNRIFailureIsFatal covers the fatal-vs-warn decision made when
// plugin.Start() fails: outside --cgroup-path mode NRI is the sensor's only
// discovery mechanism, so a failure there must be fatal; --cgroup-path mode
// never depends on NRI, so it keeps warning and continuing.
func TestNRIFailureIsFatal(t *testing.T) {
	tests := []struct {
		name       string
		cgroupPath string
		want       bool
	}{
		{"no cgroup-path: fatal", "", true},
		{"cgroup-path set: warn only", "/sys/fs/cgroup/my-shell", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nriFailureIsFatal(tt.cgroupPath); got != tt.want {
				t.Errorf("nriFailureIsFatal(%q) = %v, want %v", tt.cgroupPath, got, tt.want)
			}
		})
	}
}
