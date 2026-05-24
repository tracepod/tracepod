//go:build linux

package container

import "testing"

func TestResolveCgroupPath_systemd(t *testing.T) {
	// systemd cgroup driver format: produced by containerd with SystemdCgroup=true.
	// Seen in kind (containerd v2+), kubeadm, EKS AL2023, GKE COS, etc.
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "besteffort pod",
			raw:  "kubelet-kubepods-besteffort-podabc123_def456.slice:cri-containerd:ctr0011",
			want: "/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice" +
				"/kubelet-kubepods-besteffort.slice" +
				"/kubelet-kubepods-besteffort-podabc123_def456.slice" +
				"/cri-containerd-ctr0011.scope",
		},
		{
			name: "burstable pod",
			raw:  "kubelet-kubepods-burstable-podxyz789.slice:cri-containerd:ctr0022",
			want: "/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice" +
				"/kubelet-kubepods-burstable.slice" +
				"/kubelet-kubepods-burstable-podxyz789.slice" +
				"/cri-containerd-ctr0022.scope",
		},
		{
			name: "guaranteed pod (no QoS subdir)",
			raw:  "kubelet-kubepods-podguaranteed123.slice:cri-containerd:ctr0033",
			want: "/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice" +
				"/kubelet-kubepods-podguaranteed123.slice" +
				"/cri-containerd-ctr0033.scope",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveCgroupPath(tc.raw)
			if got != tc.want {
				t.Errorf("resolveCgroupPath(%q):\n  got  %q\n  want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestResolveCgroupPath_ociAbsolute(t *testing.T) {
	// OCI/cgroupfs: already absolute under /sys/fs/cgroup — returned unchanged.
	raw := "/sys/fs/cgroup/kubepods/besteffort/podabc/ctr0"
	got := resolveCgroupPath(raw)
	if got != raw {
		t.Errorf("resolveCgroupPath(%q) = %q; want unchanged", raw, got)
	}
}

func TestResolveCgroupPath_ociRelative(t *testing.T) {
	// OCI/cgroupfs: relative path gets prefixed with /sys/fs/cgroup.
	got := resolveCgroupPath("kubepods/besteffort/podabc/ctr0")
	want := "/sys/fs/cgroup/kubepods/besteffort/podabc/ctr0"
	if got != want {
		t.Errorf("resolveCgroupPath: got %q, want %q", got, want)
	}
}

func TestResolveCgroupPath_ociAbsoluteSlash(t *testing.T) {
	// OCI/cgroupfs: absolute path starting with "/" but not the cgroupRoot prefix.
	got := resolveCgroupPath("/kubepods/besteffort/podabc/ctr0")
	want := "/sys/fs/cgroup/kubepods/besteffort/podabc/ctr0"
	if got != want {
		t.Errorf("resolveCgroupPath: got %q, want %q", got, want)
	}
}

func TestExpandSystemdCgroupPath(t *testing.T) {
	got := expandSystemdCgroupPath(
		"kubelet-kubepods-besteffort-podabc123.slice",
		"cri-containerd",
		"deadbeef",
	)
	want := "/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice" +
		"/kubelet-kubepods-besteffort.slice" +
		"/kubelet-kubepods-besteffort-podabc123.slice" +
		"/cri-containerd-deadbeef.scope"
	if got != want {
		t.Errorf("expandSystemdCgroupPath:\n  got  %q\n  want %q", got, want)
	}
}
