//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define NAME_MAX      255

/* PROT_EXEC — mmap protection flag passed by userspace.
 * asm-generic/mman-common.h: #define PROT_EXEC 0x4 */
#define PROT_EXEC 0x4

/* Event type discriminator — tells the Go consumer which kprobe fired. */
#define EVENT_OPENAT  1
#define EVENT_EXECVE  2
#define EVENT_MMAP    3

struct event {
	__u32 type;              /* offset   0 — EVENT_OPENAT / EXECVE / MMAP */
	__u32 pid;               /* offset   4 */
	__u64 cgroup_id;         /* offset   8 */
	__u64 flags_or_prot;     /* offset  16 — openat: open_how.flags; mmap: vm_flags; execve: 0 */
	char  comm[TASK_COMM_LEN];    /* offset  24 */
	char  filename[NAME_MAX + 1]; /* offset  40 — binary path for execve/mmap; opened path for openat */
	char  interp[NAME_MAX + 1];   /* offset 296 — execve: script interpreter path; else empty */
	/* total: 552 bytes */
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18); /* 256 KB */
} events SEC(".maps");

/* Userspace populates this map with the cgroup IDs of containers being
 * profiled. The kprobe discards events for any cgroup not in this map.
 * Key: cgroup ID (u64). Value: u8 sentinel (always 1). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, 1024);
} allowed_cgroups SEC(".maps");

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(kprobe_openat, int dfd, const char *filename,
               struct open_how *how)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	/* Filter: only emit events for cgroups the userspace plugin has allowed. */
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	__u8 *allowed = bpf_map_lookup_elem(&allowed_cgroups, &cgroup_id);
	if (!allowed) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	e->type = EVENT_OPENAT;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->cgroup_id = cgroup_id;
	e->flags_or_prot = BPF_CORE_READ_USER(how, flags);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);
	e->interp[0] = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* security_bprm_check — called after prepare_binprm() has fully populated
 * linux_binprm. At this point bprm->filename is the binary path and
 * bprm->interp is the script interpreter (e.g. /usr/bin/python3 for a
 * #!/usr/bin/python3 script). For native ELF binaries interp == filename.
 *
 * We use this hook instead of do_execveat_common because bprm is not yet
 * allocated at do_execveat_common entry, making field access unsafe there. */
SEC("kprobe/security_bprm_check")
int BPF_KPROBE(kprobe_execve, struct linux_binprm *bprm)
{
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	__u8 *allowed = bpf_map_lookup_elem(&allowed_cgroups, &cgroup_id);
	if (!allowed)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_EXECVE;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->cgroup_id = cgroup_id;
	e->flags_or_prot = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* bprm->filename: the binary being exec'd */
	const char *fname = BPF_CORE_READ(bprm, filename);
	bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fname);

	/* bprm->interp: the interpreter (equals filename for ELF binaries) */
	const char *interp = BPF_CORE_READ(bprm, interp);
	bpf_probe_read_kernel_str(e->interp, sizeof(e->interp), interp);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* security_mmap_file — LSM hook called on every file-backed mmap(2) before
 * the mapping is created. Filters on PROT_EXEC and drops anonymous mappings.
 *
 * Path note: kprobe programs cannot use bpf_d_path() (requires LSM or iter
 * program type). We read the filename component only (d_name.name), which
 * gives the basename such as "libc.so.6". The Go handler correlates this
 * basename against paths already recorded by the openat probe — every file
 * mmap'd PROT_EXEC was opened via openat first by the dynamic linker, so
 * the full path is guaranteed to exist in the manifest before the mmap fires.
 * The handler merges the AccessMmap mode into the matching entry by suffix. */
SEC("kprobe/security_mmap_file")
int BPF_KPROBE(kprobe_mmap, struct file *file, unsigned long prot,
               unsigned long flags)
{
	if (!file)
		return 0;
	if (!(prot & PROT_EXEC))
		return 0;

	__u64 cgroup_id = bpf_get_current_cgroup_id();
	__u8 *allowed = bpf_map_lookup_elem(&allowed_cgroups, &cgroup_id);
	if (!allowed)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_MMAP;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->cgroup_id = cgroup_id;
	e->flags_or_prot = prot;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Read the filename component from the dentry. This is the basename only
	 * (e.g. "libc.so.6"), not the full path — see path note above. */
	const unsigned char *name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
	bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), name);
	e->interp[0] = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
