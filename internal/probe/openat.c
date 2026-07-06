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
#define EVENT_STAT    4

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

/* Event-loss counters (schema v3). A per-CPU array so increments are lock-free
 * and loss-proof: each CPU bumps its own slot, userspace sums across CPUs at
 * profile finalisation. Two distinct loss classes are counted here:
 *   STAT_RESERVE_FAILED   — bpf_ringbuf_reserve() returned NULL (ring full): the
 *                           primary buffer-pressure loss point, across all probes.
 *                           A HARD loss — counted toward event_loss.total.
 *   STAT_PATH_READ_FAILED — bpf_probe_read_user_str() faulted on the openat
 *                           filename pointer (e.g. the user page is not yet
 *                           present): the reservation succeeded but the path was
 *                           unreadable, so the open went unidentified. A TOLERATED
 *                           loss — a counted observation lost with a known
 *                           load-independent idle floor (0–2 per container). It is
 *                           reported in event_loss.tolerated, separately gated by
 *                           the consumer, and NEVER folded into total (folding it
 *                           in would put a permanent floor under the strict-zero
 *                           gate on hard losses and defeat it). See
 *                           manifest/eventloss.go and docs/profile-schema/README.md.
 *
 * Both are counted in-kernel — userspace never sees a reservation that never
 * happened, nor a discard the kernel performed. Keep these indices in sync with
 * the Go reader in probe.go (lossStatIndex). */
#define STAT_RESERVE_FAILED   0
#define STAT_PATH_READ_FAILED 1
#define STAT_MAX              2

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, STAT_MAX);
} event_loss_stats SEC(".maps");

/* stat_inc bumps a per-CPU loss counter. The lookup of a fixed key in a
 * preallocated PERCPU_ARRAY cannot fail, so counting is itself loss-proof. */
static __always_inline void stat_inc(__u32 idx)
{
	__u64 *c = bpf_map_lookup_elem(&event_loss_stats, &idx);
	if (c)
		(*c)++;
}

/* Userspace populates this map with the cgroup IDs of containers being
 * profiled. The kprobe discards events for any cgroup not in this map.
 * Key: cgroup ID (u64). Value: u8 sentinel (always 1). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, 1024);
} allowed_cgroups SEC(".maps");

/* kprobe/do_sys_openat2 fires at the kernel's unified open handler, called
 * for both openat(2) and openat2(2). The raw user-space filename string is
 * captured as provided by the caller — absolute paths ("/usr/lib/libc.so")
 * are emitted directly; relative paths ("app.rb", "config.yml") are emitted
 * as-is and resolved in the userspace router via /proc/<pid>/cwd.
 *
 * We do not use bpf_d_path here because it cannot resolve paths for files in
 * overlayfs containers: file->f_path.dentry points to the underlying layer
 * dentry which is not visible in the calling process's mount namespace, so
 * d_path() consistently returns errors in containerised overlay2 environments.
 *
 * The userspace resolver reads /proc/<pid>/cwd to obtain the container
 * process's CWD and reconstructs the absolute path there.  Because the sensor
 * processes ring-buffer events while the emitting process is still in the
 * syscall, the /proc entry is guaranteed to be valid at resolution time. */
SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(kprobe_openat, int dfd, const char *filename,
               struct open_how *how)
{
	/* Filter early: only emit events for cgroups the userspace plugin has
	 * allowed.  Kernel threads and host processes are in the root cgroup
	 * and will not be in allowed_cgroups. */
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	__u8 *allowed = bpf_map_lookup_elem(&allowed_cgroups, &cgroup_id);
	if (!allowed)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_RESERVE_FAILED);
		return 0;
	}

	e->type = EVENT_OPENAT;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->cgroup_id = cgroup_id;
	/* Read open flags from the kernel-space open_how struct.
	 * The access mode bits (O_RDONLY/O_WRONLY/O_RDWR) and O_APPEND have the
	 * same values as the user-space open(2) flags. */
	e->flags_or_prot = BPF_CORE_READ(how, flags);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	long n = bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);
	if (n <= 0) {
		/* Filename pointer unreadable (e.g. page not yet present). The reservation
		 * succeeded but the path could not be read, so the open goes unidentified
		 * — a lost observation. This is a path-read fault, a different class from a
		 * capacity/transport drop: it has a known load-independent idle floor, so
		 * it is counted as a TOLERATED loss (event_loss.tolerated.path_read_failed)
		 * and never folded into total. See the STAT_* note above. */
		stat_inc(STAT_PATH_READ_FAILED);
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	e->interp[0] = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* kprobe/vfs_fstatat — the kernel's unified fstatat handler, reached by the
 * stat/lstat/fstatat/newfstatat family (glibc and musl stat() both land here
 * on modern kernels). The filename argument is the raw USER-space pointer —
 * vfs_fstatat performs getname() internally — so the capture mirrors the
 * openat probe exactly, including the tolerated path-read-fault accounting.
 *
 * Why trace stats at all: interpreters prove files are required without ever
 * opening them. CPython stats a module's .py source and then loads only the
 * cached pyc; an image built from open observations alone cannot boot. The
 * probe is attached only when the sensor runs with --trace-stat (see
 * probe.Options.TraceStat) — stat volume is much higher than open volume, and
 * the schema-v3 event-loss counters make any resulting ring-buffer pressure
 * visible rather than silent.
 *
 * statx(2) does NOT pass through vfs_fstatat on all kernel versions; it is a
 * documented follow-up (KNOWN-LIMITATIONS §6). */
SEC("kprobe/vfs_fstatat")
int BPF_KPROBE(kprobe_stat, int dfd, const char *filename)
{
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	__u8 *allowed = bpf_map_lookup_elem(&allowed_cgroups, &cgroup_id);
	if (!allowed)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_RESERVE_FAILED);
		return 0;
	}

	e->type = EVENT_STAT;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->cgroup_id = cgroup_id;
	e->flags_or_prot = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	long n = bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);
	if (n <= 0) {
		stat_inc(STAT_PATH_READ_FAILED);
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
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
	if (!e) {
		stat_inc(STAT_RESERVE_FAILED);
		return 0;
	}

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
	if (!e) {
		stat_inc(STAT_RESERVE_FAILED);
		return 0;
	}

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
