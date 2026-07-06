// Package manifest defines the file observation schema written by the sensor
// after profiling a container. Each container produces a profiles/<id>/files.json
// that downstream tools (image factory, AppArmor generator, coverage scorer) consume.
//
// Schema versioning: the profile document carries a top-level integer
// schema_version (see SchemaVersion). Any change to the wire shape of the profile
// — adding/removing/retyping a field, or changing the semantics of an existing
// field — REQUIRES bumping SchemaVersion and committing a new JSON Schema file
// under docs/profile-schema/. The sensor only ever emits the current version.
// See docs/profile-schema/README.md for the full policy and field reference.
package manifest

import "time"

// SchemaVersion is the profile schema version the sensor currently emits.
//
//   - v1 (legacy, string "1"): pre-versioned file-observation manifest. Carried a
//     string schema_version, no coverage markers, no start-event records.
//   - v2 (integer 2): adds the Coverage block (R2 process-start marker,
//     attach/first-exec timestamps) and the ContainerStarts records (R3). The
//     schema_version field changed type from string to integer at this bump.
//   - v3 (current, integer 3): adds the EventLoss block (top-level event_loss) —
//     per-window event-loss counters so a consumer can refuse "not observed ⇒
//     not loaded" claims from a lossy observation window. No v2 field semantics
//     changed.
//
// Consumers MUST treat any profile lacking an integer schema_version (i.e. the
// legacy string "1" form, or no field at all) as a legacy v1 profile.
const SchemaVersion = 3

// ObservationSource describes how a file was included in the manifest.
// Every FileEntry carries exactly one source. The source is the foundation of
// confidence scoring and AppArmor file-rule generation.
type ObservationSource string

const (
	// SourceDirect means the path appeared in a BPF openat event during profiling.
	// Highest trust — the file was directly observed at runtime.
	SourceDirect ObservationSource = "direct"

	// SourceInferredELF means the path was resolved as a shared library dependency
	// of a direct ELF binary via readelf/ld.so.conf.
	// High trust — necessary for dynamic linking, but depends on resolver correctness.
	SourceInferredELF ObservationSource = "inferred-elf"

	// SourceDirectoryInclusion means the file's parent directory had a direct hit
	// and safe-mode expansion included all directory contents.
	// Medium trust — conservative, may over-include.
	SourceDirectoryInclusion ObservationSource = "directory-inclusion"

	// SourceInferredRuntime means the path was added by a language-runtime
	// companion rule rather than observed directly. Interpreters can prove a
	// file is required without ever open(2)-ing it — CPython stats a module's
	// .py source and then loads only the cached __pycache__/*.pyc, yet refuses
	// that pyc at runtime when the sibling source is missing. Such files never
	// appear as openat events, so the hardener infers them from the files that
	// were observed. High trust — each rule is deterministic and only adds
	// paths that exist in the source image.
	SourceInferredRuntime ObservationSource = "inferred-runtime"

	// SourceManual means the operator explicitly added this path via config or CLI.
	SourceManual ObservationSource = "manual"

	// SourceEnsureDir means an empty directory was explicitly declared by the operator
	// to exist in the hardened image, even if absent from the source image.
	// Written as a tar.TypeDir entry in the OCI layer. Corresponds to --mkdir / type:"directory".
	SourceEnsureDir ObservationSource = "ensure-dir"

	// SourceEnsureFile means an empty file (0 bytes) was explicitly declared by the
	// operator. Written as a tar.TypeReg entry only if the path is absent from the
	// source image. Corresponds to --touch / type:"file" when the file doesn't exist.
	SourceEnsureFile ObservationSource = "ensure-file"
)

// AccessMode records the file-access type observed at the openat call.
// Multiple modes may be set on a single FileEntry if the file was opened
// with different modes across separate opens.
type AccessMode string

const (
	AccessRead    AccessMode = "r" // O_RDONLY or O_RDWR
	AccessWrite   AccessMode = "w" // O_WRONLY or O_RDWR or O_APPEND
	AccessExecute AccessMode = "x" // via execve kprobe
	AccessLink    AccessMode = "l" // hardlink / rename observed
	AccessMmap    AccessMode = "m" // mmap with PROT_EXEC
)

// FileEntry is a single file in the manifest. The map key in Manifest.Files
// is the file's absolute path.
type FileEntry struct {
	Source      ObservationSource `json:"source"`
	AccessModes []AccessMode      `json:"access_modes"` // observed open flags
	FirstSeen   time.Time         `json:"first_seen"`
	LastSeen    time.Time         `json:"last_seen"`
	Count       uint64            `json:"count"` // 0 for inferred-elf and directory-inclusion entries

	// Audit trail — only set for non-direct sources.
	InferredFrom    string `json:"inferred_from,omitempty"`    // source=inferred-elf: the ELF binary that required this .so; source=inferred-runtime: the observed file that implied this one
	IncludedBecause string `json:"included_because,omitempty"` // source=directory-inclusion: the direct hit that triggered expansion
}

// StartEvent records a single container start the sensor witnessed during the
// profiling window (R3). Each (re)start the sensor observes appends one record,
// so a consumer can count full restarts within the window as
// len(ContainerStarts)-1 for a profile, summing across the profiles emitted for
// a workload for cross-window restart totals.
//
// The sensor only records starts it actually witnessed via the NRI
// StartContainer hook — it does not infer or judge. A start the sensor missed
// (e.g. a container that was already running before the sensor attached) does
// not appear here; that gap is surfaced instead by Coverage.ProcessStartObserved.
type StartEvent struct {
	ContainerID string    `json:"container_id"`
	Timestamp   time.Time `json:"timestamp"`
}

// Coverage carries the per-container coverage markers a downstream coverage
// scorer needs (schema v2+). The sensor records the raw signals; it does not
// score or interpret them.
type Coverage struct {
	// ProcessStartObserved (R2) is true only when the sensor can demonstrate it
	// observed the container's main process from its first exec — i.e. its cgroup
	// attachment won the NRI startup race (docs/known-limitations.md §1).
	//
	// It is set true ONLY when all of the following hold:
	//   1. the sensor recorded its attach (cgroup added to the BPF allowlist);
	//   2. the container was NOT already running when the sensor attached — i.e.
	//      the sensor learned of it via the NRI StartContainer hook (attaching
	//      before the runtime started the workload), not by adopting an
	//      already-running container at sensor startup (NRI Synchronize), whose
	//      first exec was dropped in-kernel before the sensor attached;
	//   3. the sensor observed at least one exec for the container; and
	//   4. the recorded attach time strictly precedes the first observed exec.
	//
	// Any uncertainty resolves to false: a missing attach record, a container
	// adopted already-running, no observed exec, or non-strict ordering all
	// yield false. A false marker tells the consumer that startup code paths are
	// systematically missing from this profile. A wrongly-true marker would
	// poison every downstream coverage claim, so the bias is deliberate and
	// toward false.
	ProcessStartObserved bool `json:"process_start_observed"`

	// AttachTime is when the sensor added the container's cgroup to the BPF
	// allowlist (the earliest instant any event from this container could be
	// observed). Zero value if the sensor never recorded an attach.
	AttachTime time.Time `json:"attach_time"`

	// FirstExecTime is the timestamp of the first exec event the sensor observed
	// for the container. Nil when no exec was observed during the window.
	FirstExecTime *time.Time `json:"first_exec_time,omitempty"`
}

// Manifest is the file observation record for one container profiling run.
// Written to profiles/<container-id>/files.json by the sensor on StopContainer
// (standalone mode) or POSTed to the controller (DaemonSet mode).
//
// All timestamps (ProfileStart/End, FileEntry.First/LastSeen, StartEvent and
// Coverage times) are UTC RFC 3339 with nanosecond resolution (R4). They are
// sourced from the sensor host's wall clock (time.Now) at event-processing time,
// so they are suitable for bucketing into intervals but are NOT guaranteed
// strictly monotonic across events: wall-clock adjustments can move them
// backwards. Consumers computing first-seen-unique-path curves should bucket at
// second resolution or coarser and tolerate small non-monotonicities.
type Manifest struct {
	SchemaVersion int       `json:"schema_version"`
	ContainerID   string    `json:"container_id"`
	ImageRef      string    `json:"image_ref,omitempty"`
	ProfileStart  time.Time `json:"profile_start"`
	ProfileEnd    time.Time `json:"profile_end"`

	// Coverage holds the v2 coverage markers (R2). Always present.
	Coverage Coverage `json:"coverage"`

	// ContainerStarts lists the container starts the sensor witnessed during the
	// window (R3), in observation order. Always present; never nil (empty slice
	// when the sensor witnessed no start, e.g. a synthesised/legacy aggregator).
	ContainerStarts []StartEvent `json:"container_starts"`

	// EventLoss carries the v3 per-window event-loss counters. Always present.
	// total==0 is a positive claim ("instrumented everywhere, lost nothing");
	// any nonzero total taints "not observed ⇒ not loaded" conclusions for the
	// whole window. See EventLoss and docs/profile-schema/README.md.
	EventLoss EventLoss `json:"event_loss"`

	Files map[string]FileEntry `json:"files"` // keyed by absolute path
}
