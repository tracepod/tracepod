// Package manifest defines the file observation schema written by the sensor
// after profiling a container. Each container produces a profiles/<id>/files.json
// that downstream tools (image factory, AppArmor generator) consume.
package manifest

import "time"

// ObservationSource describes how a file was included in the manifest.
// Every FileEntry carries exactly one source. The source is the foundation of
// confidence scoring in M6 and AppArmor file-rule generation in M9.
type ObservationSource string

const (
	// SourceDirect means the path appeared in a BPF openat event during profiling.
	// Highest trust — the file was directly observed at runtime.
	SourceDirect ObservationSource = "direct"

	// SourceInferredELF means the path was resolved as a shared library dependency
	// of a direct ELF binary via readelf/ld.so.conf. Added by the ELF resolver in M4–5.
	// High trust — necessary for dynamic linking, but depends on resolver correctness.
	SourceInferredELF ObservationSource = "inferred-elf"

	// SourceDirectoryInclusion means the file's parent directory had a direct hit
	// and safe-mode expansion included all directory contents. Added in M6.
	// Medium trust — conservative, may over-include.
	SourceDirectoryInclusion ObservationSource = "directory-inclusion"

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
	AccessExecute AccessMode = "x" // via execve (added when execve kprobe lands in M9)
	AccessLink    AccessMode = "l" // hardlink / rename observed
	AccessMmap    AccessMode = "m" // mmap with PROT_EXEC (future)
)

// FileEntry is a single file in the manifest. The map key in Manifest.Files
// is the file's absolute path.
type FileEntry struct {
	Source      ObservationSource `json:"source"`
	AccessModes []AccessMode      `json:"access_modes"` // observed open flags; used by image factory and M9 AppArmor generator
	FirstSeen   time.Time         `json:"first_seen"`
	LastSeen    time.Time         `json:"last_seen"`
	Count       uint64            `json:"count"` // 0 for inferred-elf and directory-inclusion entries

	// Audit trail — only set for non-direct sources.
	InferredFrom    string `json:"inferred_from,omitempty"`    // source=inferred-elf: the ELF binary that required this .so
	IncludedBecause string `json:"included_because,omitempty"` // source=directory-inclusion: the direct hit that triggered expansion
}

// Manifest is the file observation record for one container profiling run.
// Written to profiles/<container-id>/files.json by the sensor on StopContainer.
//
// Syscall and AppArmor profiles are separate files written in M9:
//
//	profiles/<container-id>/
//	  files.json       — this type
//	  syscalls.json    — M9, for Seccomp profile generation
//	  apparmor.json    — M9, for AppArmor profile generation
type Manifest struct {
	SchemaVersion string               `json:"schema_version"` // always "1"
	ContainerID   string               `json:"container_id"`
	ImageRef      string               `json:"image_ref,omitempty"`
	ProfileStart  time.Time            `json:"profile_start"`
	ProfileEnd    time.Time            `json:"profile_end"`
	Files         map[string]FileEntry `json:"files"` // keyed by absolute path
}
