// Package ringbuf decodes events from the BPF ring buffer.
package ringbuf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	ebpfringbuf "github.com/cilium/ebpf/ringbuf"
)

// Event type constants — mirror the EVENT_* defines in openat.c.
const (
	EventTypeOpenat uint32 = 1
	EventTypeExecve uint32 = 2
	EventTypeMmap   uint32 = 3
)

// Event mirrors the BPF event struct in openat.c. Field sizes and order must
// match exactly — binary.Read deserialises raw kernel memory into this struct.
// Layout (552 bytes):
//
//	type(4) pid(4) cgroup_id(8) flags_or_prot(8) comm(16) filename(256) interp(256)
//
// NOTE: requires ./dev.sh generate after editing openat.c to recompile the BPF
// program. The generated openat_bpfel.go / openat_bpfeb.go embed the compiled
// bytecode; this struct is maintained manually to mirror the C layout.
type Event struct {
	Type        uint32   // EVENT_OPENAT / EVENT_EXECVE / EVENT_MMAP
	Pid         uint32
	CgroupID    uint64
	FlagsOrProt uint64   // openat: open_how.flags; mmap: vm_flags; execve: 0
	Comm        [16]byte
	Filename    [256]byte
	Interp      [256]byte // execve: script interpreter path; else empty
}

// Path returns the null-terminated filename from the event.
func (e Event) Path() string { return nullTerminated(e.Filename[:]) }

// Process returns the null-terminated comm (process name) from the event.
func (e Event) Process() string { return nullTerminated(e.Comm[:]) }

// InterpPath returns the null-terminated interpreter path from an execve event.
// For native ELF binaries this equals Path(). Empty for non-execve events.
func (e Event) InterpPath() string { return nullTerminated(e.Interp[:]) }

// Reader is satisfied by *ebpf/ringbuf.Reader. Declared as an interface so
// tests can inject a mock without a running kernel.
type Reader interface {
	Read() (ebpfringbuf.Record, error)
	Close() error
}

// Consumer reads raw records from a BPF ring buffer and dispatches structured events.
type Consumer struct {
	rd      Reader
	handler func(Event)
}

// New returns a Consumer. handler is called once per successfully decoded event.
// Malformed records (too short to decode) are silently skipped.
func New(rd Reader, handler func(Event)) *Consumer {
	return &Consumer{rd: rd, handler: handler}
}

// Run blocks, reading events until the reader is closed. It returns nil on a
// clean close and a non-nil error only for unrecoverable reader failures.
func (c *Consumer) Run() error {
	for {
		rec, err := c.rd.Read()
		if err != nil {
			if errors.Is(err, ebpfringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("ringbuf read: %w", err)
		}

		var e Event
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			// Malformed record — skip rather than crash.
			continue
		}

		c.handler(e)
	}
}

func nullTerminated(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
