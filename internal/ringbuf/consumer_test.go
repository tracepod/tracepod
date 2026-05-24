package ringbuf_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	cilebpf "github.com/cilium/ebpf/ringbuf"

	"github.com/tracepod/tracepod/internal/ringbuf"
)

// mockReader implements ringbuf.Reader using a fixed slice of records.
// After all records are consumed it returns cilebpf.ErrClosed.
type mockReader struct {
	records []cilebpf.Record
	pos     int
}

func (m *mockReader) Read() (cilebpf.Record, error) {
	if m.pos >= len(m.records) {
		return cilebpf.Record{}, cilebpf.ErrClosed
	}
	r := m.records[m.pos]
	m.pos++
	return r, nil
}

func (m *mockReader) Close() error { return nil }

// makeRecord constructs a raw ring buffer record from the given fields.
// eventType should be one of ringbuf.EventTypeOpenat / EventTypeExecve / EventTypeMmap.
// interp is the interpreter path for execve events; pass "" for others.
func makeRecord(eventType uint32, pid uint32, cgroupID uint64, flagsOrProt uint64, comm, filename, interp string) cilebpf.Record {
	var e ringbuf.Event
	e.Type = eventType
	e.Pid = pid
	e.CgroupID = cgroupID
	e.FlagsOrProt = flagsOrProt
	copy(e.Comm[:], comm)
	copy(e.Filename[:], filename)
	copy(e.Interp[:], interp)

	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, e)
	return cilebpf.Record{RawSample: buf.Bytes()}
}

const (
	flagRDONLY uint64 = 0
	flagRDWR   uint64 = 2
)

func TestRun_dispatchesOpenatEvents(t *testing.T) {
	rd := &mockReader{records: []cilebpf.Record{
		makeRecord(ringbuf.EventTypeOpenat, 1234, 4026532156, flagRDONLY, "nginx", "/etc/nginx/nginx.conf", ""),
		makeRecord(ringbuf.EventTypeOpenat, 5678, 4026532200, flagRDWR, "redis-server", "/var/lib/redis/dump.rdb", ""),
	}}

	var got []ringbuf.Event
	c := ringbuf.New(rd, func(e ringbuf.Event) { got = append(got, e) })

	if err := c.Run(); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("got %d events, want 2", len(got))
	}

	if got[0].Type != ringbuf.EventTypeOpenat {
		t.Errorf("event[0].Type: got %d, want EventTypeOpenat", got[0].Type)
	}
	if got[0].Pid != 1234 {
		t.Errorf("event[0].Pid: got %d, want 1234", got[0].Pid)
	}
	if got[0].CgroupID != 4026532156 {
		t.Errorf("event[0].CgroupID: got %d, want 4026532156", got[0].CgroupID)
	}
	if got[0].FlagsOrProt != flagRDONLY {
		t.Errorf("event[0].FlagsOrProt: got %d, want %d", got[0].FlagsOrProt, flagRDONLY)
	}
	if got[0].Path() != "/etc/nginx/nginx.conf" {
		t.Errorf("event[0].Path(): got %q, want /etc/nginx/nginx.conf", got[0].Path())
	}
	if got[0].Process() != "nginx" {
		t.Errorf("event[0].Process(): got %q, want nginx", got[0].Process())
	}

	if got[1].Path() != "/var/lib/redis/dump.rdb" {
		t.Errorf("event[1].Path(): got %q, want /var/lib/redis/dump.rdb", got[1].Path())
	}
	if got[1].FlagsOrProt != flagRDWR {
		t.Errorf("event[1].FlagsOrProt: got %d, want %d", got[1].FlagsOrProt, flagRDWR)
	}
}

func TestRun_dispatchesExecveEvent(t *testing.T) {
	rd := &mockReader{records: []cilebpf.Record{
		// Native ELF binary: interp == filename
		makeRecord(ringbuf.EventTypeExecve, 100, 4026532156, 0, "nginx", "/usr/sbin/nginx", "/usr/sbin/nginx"),
		// Python script: interp is the interpreter, filename is the script
		makeRecord(ringbuf.EventTypeExecve, 101, 4026532156, 0, "python3", "/app/server.py", "/usr/bin/python3"),
	}}

	var got []ringbuf.Event
	c := ringbuf.New(rd, func(e ringbuf.Event) { got = append(got, e) })

	if err := c.Run(); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2", len(got))
	}

	if got[0].Type != ringbuf.EventTypeExecve {
		t.Errorf("event[0].Type: got %d, want EventTypeExecve", got[0].Type)
	}
	if got[0].Path() != "/usr/sbin/nginx" {
		t.Errorf("event[0].Path(): got %q, want /usr/sbin/nginx", got[0].Path())
	}
	if got[0].InterpPath() != "/usr/sbin/nginx" {
		t.Errorf("event[0].InterpPath(): got %q, want /usr/sbin/nginx", got[0].InterpPath())
	}

	if got[1].Path() != "/app/server.py" {
		t.Errorf("event[1].Path(): got %q, want /app/server.py", got[1].Path())
	}
	if got[1].InterpPath() != "/usr/bin/python3" {
		t.Errorf("event[1].InterpPath(): got %q, want /usr/bin/python3", got[1].InterpPath())
	}
}

func TestRun_dispatchesMmapEvent(t *testing.T) {
	const vmFlagsExec uint64 = 0x4 // VM_EXEC
	rd := &mockReader{records: []cilebpf.Record{
		makeRecord(ringbuf.EventTypeMmap, 200, 4026532156, vmFlagsExec, "nginx", "libz.so.1", ""),
	}}

	var got []ringbuf.Event
	c := ringbuf.New(rd, func(e ringbuf.Event) { got = append(got, e) })

	if err := c.Run(); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if got[0].Type != ringbuf.EventTypeMmap {
		t.Errorf("event[0].Type: got %d, want EventTypeMmap", got[0].Type)
	}
	if got[0].Path() != "libz.so.1" {
		t.Errorf("event[0].Path(): got %q, want libz.so.1", got[0].Path())
	}
	if got[0].FlagsOrProt != vmFlagsExec {
		t.Errorf("event[0].FlagsOrProt: got %d, want %d", got[0].FlagsOrProt, vmFlagsExec)
	}
}

func TestRun_skipsMalformedRecord(t *testing.T) {
	rd := &mockReader{records: []cilebpf.Record{
		{RawSample: []byte{0x01, 0x02}}, // too short — must be skipped
		makeRecord(ringbuf.EventTypeOpenat, 42, 4026532100, flagRDONLY, "cat", "/etc/passwd", ""),
	}}

	var got []ringbuf.Event
	c := ringbuf.New(rd, func(e ringbuf.Event) { got = append(got, e) })

	if err := c.Run(); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if got[0].Path() != "/etc/passwd" {
		t.Errorf("got path %q, want /etc/passwd", got[0].Path())
	}
	if got[0].Pid != 42 {
		t.Errorf("got pid %d, want 42", got[0].Pid)
	}
}

func TestRun_emptyReaderReturnsNil(t *testing.T) {
	rd := &mockReader{}
	c := ringbuf.New(rd, func(ringbuf.Event) { t.Error("unexpected handler call") })
	if err := c.Run(); err != nil {
		t.Fatalf("Run returned error on empty reader: %v", err)
	}
}
