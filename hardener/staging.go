package hardener

import (
	"archive/tar"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// The staging tree is a working copy of the source image filesystem that the
// hardener reads (ELF resolver, runtime companions, directory inclusion,
// inventory, package scan). It is not a faithful copy: the hardener may run
// as an unprivileged user, which cannot read a file whose mode denies it
// (/etc/shadow is 0000 on RHEL-family images), cannot create entries in a
// directory without owner write and search (/root is 0550), cannot set
// security.* extended attributes and cannot create device nodes. So staged
// files always get owner read+write, staged directories owner rwx, device
// nodes and fifos are empty placeholder files, and extended attributes are
// never applied to disk.
//
// The real metadata of every staged path is kept from the source layer's tar
// header in a stagingMeta and the layer writer takes mode, ownership, mtime,
// type, device numbers and extended attributes from there, never from lstat
// of the staged copy. Root and non-root builds therefore produce the same
// layer.

// srcMeta is the source-layer metadata of one staged path.
type srcMeta struct {
	Typeflag           byte // TypeReg, TypeDir, TypeSymlink, TypeChar, TypeBlock or TypeFifo
	Mode               int64
	Uid, Gid           int
	Uname, Gname       string
	ModTime            time.Time
	Devmajor, Devminor int64
	// Xattrs holds the extended-attribute PAX records of the header
	// (SCHILY.xattr.*, LIBARCHIVE.xattr.*), e.g. security.capability.
	Xattrs map[string]string
}

// stagingMeta maps the canonical in-image path of every staged entry
// ("/"-rooted, cleaned, no trailing slash) to its source metadata. The last
// layer that wrote a path wins; whiteouts remove entries.
type stagingMeta map[string]*srcMeta

// xattrPAXPrefixes are the PAX record prefixes that carry extended attributes.
var xattrPAXPrefixes = []string{"SCHILY.xattr.", "LIBARCHIVE.xattr."}

// metaFromHeader captures the metadata of hdr. Hard links and any regular
// file flavour are recorded as TypeReg.
func metaFromHeader(hdr *tar.Header) *srcMeta {
	sm := &srcMeta{
		Typeflag: hdr.Typeflag,
		Mode:     hdr.Mode & 0o7777,
		Uid:      hdr.Uid,
		Gid:      hdr.Gid,
		Uname:    hdr.Uname,
		Gname:    hdr.Gname,
		ModTime:  hdr.ModTime,
		Devmajor: hdr.Devmajor,
		Devminor: hdr.Devminor,
	}
	switch hdr.Typeflag {
	case tar.TypeDir, tar.TypeSymlink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
	default:
		sm.Typeflag = tar.TypeReg
	}
	if sm.Typeflag != tar.TypeChar && sm.Typeflag != tar.TypeBlock {
		sm.Devmajor, sm.Devminor = 0, 0
	}
	for k, v := range hdr.PAXRecords {
		for _, p := range xattrPAXPrefixes {
			if strings.HasPrefix(k, p) {
				if sm.Xattrs == nil {
					sm.Xattrs = make(map[string]string)
				}
				sm.Xattrs[k] = v
			}
		}
	}
	return sm
}

// header returns a tar header named name with typeflag typ and every other
// field taken from sm.
func (sm *srcMeta) header(typ byte, name string) *tar.Header {
	h := &tar.Header{
		Typeflag: typ,
		Name:     name,
		Mode:     sm.Mode,
		Uid:      sm.Uid,
		Gid:      sm.Gid,
		Uname:    sm.Uname,
		Gname:    sm.Gname,
		ModTime:  sm.ModTime,
	}
	if typ == tar.TypeChar || typ == tar.TypeBlock {
		h.Devmajor, h.Devminor = sm.Devmajor, sm.Devminor
	}
	if len(sm.Xattrs) > 0 {
		h.PAXRecords = make(map[string]string, len(sm.Xattrs))
		for k, v := range sm.Xattrs {
			h.PAXRecords[k] = v
		}
	}
	return h
}

// isSpecial reports whether sm describes a device node or fifo, which is
// staged as an empty placeholder file and written from metadata only.
func (sm *srcMeta) isSpecial() bool {
	return sm != nil && (sm.Typeflag == tar.TypeChar || sm.Typeflag == tar.TypeBlock || sm.Typeflag == tar.TypeFifo)
}

// lookup returns the metadata of the staged host path hostPath, or nil.
func (sm stagingMeta) lookup(stagingDir, hostPath string) *srcMeta {
	if sm == nil {
		return nil
	}
	rel, err := filepath.Rel(stagingDir, hostPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil
	}
	return sm[path.Clean("/"+filepath.ToSlash(rel))]
}

// forget removes p and, when descendants is true, every path beneath it.
func (sm stagingMeta) forget(p string, descendants bool) {
	if sm == nil {
		return
	}
	delete(sm, p)
	if !descendants {
		return
	}
	prefix := strings.TrimSuffix(p, "/") + "/"
	for k := range sm {
		if strings.HasPrefix(k, prefix) {
			delete(sm, k)
		}
	}
}

// stagedFileMode is the on-disk mode of a staged regular file (or placeholder):
// the source permission bits plus owner read+write, without setuid, setgid or
// sticky (the staged copy is never executed by the hardener).
func stagedFileMode(mode int64) os.FileMode {
	return os.FileMode(mode&0o777) | 0o600
}

// stagedDirMode is the on-disk mode of a staged directory: the source
// permission bits plus owner rwx, so entries can be created in it and it can
// be listed, traversed and removed without privileges.
func stagedDirMode(mode int64) os.FileMode {
	return os.FileMode(mode&0o777) | 0o700
}
