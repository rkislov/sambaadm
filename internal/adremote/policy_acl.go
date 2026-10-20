package adremote

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type SecurityBytes []byte

func (b SecurityBytes) Size() int         { return len(b) }
func (b SecurityBytes) Encode(dst []byte) { copy(dst, b) }

// PolicyFileACL translates a fresh directory GPO ACL into inheritable SYSVOL
// rights. Unsupported ACEs fail closed instead of silently dropping restrictions.
func PolicyFileACL(sd []byte) (SecurityBytes, error) {
	bad := fmt.Errorf("unsupported or malformed GPO security descriptor")
	if len(sd) < 20 || sd[0] != 1 {
		return nil, bad
	}
	le := binary.LittleEndian
	sidAt := func(off uint32) ([]byte, error) {
		if off == 0 {
			return nil, nil
		}
		if uint64(off)+8 > uint64(len(sd)) {
			return nil, bad
		}
		size := 8 + 4*int(sd[off+1])
		if uint64(off)+uint64(size) > uint64(len(sd)) {
			return nil, bad
		}
		return sd[int(off) : int(off)+size], nil
	}
	owner, e := sidAt(le.Uint32(sd[4:8]))
	if e != nil {
		return nil, e
	}
	group, e := sidAt(le.Uint32(sd[8:12]))
	if e != nil {
		return nil, e
	}
	offset := int(le.Uint32(sd[16:20]))
	if offset < 20 || offset+8 > len(sd) {
		return nil, bad
	}
	size := int(le.Uint16(sd[offset+2:]))
	if size < 8 || offset+size > len(sd) {
		return nil, bad
	}
	count := int(le.Uint16(sd[offset+4:]))
	acl := []byte{4, 0, 0, 0, 0, 0, 0, 0}
	kept := 0
	pos := offset + 8
	for i := 0; i < count; i++ {
		if pos+8 > offset+size {
			return nil, bad
		}
		n := int(le.Uint16(sd[pos+2:]))
		if n < 8 || pos+n > offset+size {
			return nil, bad
		}
		ace := append([]byte(nil), sd[pos:pos+n]...)
		pos += n
		sidOffset := 8
		switch ace[0] {
		case 0:
		case 5:
			if n < 12 {
				return nil, bad
			}
			sidOffset = 12
			flags := le.Uint32(ace[8:])
			if flags&1 != 0 {
				sidOffset += 16
			}
			if flags&2 != 0 {
				sidOffset += 16
			}
		default:
			return nil, bad
		}
		if sidOffset+8 > len(ace) {
			return nil, bad
		}
		sid := ace[sidOffset:]
		if len(sid) != 8+4*int(sid[1]) {
			return nil, bad
		}
		// Pre-Windows 2000 Compatible Access does not grant SYSVOL rights.
		if bytes.Equal(sid, []byte{1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 42, 2, 0, 0}) {
			continue
		}
		mask := le.Uint32(ace[4:])
		fileMask := mask & 0x1f0000
		if mask&0x14 == 0x14 {
			fileMask |= 0x1000a9
		}
		if mask&0x20 != 0 {
			fileMask |= 0x100116
		}
		if mask&1 != 0 {
			fileMask |= 6
		}
		if mask&2 != 0 {
			fileMask |= 0x40
		}
		le.PutUint32(ace[4:], fileMask)
		ace[1] |= 3
		if bytes.Equal(sid, []byte{1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0}) {
			ace[1] |= 8
		}
		acl = append(acl, ace...)
		kept++
	}
	if kept == 0 || len(acl) > 65535 {
		return nil, bad
	}
	le.PutUint16(acl[2:], uint16(len(acl)))
	le.PutUint16(acl[4:], uint16(kept))
	out := make([]byte, 20)
	out[0] = 1
	le.PutUint16(out[2:], 0x9004)
	if len(owner) > 0 {
		le.PutUint32(out[4:], uint32(len(out)))
		out = append(out, owner...)
	}
	if len(group) > 0 {
		le.PutUint32(out[8:], uint32(len(out)))
		out = append(out, group...)
	}
	le.PutUint32(out[16:], uint32(len(out)))
	out = append(out, acl...)
	return out, nil
}
