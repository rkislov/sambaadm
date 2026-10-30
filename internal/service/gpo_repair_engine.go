package service

import (
	"context"
	"fmt"
	"os"
	"path"
	"sort"

	"github.com/google/uuid"
)

// A repairVolume exposes only the validated policy's parent directory. Temporary
// directories have unpredictable names bound to the private durable journal.
type repairVolume interface {
	Tree(string) policyStore
	Rename(string, string) error
	Mkdir(string) error
}

func repairBackup(r *RepairRecord) string  { return ".sambaadm-repair-" + r.ID + "-before" }
func repairArchive(r *RepairRecord) string { return ".sambaadm-repair-" + r.ID + "-after" }
func repairLive(r *RepairRecord) string    { return path.Base(r.Base) }
func repairMarker(r *RepairRecord) []byte {
	return []byte("sambaadm SYSVOL repair: " + r.ID + "\nUse repair recovery; do not use script recovery.\n")
}
func repairTreeState(ctx context.Context, v repairVolume, name string, r *RepairRecord) (string, error) {
	root := v.Tree(name)
	if _, e := root.Lstat("."); os.IsNotExist(e) {
		return "missing", nil
	} else if e != nil {
		return "", e
	}
	snap, e := scanPolicyTree(ctx, root, true)
	if e != nil {
		return "", e
	}
	if snap.Pending {
		b, e := readPolicyFile(root, editorJournal)
		if e != nil {
			return "", e
		}
		if string(b) != string(repairMarker(r)) {
			return "", fmt.Errorf("foreign pending journal in %s", name)
		}
	}
	return consistencyHash([]any{snap.Files, snap.GPT, false}), nil
}
func repairMark(root policyStore, r *RepairRecord) error {
	b, e := readPolicyFile(root, editorJournal)
	if e == nil {
		if string(b) == string(repairMarker(r)) {
			return nil
		}
		return ErrTopologyConflict
	}
	if !os.IsNotExist(e) {
		return e
	}
	// Publish only a fully flushed marker; an interrupted marker write must not
	// leave an unrecognizable live journal that prevents recovery.
	tmp := ".sambaadm-repair-marker-" + r.ID + "-" + uuid.NewString()
	if e := createDurablePolicyFile(root, tmp, repairMarker(r)); e != nil {
		return e
	}
	if _, e := root.Lstat(editorJournal); !os.IsNotExist(e) {
		if e != nil {
			return e
		}
		return ErrTopologyConflict
	}
	return root.Rename(tmp, editorJournal)
}
func repairUnmark(root policyStore, r *RepairRecord) error {
	b, e := readPolicyFile(root, editorJournal)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if string(b) != string(repairMarker(r)) {
		return ErrTopologyConflict
	}
	return root.Remove(editorJournal)
}
func stageRepair(ctx context.Context, v repairVolume, local *os.Root, r *RepairRecord) error {
	if r.Stage != "" {
		sig, e := repairTreeState(ctx, v, r.Stage, r)
		if e == nil && sig == r.After.Signature {
			return nil
		}
	}
	// Failed staging directories are retained, never recursively deleted. A new
	// unpredictable staging directory is journaled before any data is created.
	if r.Attempts >= 8 {
		return fmt.Errorf("staging attempt limit reached; retain journal and contact administrator")
	}
	r.Attempts++
	r.Stage = ".sambaadm-repair-" + r.ID + "-" + uuid.NewString()
	if e := saveRepair(local, r); e != nil {
		return e
	}
	if e := v.Mkdir(r.Stage); e != nil {
		return e
	}
	root := v.Tree(r.Stage)
	if e := repairMark(root, r); e != nil {
		return e
	}
	for _, o := range r.After.Objects {
		if e := ctx.Err(); e != nil {
			return e
		}
		if o.Path == "." {
			continue
		}
		if o.Directory {
			if e := root.Mkdir(o.Path, 0700); e != nil {
				return e
			}
		} else {
			if e := createDurablePolicyFile(root, o.Path, o.Data); e != nil {
				return e
			}
		}
	}
	// Children first; applying a restrictive parent ACL earlier could deny writes.
	sec := root.(policySecurityStore)
	for i := len(r.After.Objects) - 1; i >= 0; i-- {
		o := r.After.Objects[i]
		if e := sec.SetACL(o.Path, o.ACL); e != nil {
			return e
		}
	}
	got, e := repairTreeState(ctx, v, r.Stage, r)
	if e != nil {
		return e
	}
	if got != r.After.Signature {
		return fmt.Errorf("staged SYSVOL verification failed")
	}
	return nil
}
func validateRepairLocations(r *RepairRecord, a, b, c, direction string) error {
	before, after := repairSignature(r.Before), r.After.Signature
	if direction == "rollback" {
		if c != "missing" && c != after {
			return ErrTopologyConflict
		}
		if a == after && c != "missing" {
			return ErrTopologyConflict
		}
		if r.Before == nil {
			if b != "missing" || (a != "missing" && a != after) {
				return ErrTopologyConflict
			}
			return nil
		}
		if (a == before && b == "missing") || ((a == after || a == "missing") && b == before) {
			return nil
		}
		return ErrTopologyConflict
	}
	if c != "missing" {
		return ErrTopologyConflict
	}
	if (a == after && b == before) || (a == before && b == "missing") || (a == "missing" && b == before) {
		return nil
	}
	return ErrTopologyConflict
}

func runRepair(ctx context.Context, v repairVolume, local *os.Root, r *RepairRecord, checkLDAP func() error) error {
	live, bak, archive := repairLive(r), repairBackup(r), repairArchive(r)
	before := repairSignature(r.Before)
	after := r.After.Signature
	state := func(n string) (string, error) { return repairTreeState(ctx, v, n, r) }
	get := func() (string, string, string, error) {
		a, e := state(live)
		if e != nil {
			return "", "", "", e
		}
		b, e := state(bak)
		if e != nil {
			return "", "", "", e
		}
		c, e := state(archive)
		return a, b, c, e
	}
	a, b, c, e := get()
	if e != nil {
		return e
	}
	if e = validateRepairLocations(r, a, b, c, r.Direction); e != nil {
		return e
	}
	if r.Direction == "rollback" {
		if c != "missing" && c != after {
			return ErrTopologyConflict
		}
		if r.Before != nil && b != before && !(a == before && b == "missing") {
			return ErrTopologyConflict
		}
		if a != before && a != after && a != "missing" {
			return ErrTopologyConflict
		}
		if e = checkLDAP(); e != nil {
			return e
		}
		if a == after {
			if c != "missing" {
				return ErrTopologyConflict
			}
			if e = repairMark(v.Tree(live), r); e != nil {
				return e
			}
			if e = v.Rename(live, archive); e != nil {
				return e
			}
			a = "missing"
		}
		if a == "missing" && r.Before != nil {
			if e = checkLDAP(); e != nil {
				return e
			}
			if e = v.Rename(bak, live); e != nil {
				return e
			}
		}
		got, e := state(live)
		if e != nil {
			return e
		}
		if got != before {
			return ErrTopologyConflict
		}
		if r.Before != nil {
			if e = repairUnmark(v.Tree(live), r); e != nil {
				return e
			}
		}
		r.State = "rolled-back"
		return saveRepair(local, r)
	}
	if c != "missing" {
		return ErrTopologyConflict
	}
	if a == after && ((r.Before == nil && b == "missing") || b == before) {
		if e = checkLDAP(); e != nil {
			return e
		}
		if e = repairUnmark(v.Tree(live), r); e != nil {
			return e
		}
		r.State = "complete"
		return saveRepair(local, r)
	}
	if !((a == before && b == "missing") || (a == "missing" && b == before)) {
		return ErrTopologyConflict
	}
	if e = stageRepair(ctx, v, local, r); e != nil {
		return e
	}
	if e = checkLDAP(); e != nil {
		return e
	}
	// Re-read both directories immediately before cutover. This is optimistic
	// conflict detection, not a lock against external SMB clients.
	a, b, _, e = get()
	if e != nil {
		return e
	}
	if r.Before != nil && a == before && b == "missing" {
		if e = repairMark(v.Tree(live), r); e != nil {
			return e
		}
		sig, e := state(live)
		if e != nil {
			return e
		}
		if sig != before {
			return ErrTopologyConflict
		}
		if e = v.Rename(live, bak); e != nil {
			return e
		}
		a = "missing"
		b = before
	}
	if a != "missing" || (r.Before != nil && b != before) {
		return ErrTopologyConflict
	}
	if e = checkLDAP(); e != nil {
		return e
	}
	sig, e := state(r.Stage)
	if e != nil {
		return e
	}
	if sig != after {
		return ErrTopologyConflict
	}
	if e = v.Rename(r.Stage, live); e != nil {
		return e
	}
	sig, e = state(live)
	if e != nil {
		return e
	}
	if sig != after {
		return fmt.Errorf("post-cutover verification failed")
	}
	if e = checkLDAP(); e != nil {
		return e
	}
	if e = repairUnmark(v.Tree(live), r); e != nil {
		return e
	}
	r.State = "complete"
	return saveRepair(local, r)
}
func repairPlanChanges(a, b *repairSnapshot) []ConsistencyDifference {
	out := []ConsistencyDifference{}
	old := map[string]repairObject{}
	if a != nil {
		for _, o := range a.Objects {
			old[o.Path] = o
		}
	}
	var desired []repairObject
	if b != nil {
		desired = b.Objects
	}
	for _, n := range desired {
		o, ok := old[n.Path]
		delete(old, n.Path)
		kind := ""
		if !ok {
			kind = "add"
		} else if o.Directory != n.Directory {
			kind = "type"
		} else if string(o.Data) != string(n.Data) {
			kind = "content"
		}
		if kind != "" {
			out = append(out, ConsistencyDifference{Kind: kind, Path: n.Path})
		}
		oa, _ := consistencyACL(o.ACL)
		na, _ := consistencyACL(n.ACL)
		if ok && oa != na {
			out = append(out, ConsistencyDifference{Kind: "sysvol-acl", Path: n.Path, Reference: na, Value: oa})
		}
	}
	for p := range old {
		out = append(out, ConsistencyDifference{Kind: "remove", Path: p})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Path < out[j].Path
	})
	return out
}
