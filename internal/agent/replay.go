package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Persist nonces across SSH processes and HTTPS restarts. An SSH transport key
// alone must not permit replaying a captured signed mutation.
func (v *Verifier) UseStateDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("helper state_dir must be absolute")
	}
	st, e := os.Lstat(dir)
	if e != nil {
		return e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 || !trustedOwner(st) {
		return fmt.Errorf("helper state_dir must be a private directory owned by the helper identity")
	}
	v.stateDir = dir
	return nil
}
func (v *Verifier) remember(req Request, now int64) error {
	if v.stateDir == "" {
		return nil
	}
	root, e := os.OpenRoot(v.stateDir)
	if e != nil {
		return e
	}
	defer root.Close()
	bucket := strconv.FormatInt(req.Time/120, 10)
	dir := filepath.Join("nonces", bucket)
	if e = root.MkdirAll(dir, 0700); e != nil {
		return e
	}
	f, e := root.OpenFile(filepath.Join(dir, req.ID), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	e = f.Sync()
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	for _, name := range []string{dir, "nonces", "."} {
		d, e := root.Open(name)
		if e != nil {
			return e
		}
		e = d.Sync()
		ce = d.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
	}
	// Only old timestamp buckets in the private nonce subtree are disposable.
	nonces, e := root.Open("nonces")
	if e != nil {
		return e
	}
	entries, e := nonces.ReadDir(-1)
	nonces.Close()
	if e != nil {
		return e
	}
	for _, entry := range entries {
		n, e := strconv.ParseInt(entry.Name(), 10, 64)
		if e == nil && n >= 0 && n < (now-240)/120 {
			if e = root.RemoveAll(filepath.Join("nonces", entry.Name())); e != nil && !os.IsNotExist(e) {
				return e
			}
		}
	}
	return nil
}
