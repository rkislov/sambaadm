//go:build !linux

package service

func diagnosticWriteAccess(path string, directory bool) (bool, bool) { return false, false }
