package service

import "os"

func preserveConfigOwner(f *os.File, info os.FileInfo) error { return nil }
