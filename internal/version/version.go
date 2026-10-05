package version

// Set via -ldflags at build time.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func String() string {
	return "sambaadm " + Version + " (commit=" + Commit + ", built=" + Date + ")"
}
