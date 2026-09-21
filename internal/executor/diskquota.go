package executor

import (
	"fmt"
	"os"
	"strings"
)

// DefaultUntrustedWorkspaceMaxBytes is the mandatory workspace disk budget for
// an untrusted container job whose pipeline does not declare resources.disk.
// It is deliberately not zero: an undeclared disk used to leave the workspace
// completely unbounded, which let a malicious step fill the runner host disk.
// 10 GiB matches the scale of the largest admitted memory request and is far
// above any realistic checkout plus dependency set, while still bounding the
// blast radius. Callers may override it per executor through
// Options.UntrustedWorkspaceMaxBytes (e.g. from configuration); zero selects
// this default.
const DefaultUntrustedWorkspaceMaxBytes int64 = 10 << 30

// AllowUnquotaedUntrustedDiskEnv is the operator escape hatch for the
// fail-closed project-quota gate: when set to 1/true, untrusted jobs are
// allowed to run with only the step-boundary resources.disk enforcement even
// though no OS-level hard bound could be established. It exists for
// trusted-only/self-hosted runners that knowingly accept the residual risk;
// production runners must leave it unset.
const AllowUnquotaedUntrustedDiskEnv = "KIWI_ALLOW_UNQUOTAED_UNTRUSTED_DISK"

// AllowUnquotaedUntrustedDisk reports whether the operator escape hatch above
// is active.
func AllowUnquotaedUntrustedDisk() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(AllowUnquotaedUntrustedDiskEnv))) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

// DiskQuotaStatus is the outcome of the OS-level workspace disk-bound
// capability probe. Hard is true only when a hard kernel/filesystem-level
// bound on the workspace tree was actually established (currently: an XFS
// project quota); Detail always explains the outcome, including the failure
// reason when Hard is false.
type DiskQuotaStatus struct {
	Hard   bool
	Detail string
}

// workspaceDiskQuotaSetup attempts to establish a hard OS-level bound for the
// workspace tree and returns the resulting status plus a cleanup function
// (nil when nothing was changed). The default implementation lives in
// diskquota_linux.go; it is a package variable so tests can substitute a
// deterministic capability outcome.
var workspaceDiskQuotaSetup = setupWorkspaceDiskQuota

// mountInfoEntry is one parsed /proc/self/mountinfo record.
type mountInfoEntry struct {
	mountPoint   string
	fsType       string
	superOptions string
}

// parseMountInfoLine parses one /proc/self/mountinfo line. The format is
// space-separated fields followed by an optional-fields run, a "-" separator,
// then fstype, mount source and super options. Mount point escapes
// (\040 space, \011 tab, \012 newline, \134 backslash) are decoded so a path
// with spaces still matches.
func parseMountInfoLine(line string) (mountInfoEntry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 7 {
		return mountInfoEntry{}, false
	}
	sep := -1
	for i, f := range fields {
		if f == "-" {
			sep = i
			break
		}
	}
	if sep < 0 || sep+3 > len(fields)-1 {
		return mountInfoEntry{}, false
	}
	return mountInfoEntry{
		mountPoint:   unescapeMountInfoPath(fields[4]),
		fsType:       fields[sep+1],
		superOptions: fields[sep+3],
	}, true
}

// unescapeMountInfoPath decodes the octal escapes mountinfo uses for
// whitespace and backslashes in paths.
func unescapeMountInfoPath(p string) string {
	if !strings.ContainsRune(p, '\\') {
		return p
	}
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '\\' && i+3 < len(p) {
			var v int
			if _, err := fmt.Sscanf(p[i+1:i+4], "%03o", &v); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(p[i])
	}
	return b.String()
}

// findWorkspaceMount returns the mountinfo entry whose mount point is the
// longest prefix covering workspace (the filesystem the workspace actually
// lives on). Ties are impossible because a path has exactly one longest
// covering prefix.
func findWorkspaceMount(mountInfo, workspace string) (mountInfoEntry, bool) {
	best := mountInfoEntry{}
	found := false
	for _, line := range strings.Split(mountInfo, "\n") {
		entry, ok := parseMountInfoLine(line)
		if !ok {
			continue
		}
		if !pathCoveredByMount(workspace, entry.mountPoint) {
			continue
		}
		if !found || len(entry.mountPoint) > len(best.mountPoint) {
			best, found = entry, true
		}
	}
	return best, found
}

// pathCoveredByMount reports whether path lives under mountPoint, using the
// mount namespace's own semantics: an exact match or a "/" boundary after the
// mount point. The root mount ("/") covers every absolute path.
func pathCoveredByMount(path, mountPoint string) bool {
	if mountPoint == "" {
		return false
	}
	if mountPoint == "/" {
		return strings.HasPrefix(path, "/")
	}
	mountPoint = strings.TrimRight(mountPoint, "/")
	return path == mountPoint || strings.HasPrefix(path, mountPoint+"/")
}

// hasMountOption reports whether a comma-separated mount option list contains
// name exactly.
func hasMountOption(options, name string) bool {
	for _, o := range strings.Split(options, ",") {
		if strings.TrimSpace(o) == name {
			return true
		}
	}
	return false
}
