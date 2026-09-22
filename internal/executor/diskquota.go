package executor

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
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
// reason when Hard is false. Limit is the byte bound actually applied (zero
// unless Hard).
type DiskQuotaStatus struct {
	Hard   bool
	Limit  int64
	Detail string
}

// workspaceDiskQuotaSetup attempts to establish a hard OS-level bound for the
// workspace tree and returns the resulting status plus a cleanup function
// (nil when nothing was changed). The default implementation lives in
// diskquota_linux.go; it is a package variable so tests can substitute a
// deterministic capability outcome.
var workspaceDiskQuotaSetup = setupWorkspaceDiskQuota

// WorkspaceDiskQuotaSetup is the exported entry point for callers that own
// the workspace lifecycle outside the backend (the distributed runner
// installs the quota before checkout, see runner.execute). It routes through
// the same capability probe as the backend so the two can never disagree.
func WorkspaceDiskQuotaSetup(workspace string, limit int64) (DiskQuotaStatus, func() error) {
	return workspaceDiskQuotaSetup(workspace, limit)
}

// WorkspaceBoundBytes derives the workspace content bound for one job with a
// single shared precedence, used by the runner (quota installation and
// executor options) and by the container backend (step-boundary checks):
//
//  1. a declared resources.disk request (any job), then
//  2. for an untrusted job, the per-executor override when set, otherwise
//     DefaultUntrustedWorkspaceMaxBytes, then
//  3. trusted jobs without a declaration: zero (unbounded), the documented
//     historical default.
func WorkspaceBoundBytes(declaredDisk int64, untrusted bool, untrustedDefault int64) int64 {
	if declaredDisk > 0 {
		return declaredDisk
	}
	if untrusted {
		if untrustedDefault > 0 {
			return untrustedDefault
		}
		return DefaultUntrustedWorkspaceMaxBytes
	}
	return 0
}

// UntrustedDiskQuotaGateError renders the fail-closed error for an untrusted
// container job that demands a hard workspace disk quota but has none. The
// message names the probe's reason and the documented operator escape hatch.
// A single implementation keeps the runner's pre-checkout gate and the
// container backend's defense-in-depth gate identical.
func UntrustedDiskQuotaGateError(detail string) error {
	return &RunError{Kind: ErrorConfig, Err: fmt.Errorf("untrusted job requires a hard workspace disk quota, but none could be established: %s (the step-boundary resources.disk check is not a hard bound; set %s=1 only on trusted-only self-hosted runners to accept that residual, or run the runner on an XFS workspace with prjquota and root)", detail, AllowUnquotaedUntrustedDiskEnv)}
}

// mountInfoEntry is one parsed /proc/self/mountinfo record.
type mountInfoEntry struct {
	mountPoint   string
	device       string
	fsType       string
	superOptions string
}

// fsKey identifies the filesystem a mount belongs to for XFS project-ID
// allocation: XFS project quotas are scoped per mounted superblock, so IDs
// must be unique per filesystem, not globally. The mountinfo device
// (major:minor) is the precise identity; the mount point is the fallback for
// records without one.
func (e mountInfoEntry) fsKey() string {
	if e.device != "" {
		return e.device
	}
	return e.mountPoint
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
		device:       fields[2],
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

// XFS project-ID allocation (E3-D).
//
// Every concurrent XFS project quota needs its own project ID. IDs are scoped
// per mounted XFS superblock, so the allocator is a process-local pool per
// filesystem identity (mountinfo device): the same numeric ID may be live on
// two different filesystems, which the kernel keeps apart. Within one
// filesystem an ID is never handed out twice, and a released ID is only
// returned to the pool after the project assignment was removed, so a
// workspace can never inherit another workspace's quota (the previous
// hash-derived ID could collide between simultaneously active workspaces and
// the cleanup command omitted the ID entirely, so a removal targeted the
// wrong project).
const (
	// defaultXFSProjectIDBase starts the allocator pool well above the low
	// project IDs administrators typically assign by hand.
	defaultXFSProjectIDBase uint32 = 100000
	// defaultXFSProjectIDCount is the pool size per filesystem. It bounds
	// simultaneous project-quotaed workspaces on one filesystem and never
	// overflows the 31-bit range the executor uses (XFS project IDs are
	// 32-bit; keeping the high bit clear avoids signedness surprises in
	// xfs_quota arguments).
	defaultXFSProjectIDCount uint32 = 1 << 20
	// xfsProjectIDMax is the largest ID the pool may hand out.
	xfsProjectIDMax uint32 = 0x7fffffff
)

// Environment overrides for the project-ID pool: KIWI_XFS_PROJECT_ID_BASE and
// KIWI_XFS_PROJECT_ID_COUNT let an operator move the pool out of a range their
// own tooling uses. Invalid or overflowing configurations fall back to the
// defaults.
const (
	xfsProjectIDBaseEnv  = "KIWI_XFS_PROJECT_ID_BASE"
	xfsProjectIDCountEnv = "KIWI_XFS_PROJECT_ID_COUNT"
)

// projectIDPool is one filesystem's project-ID allocator: a monotonic cursor
// plus the sorted set of released IDs, so reuse is deterministic (smallest
// free ID first) and an ID is live at most once.
type projectIDPool struct {
	mu       sync.Mutex
	base     uint32
	size     uint32
	used     uint32
	free     []uint32
	live     map[uint32]bool
	released uint64
}

func newProjectIDPool(base, size uint32) *projectIDPool {
	if base == 0 || base > xfsProjectIDMax {
		base = defaultXFSProjectIDBase
	}
	if size == 0 || base > xfsProjectIDMax-size+1 {
		size = min(defaultXFSProjectIDCount, xfsProjectIDMax-base+1)
	}
	return &projectIDPool{base: base, size: size, live: map[uint32]bool{}}
}

// allocate returns the next free project ID, preferring the smallest released
// one. ok is false only when every ID in the pool is live.
func (p *projectIDPool) allocate() (uint32, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.free) > 0 {
		id := p.free[0]
		p.free = p.free[1:]
		p.live[id] = true
		return id, true
	}
	if p.used >= p.size {
		return 0, false
	}
	id := p.base + p.used
	p.used++
	p.live[id] = true
	return id, true
}

// release returns an ID to the pool. Releasing an ID that is not live is a
// no-op, so repeated cleanup paths cannot corrupt the pool.
func (p *projectIDPool) release(id uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.live[id] {
		return
	}
	delete(p.live, id)
	p.released++
	i := sort.Search(len(p.free), func(i int) bool { return p.free[i] >= id })
	p.free = append(p.free, 0)
	copy(p.free[i+1:], p.free[i:])
	p.free[i] = id
}

// liveCount reports how many IDs are currently allocated (test/observability).
func (p *projectIDPool) liveCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.live)
}

// xfsProjectIDPools holds one pool per filesystem identity.
var xfsProjectIDPools = struct {
	mu sync.Mutex
	m  map[string]*projectIDPool
}{m: map[string]*projectIDPool{}}

// projectIDPoolFor returns (creating on first use) the pool for fsKey. The
// pool configuration comes from the environment once per filesystem.
func projectIDPoolFor(fsKey string) *projectIDPool {
	xfsProjectIDPools.mu.Lock()
	defer xfsProjectIDPools.mu.Unlock()
	if p, ok := xfsProjectIDPools.m[fsKey]; ok {
		return p
	}
	p := newProjectIDPool(xfsProjectIDBase(), xfsProjectIDCount())
	xfsProjectIDPools.m[fsKey] = p
	return p
}

// xfsProjectIDBase resolves the configured pool base (default when unset or
// invalid).
func xfsProjectIDBase() uint32 {
	v, err := strconv.ParseUint(strings.TrimSpace(os.Getenv(xfsProjectIDBaseEnv)), 10, 32)
	if err != nil || v == 0 || uint32(v) > xfsProjectIDMax {
		return defaultXFSProjectIDBase
	}
	return uint32(v)
}

// xfsProjectIDCount resolves the configured pool size. Values that are unset,
// invalid, zero or wider than the 31-bit project-ID range fall back to the
// default; an in-range value is clamped to what the configured base leaves
// available (see newProjectIDPool).
func xfsProjectIDCount() uint32 {
	v, err := strconv.ParseUint(strings.TrimSpace(os.Getenv(xfsProjectIDCountEnv)), 10, 32)
	if err != nil || v == 0 || v > uint64(xfsProjectIDMax) {
		return defaultXFSProjectIDCount
	}
	return uint32(v)
}

// allocateXFSProjectID hands out a collision-free ID for one filesystem.
func allocateXFSProjectID(fsKey string) (uint32, error) {
	p := projectIDPoolFor(fsKey)
	id, ok := p.allocate()
	if !ok {
		return 0, fmt.Errorf("XFS project id pool for filesystem %q exhausted (%d IDs live; raise %s/%s or clean up leaked workspaces)", fsKey, p.size, xfsProjectIDBaseEnv, xfsProjectIDCountEnv)
	}
	return id, nil
}

// releaseXFSProjectID returns an ID to its filesystem's pool.
func releaseXFSProjectID(fsKey string, id uint32) {
	if id == 0 {
		return
	}
	projectIDPoolFor(fsKey).release(id)
}

// xfsQuote single-quotes a path argument for the xfs_quota command language,
// escaping embedded single quotes.
func xfsQuote(path string) string {
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}

// xfsProjectAssignCommand renders the xfs_quota command that assigns the
// workspace directory to projID (with -s so existing files are inherited).
func xfsProjectAssignCommand(workspace string, projID uint32) string {
	return fmt.Sprintf("project -s -p %s %d", xfsQuote(workspace), projID)
}

// xfsProjectLimitCommand renders the bhard limit command for projID.
func xfsProjectLimitCommand(limit int64, projID uint32) string {
	return fmt.Sprintf("limit -p bhard=%d %d", limit, projID)
}

// xfsProjectCleanupCommands renders the removal commands for one project
// quota. The project ID is part of BOTH commands: `project -C` without the ID
// (the previous implementation) removes the assignment by path only and can
// clear the wrong project's state when paths are reused, so every removal
// names the exact ID it clears.
func xfsProjectCleanupCommands(workspace string, projID uint32) []string {
	return []string{
		fmt.Sprintf("project -C -p %s %d", xfsQuote(workspace), projID),
		fmt.Sprintf("limit -p bhard=0 %d", projID),
	}
}

// runXFSQuotaCommand executes `xfs_quota -x -c <command> <mountPoint>`.
func runXFSQuotaCommand(xq, mountPoint, command string) error {
	out, err := exec.Command(xq, "-x", "-c", command, mountPoint).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", command, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// setupXFSProjectQuotaOnMount is the XFS core shared by the Linux capability
// probe and the tests: it allocates a project ID for the workspace's
// filesystem, assigns the workspace to it, applies the bhard limit, and
// returns the status plus a cleanup that removes both and releases the ID.
//
// The ID is released only after both removal commands succeeded: if the
// assignment may still exist, the ID stays allocated so no other workspace
// can inherit it. On any failure before the limit was applied, the
// half-applied state is removed and the ID released (best effort).
func setupXFSProjectQuotaOnMount(workspace string, entry mountInfoEntry, limit int64, xq string) (DiskQuotaStatus, func() error) {
	fsKey := entry.fsKey()
	projID, err := allocateXFSProjectID(fsKey)
	if err != nil {
		return DiskQuotaStatus{Detail: "allocate XFS project id: " + err.Error()}, nil
	}
	if err := runXFSQuotaCommand(xq, entry.mountPoint, xfsProjectAssignCommand(workspace, projID)); err != nil {
		releaseXFSProjectID(fsKey, projID)
		return DiskQuotaStatus{Detail: "assign XFS project quota: " + err.Error()}, nil
	}
	if err := runXFSQuotaCommand(xq, entry.mountPoint, xfsProjectLimitCommand(limit, projID)); err != nil {
		// Leave nothing half-applied: drop the project assignment again with
		// the same cleanup used on the normal path (it names the ID and
		// releases it only when both commands succeed).
		if cerr := runXFSProjectCleanup(xq, entry.mountPoint, workspace, projID, fsKey); cerr != nil {
			return DiskQuotaStatus{Detail: fmt.Sprintf("apply XFS project hard limit: %v (cleanup also failed, the project id stays allocated: %v)", err, cerr)}, nil
		}
		return DiskQuotaStatus{Detail: "apply XFS project hard limit: " + err.Error()}, nil
	}
	cleanup := func() error {
		return runXFSProjectCleanup(xq, entry.mountPoint, workspace, projID, fsKey)
	}
	return DiskQuotaStatus{
		Hard:   true,
		Limit:  limit,
		Detail: fmt.Sprintf("XFS project quota %d enforces a hard %d-byte bound on %s (mount %s)", projID, limit, workspace, entry.mountPoint),
	}, cleanup
}

// runXFSProjectCleanup removes the assignment and the hard limit for projID,
// then releases the ID. The ID is released only when both commands succeeded.
func runXFSProjectCleanup(xq, mountPoint, workspace string, projID uint32, fsKey string) error {
	var errs []string
	for _, command := range xfsProjectCleanupCommands(workspace, projID) {
		if err := runXFSQuotaCommand(xq, mountPoint, command); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("remove XFS project quota: %s", strings.Join(errs, "; "))
	}
	releaseXFSProjectID(fsKey, projID)
	return nil
}
