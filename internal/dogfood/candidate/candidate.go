// Package candidate resolves the EXACT product binary under test.
//
// Release certification must exercise the frozen candidate bytes, never a
// fresh `go build` of the source tree: artifact identity is part of the
// proposition. When KIWI_CANDIDATE_BIN is set those bytes are installed
// verbatim and checked against KIWI_CANDIDATE_SHA256 (or the FREEZE
// manifest's platform digest). When it is unset this is a development run
// and the caller builds from source as before.
package candidate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Env vars that select a frozen candidate.
const (
	EnvBin    = "KIWI_CANDIDATE_BIN"
	EnvSHA256 = "KIWI_CANDIDATE_SHA256"
	// EnvFreeze points at a FREEZE manifest from `release.sh --candidate`.
	EnvFreeze = "KIWI_CANDIDATE_FREEZE"
	// EnvPlatform is the bundle basename to look up in the FREEZE/SHA256SUMS
	// (e.g. kiwi-darwin-arm64). Defaults to the current GOOS/GOARCH.
	EnvPlatform = "KIWI_CANDIDATE_PLATFORM"
)

// Resolve installs the frozen candidate bytes at dest when one is selected
// and returns the binary's lowercase SHA-256 plus whether a frozen
// candidate was used. A selected candidate that fails verification is a
// hard error — never a silent fallback to a source build.
func Resolve(dest string) (sha string, frozen bool, err error) {
	bin := strings.TrimSpace(os.Getenv(EnvBin))
	if bin == "" {
		return "", false, nil
	}
	st, err := os.Stat(bin)
	if err != nil || st.IsDir() {
		return "", true, fmt.Errorf("%s=%q is not a readable file", EnvBin, bin)
	}
	want, err := expectedDigest(bin)
	if err != nil {
		return "", true, err
	}
	got, err := SHA256File(bin)
	if err != nil {
		return "", true, err
	}
	if want != "" && got != want {
		return "", true, fmt.Errorf("candidate %s sha256=%s, want pinned %s", bin, got, want)
	}
	if err := CopyFile(bin, dest); err != nil {
		return "", true, fmt.Errorf("install candidate: %w", err)
	}
	again, err := SHA256File(dest)
	if err != nil {
		return "", true, err
	}
	if again != got {
		return "", true, fmt.Errorf("installed candidate sha256=%s, want source %s", again, got)
	}
	return got, true, nil
}

// expectedDigest resolves the independently trusted pin for the selected
// candidate: an explicit KIWI_CANDIDATE_SHA256, else the platform entry in
// the FREEZE manifest's SHA256SUMS. An empty result means "no pin supplied"
// (dev-only; release certification must always supply one).
func expectedDigest(bin string) (string, error) {
	if s := strings.TrimSpace(os.Getenv(EnvSHA256)); s != "" {
		s = strings.ToLower(s)
		if !isSHA256(s) {
			return "", fmt.Errorf("%s=%q is not a lowercase hex SHA256", EnvSHA256, s)
		}
		return s, nil
	}
	freeze := strings.TrimSpace(os.Getenv(EnvFreeze))
	if freeze == "" {
		return "", nil
	}
	sums := filepath.Join(filepath.Dir(freeze), "SHA256SUMS")
	plat := strings.TrimSpace(os.Getenv(EnvPlatform))
	if plat == "" {
		plat = DefaultPlatform()
	}
	raw, err := os.ReadFile(sums)
	if err != nil {
		return "", fmt.Errorf("candidate freeze: %w", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[1] == plat {
			if !isSHA256(strings.ToLower(fields[0])) {
				return "", fmt.Errorf("SHA256SUMS entry for %s is not a digest: %q", plat, fields[0])
			}
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("candidate freeze SHA256SUMS has no entry for %s", plat)
}

// DefaultPlatform is the bundle basename `release.sh` emits for this host.
func DefaultPlatform() string {
	return "kiwi-" + goos() + "-" + goarch()
}

// SHA256File returns the lowercase hex SHA-256 of a file's bytes.
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CopyFile copies src to dst byte-for-byte, preserving the executable bit.
func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func goos() string {
	if v := os.Getenv("GOOS"); v != "" {
		return v
	}
	return runtimeGOOS
}

func goarch() string {
	if v := os.Getenv("GOARCH"); v != "" {
		return v
	}
	return runtimeGOARCH
}
