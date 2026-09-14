package executor

// WriteOwnerOnly writes data with owner-only access semantics for secret
// material (SSH keys, tokens). The mechanism is platform-specific and is
// documented on the per-OS implementations in keyfile_unix.go and
// keyfile_windows.go: on Unix the file is created at path with mode 0600 —
// the file mode is the access-control mechanism, so 0600 is owner-only by
// construction — and on Windows the file is written into the caller's
// user-scoped %LOCALAPPDATA% tree, whose directory ACL is the Windows
// owner-only equivalent (Windows file modes do not encode access control, so
// no file-level DACL is applied). Callers writing secrets must use this
// helper rather than os.WriteFile directly.
