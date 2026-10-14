//go:build !darwin

package app

// platformKeychain returns nil on platforms without a wired keychain yet;
// DefaultSecretStore falls back to FileSecretStore (0600 under the config
// dir). Windows Credential Manager / Linux Secret Service are the next
// platform seams — the file fallback keeps the command surface complete
// today without claiming a keychain that is not wired.
func platformKeychain() SecretStore { return nil }
