//go:build darwin

package app

import (
	"os/exec"
	"strings"
)

// platformKeychain uses the macOS `security` CLI (Keychain) when present.
// Secrets never land in the config file.
func platformKeychain() SecretStore {
	if _, err := exec.LookPath("security"); err != nil {
		return nil
	}
	return macKeychain{}
}

type macKeychain struct{}

func (macKeychain) Get(service, account string) (string, error) {
	out, err := exec.Command("security", "find-generic-password", "-s", service, "-a", account, "-w").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (macKeychain) Set(service, account, secret string) error {
	// Replace any existing item first (add-generic-password fails on dup).
	_ = exec.Command("security", "delete-generic-password", "-s", service, "-a", account).Run()
	cmd := exec.Command("security", "add-generic-password", "-s", service, "-a", account, "-w", secret, "-U")
	return cmd.Run()
}

func (macKeychain) Delete(service, account string) error {
	err := exec.Command("security", "delete-generic-password", "-s", service, "-a", account).Run()
	if err != nil {
		// Already absent is success.
		if strings.Contains(err.Error(), "could not be found") {
			return nil
		}
		return err
	}
	return nil
}
