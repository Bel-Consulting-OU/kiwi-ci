//go:build windows

package runner

import (
	"os"

	"golang.org/x/sys/windows"
)

// secureIdentityDir creates the identity directory and installs a PROTECTED
// DACL granting the CURRENT USER full control only: numeric Unix modes do
// not encode Windows access control, so relying on 0700 would leave the
// persistent runner private key readable by other local principals through
// inherited ACEs. If the DACL cannot be installed the runner fails startup
// rather than persist identity material behind an unverified boundary.
func secureIdentityDir(dir string) error {
	if err := os.MkdirAll(dir, identityDirMode); err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	entries := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
		},
	}}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		dir,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	)
}
