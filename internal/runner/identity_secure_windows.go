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
	// The ACE must be INHERITABLE: the persisted private key is created as a
	// child of this directory, and a NO_INHERITANCE ACE would leave the file
	// protected only by whatever DACL it happens to receive. Object+container
	// inheritance (and the sub-* variants for deeper trees) make every child
	// — the key file included — carry the current-user-only grant.
	entries := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE,
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

// secureIdentityFile installs a PROTECTED current-user-only DACL directly on
// a sensitive file. Directory traversal restrictions are not the same
// primitive as Unix 0700 on Windows (bypass-traverse-checking is normally
// granted to local users), so the private key must carry its own proven DACL
// even though the parent ACE is inheritable.
func secureIdentityFile(path string) error {
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
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	)
}
