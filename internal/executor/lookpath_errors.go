package executor

import "errors"

// errEmptyExecutable is returned when argv0 is empty.
var errEmptyExecutable = errors.New("empty executable name")

// errNotFoundOnPath builds the Windows/Unix not-found error for a full path.
func errNotFoundOnPath(name, pathEnv, pathExt string) error {
	return &execPathError{name: name, path: pathEnv, pathExt: pathExt}
}

type execPathError struct {
	name    string
	path    string
	pathExt string
}

func (e *execPathError) Error() string {
	if e.pathExt == "" {
		return e.name + " not found on execution PATH \"" + e.path + "\""
	}
	return e.name + " not found on execution PATH \"" + e.path + "\" (PATHEXT=\"" + e.pathExt + "\")"
}
