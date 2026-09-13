package executor

import (
	"errors"
	"fmt"
)

const (
	ErrorFailure   = "failure"
	ErrorInfra     = "infra"
	ErrorTimeout   = "timeout"
	ErrorCancelled = "cancelled"
)

type RunError struct {
	Kind string
	Err  error
}

func (e *RunError) Error() string { return fmt.Sprintf("%s: %v", e.Kind, e.Err) }
func (e *RunError) Unwrap() error { return e.Err }

func errorKind(err error) string {
	var re *RunError
	if errors.As(err, &re) {
		return re.Kind
	}
	return ErrorFailure
}
