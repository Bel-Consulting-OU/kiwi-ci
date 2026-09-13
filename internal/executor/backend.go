package executor

import (
	"context"
	"fmt"
	"io"
	"runtime"
)

type Command struct {
	Shell          string
	Script         string
	Dir            string
	Env            []string
	TimeoutSeconds int64
}

type Backend interface {
	Name() string
	Run(context.Context, Command, func(string)) error
	// ReadFile reads a file from inside the job's workspace (or sandbox).
	// Implementations must not follow symlinks out of the workspace and must
	// reject files larger than maxBytes. A missing file is reported as
	// os.ErrNotExist so callers can treat "step wrote no outputs" uniformly.
	ReadFile(ctx context.Context, path string, maxBytes int64) ([]byte, error)
}

// JobLifecycle is implemented by backends that keep per-job runtime state
// (a container, a VM) across all steps of one job.
type JobLifecycle interface {
	StartJob(context.Context, string, func(string)) error
	CloseJob() error
}

func BackendFor(kind, image, vm string) (Backend, error) {
	switch kind {
	case "", "native":
		return &NativeBackend{}, nil
	case "container":
		return &ContainerBackend{Image: image}, nil
	case "tart":
		if runtime.GOOS != "darwin" {
			return nil, fmt.Errorf("tart backend requires macOS")
		}
		return &TartBackend{VM: vm}, nil
	default:
		return nil, fmt.Errorf("unknown backend %q", kind)
	}
}

// BackendForNetwork selects the backend and applies the effective network
// (for example a dedicated services network) to container and tart jobs.
// For tart the network value is carried through so StartJob can fail closed
// when isolation was requested; tart has no network isolation.
func BackendForNetwork(kind, image, vm, network string) (Backend, error) {
	b, err := BackendFor(kind, image, vm)
	if err != nil {
		return nil, err
	}
	if cb, ok := b.(*ContainerBackend); ok {
		cb.Network = network
	}
	if tb, ok := b.(*TartBackend); ok {
		tb.Network = network
	}
	return b, nil
}

// readCapped reads at most maxBytes+1 bytes from r and rejects input that
// exceeds maxBytes, so a hostile oversized output file can never be fully
// buffered.
func readCapped(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("invalid read limit %d", maxBytes)
	}
	b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d byte limit", maxBytes)
	}
	return b, nil
}
