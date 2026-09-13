package executor

import (
	"context"
	"fmt"
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
// (for example a dedicated services network) to container jobs.
func BackendForNetwork(kind, image, vm, network string) (Backend, error) {
	b, err := BackendFor(kind, image, vm)
	if err != nil {
		return nil, err
	}
	if cb, ok := b.(*ContainerBackend); ok {
		cb.Network = network
	}
	return b, nil
}
