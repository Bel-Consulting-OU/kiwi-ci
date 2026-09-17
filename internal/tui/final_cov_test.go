package tui

import (
	"context"
	"testing"
	"time"
)

// cancelOnRead cancels ctx as soon as the first Read happens, so the reader
// loop has already passed its context check when the bytes are handled.
type cancelOnRead struct {
	cancel context.CancelFunc
	data   []byte
	done   bool
}

func (r *cancelOnRead) Read(p []byte) (int, error) {
	if r.done {
		return 0, nil
	}
	r.done = true
	r.cancel()
	n := copy(p, r.data)
	return n, nil
}

// TestFinalReadKeysAbortedEmit drives the key reader with a cancelled context
// and an unread key channel: every emit lands on the ctx.Done branch, which
// aborts the reader from inside the escape and ground states.
func TestFinalReadKeysAbortedEmit(t *testing.T) {
	for _, input := range []string{"q", "\x1bX"} {
		t.Run(input, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			in := &cancelOnRead{cancel: cancel, data: []byte(input)}
			keys := make(chan string)
			returned := make(chan struct{})
			go func() {
				readKeys(ctx, in, keys)
				close(returned)
			}()
			select {
			case <-returned:
			case <-time.After(10 * time.Second):
				t.Fatal("readKeys did not observe the cancelled context")
			}
		})
	}
}
