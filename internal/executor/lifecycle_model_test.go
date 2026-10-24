package executor

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// Lifecycle model: after a mid-start failure, no port may remain claimed
// and no listener may remain. This is the automated form of the hand-found
// "transactional native startup" class (P1).
func TestLifecycleNativeMidStartFailReleasesAll(t *testing.T) {
	const port = 6511
	good := pipeline.Service{
		Name: "good", Native: true, Ready: "tcp:" + strconv.Itoa(port),
		Command: []string{"python3", "-c",
			fmt.Sprintf("import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',%d)); s.listen(1); time.sleep(30)", port)},
	}
	bad := pipeline.Service{
		Name: "bad", Native: true, Ready: "tcp:6512",
		Command: []string{"kiwi-missing-binary-lifecycle-model"},
	}
	for attempt := 0; attempt < 2; attempt++ {
		_, _, _, cleanup, err := startNativeServices(
			context.Background(), "model", t.TempDir(),
			map[string]string{"PATH": "/usr/bin:/bin"},
			[]pipeline.Service{good, bad}, nil, nil,
		)
		if cleanup != nil {
			_ = cleanup()
		}
		if err == nil {
			t.Fatalf("attempt %d: mid-start failure expected", attempt)
		}
	}
	// Oracle: nothing listens; a later claim of the same port succeeds.
	if conn, derr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond); derr == nil {
		_ = conn.Close()
		t.Fatalf("port %d still listening after two failed starts", port)
	}
	if cerr := claimNativePort(port, "model/after"); cerr != nil {
		t.Fatalf("port claim leaked across failed starts: %v", cerr)
	}
	releaseNativePort(port)
}

// Lifecycle model: onStart (ledger) failure rolls back like any other error.
func TestLifecycleNativeOnStartFailReleases(t *testing.T) {
	const port = 6513
	svc := pipeline.Service{
		Name: "only", Native: true, Ready: "tcp:" + strconv.Itoa(port),
		Command: []string{"python3", "-c",
			fmt.Sprintf("import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',%d)); s.listen(1); time.sleep(30)", port)},
	}
	_, _, _, cleanup, err := startNativeServices(
		context.Background(), "model2", t.TempDir(),
		map[string]string{"PATH": "/usr/bin:/bin"},
		[]pipeline.Service{svc},
		func([]NativeServiceInfo) error { return fmt.Errorf("ledger down") },
		nil,
	)
	if cleanup != nil {
		_ = cleanup()
	}
	if err == nil || !strings.Contains(err.Error(), "ledger down") {
		t.Fatalf("err = %v", err)
	}
	if cerr := claimNativePort(port, "later"); cerr != nil {
		t.Fatalf("claim after onStart fail: %v", cerr)
	}
	releaseNativePort(port)
	if conn, derr := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 200*time.Millisecond); derr == nil {
		_ = conn.Close()
		t.Fatal("listener leaked after onStart failure")
	}
}
