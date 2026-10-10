// Command wait-for-tcp waits until host:port accepts a TCP connection (or a
// short deadline passes). Used by the Woodpecker integration lane to wait
// for the PostgreSQL service without adding a shell dependency.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// Defaults of the CLI contract: a 2s overall deadline, 500ms per dial and a
// 200ms pause between attempts. Tests pass shorter values through run.
const (
	defaultTimeout       = 2 * time.Second
	defaultDialTimeout   = 500 * time.Millisecond
	defaultRetryInterval = 200 * time.Millisecond
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr, defaultTimeout, defaultDialTimeout, defaultRetryInterval))
}

// parseArgs extracts HOST and PORT from the CLI arguments; any arity other
// than exactly two is a usage error.
func parseArgs(args []string) (host, port string, ok bool) {
	if len(args) != 2 {
		return "", "", false
	}
	return args[0], args[1], true
}

// waitForTCP polls addr until a dial succeeds or timeout elapses. It never
// returns a listener connection: the probe dial is closed immediately.
func waitForTCP(addr string, timeout, dialTimeout, retryInterval time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, dialTimeout)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(retryInterval)
	}
	return fmt.Errorf("wait-for-tcp: %s never became reachable", addr)
}

// run executes one wait invocation and returns the process exit code: 0 when
// the address became reachable, 2 for a usage error, 1 on timeout.
func run(args []string, stderr io.Writer, timeout, dialTimeout, retryInterval time.Duration) int {
	host, port, ok := parseArgs(args)
	if !ok {
		fmt.Fprintln(stderr, "usage: wait-for-tcp HOST PORT")
		return 2
	}
	if err := waitForTCP(net.JoinHostPort(host, port), timeout, dialTimeout, retryInterval); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
