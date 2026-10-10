package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseArgs(t *testing.T) {
	if host, port, ok := parseArgs([]string{"db", "5432"}); !ok || host != "db" || port != "5432" {
		t.Fatalf("parseArgs = (%q, %q, %v)", host, port, ok)
	}
	for _, args := range [][]string{nil, {"only"}, {"a", "b", "c"}} {
		if _, _, ok := parseArgs(args); ok {
			t.Fatalf("parseArgs(%v) accepted a non-2-arity invocation", args)
		}
	}
}

func TestRunUsageErrorExits2(t *testing.T) {
	var stderr bytes.Buffer
	if got := run([]string{"only-host"}, &stderr, time.Second, time.Second, time.Millisecond); got != 2 {
		t.Fatalf("run exit = %d, want 2", got)
	}
	if !strings.Contains(stderr.String(), "usage: wait-for-tcp HOST PORT") {
		t.Fatalf("stderr = %q, want the usage line", stderr.String())
	}
}

func TestRunSucceedsAgainstListeningSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
	}()
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if got := run([]string{host, port}, &stderr, time.Second, 100*time.Millisecond, 10*time.Millisecond); got != 0 {
		t.Fatalf("run exit = %d (stderr %q), want 0", got, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty on success", stderr.String())
	}
	<-done
}

func TestRunTimesOutAndExits1(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	var stderr bytes.Buffer
	if got := run([]string{host, port}, &stderr, 100*time.Millisecond, 20*time.Millisecond, 10*time.Millisecond); got != 1 {
		t.Fatalf("run exit = %d, want 1", got)
	}
	if !strings.Contains(stderr.String(), "never became reachable") {
		t.Fatalf("stderr = %q, want the timeout diagnostic", stderr.String())
	}
}

func TestWaitForTCPReportsLastAddress(t *testing.T) {
	err := waitForTCP("127.0.0.1:1", 50*time.Millisecond, 10*time.Millisecond, 5*time.Millisecond)
	if err == nil {
		t.Fatal("waitForTCP = nil for an unreachable address")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("error %q does not name the address", err)
	}
}
