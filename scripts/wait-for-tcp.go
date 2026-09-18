// Command wait-for-tcp waits until host:port accepts a TCP connection (or a
// short deadline passes). Used by the Woodpecker integration lane to wait
// for the PostgreSQL service without adding a shell dependency.
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: wait-for-tcp HOST PORT")
		os.Exit(2)
	}
	addr := net.JoinHostPort(os.Args[1], os.Args[2])
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "wait-for-tcp: %s never became reachable\n", addr)
	os.Exit(1)
}
