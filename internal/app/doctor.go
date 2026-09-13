package app

import (
	"flag"
	"fmt"
	"os/exec"
	"runtime"
)

func Doctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Printf("OS: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	check("git")
	check("bash")
	check("docker")
	if runtime.GOOS == "darwin" {
		check("tart")
		check("xcodebuild")
		check("security")
	}
	return nil
}
func check(name string) {
	p, err := exec.LookPath(name)
	if err != nil {
		fmt.Printf("%-12s missing\n", name)
		return
	}
	fmt.Printf("%-12s %s\n", name, p)
}
