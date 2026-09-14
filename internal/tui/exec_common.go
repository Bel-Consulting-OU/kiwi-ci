package tui

import (
	"bytes"
	"os/exec"
	"strings"
)

func execTool(name string, args []string, input string) error {
	path, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	cmd := exec.Command(path, args...)
	cmd.Stdin = strings.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}
