package woodpecker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDumpCorpusTraces(t *testing.T) {
	root := filepath.Join("..", "..", "..", "compat", "woodpecker")
	for _, name := range []string{"simple", "dependencies", "conditions", "secrets", "cancellation"} {
		src, err := os.ReadFile(filepath.Join(root, name, ".woodpecker.yml"))
		if err != nil {
			t.Fatal(err)
		}
		c, err := Evaluate(string(src))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out, _ := json.MarshalIndent(c.Trace, "", "  ")
		if err := os.WriteFile(filepath.Join("/tmp/wp-trace-"+name+".json"), out, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
