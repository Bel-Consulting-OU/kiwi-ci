package explain

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestExplainWhyNilGraph is the H1-E guard regression: a nil *pipeline.Graph
// must be reported as an error instead of panicking on the g.Jobs deref.
func TestExplainWhyNilGraph(t *testing.T) {
	if _, err := ExplainWhy(&pipeline.Spec{}, nil, "build", ExplainContext{}); err == nil {
		t.Fatal("nil graph accepted")
	}
	if _, err := ExplainWhy(nil, nil, "build", ExplainContext{}); err == nil {
		t.Fatal("nil spec and graph accepted")
	}
}
