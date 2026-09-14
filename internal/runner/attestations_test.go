package runner

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestDeclaredArtifactFor(t *testing.T) {
	cj := pipeline.CompiledJob{ID: "build", BaseID: "build", Job: pipeline.Job{Artifacts: []pipeline.Artifact{
		{Name: "app", Paths: []string{"out"}, SBOM: "spdx-json", Sigstore: &pipeline.SigstoreConfig{Required: true, Issuer: "issuer"}},
	}}}
	a, ok := declaredArtifactFor(model.Job{}, cj, "app")
	if !ok || a.SBOM != "spdx-json" || a.Sigstore == nil || a.Sigstore.Issuer != "issuer" {
		t.Fatalf("strict declaration not resolved: %+v ok=%t", a, ok)
	}
	if _, ok := declaredArtifactFor(model.Job{}, cj, "missing"); ok {
		t.Fatal("undeclared artifact resolved")
	}

	// Lenient fallback: raw pipeline YAML carries the sbom/sigstore keys the
	// strict YAML schema does not admit yet.
	raw := "version: 1\njobs:\n  build:\n    artifacts:\n      - name: app\n        paths: [out]\n        sbom: cyclonedx-json\n        sigstore:\n          required: true\n          issuer: https://ci.acme\n          identity: build\n"
	j := model.Job{Key: "build", Pipeline: raw}
	a, ok = declaredArtifactFor(j, pipeline.CompiledJob{}, "app")
	if !ok || a.SBOM != "cyclonedx-json" || a.Sigstore == nil || !a.Sigstore.Required {
		t.Fatalf("lenient declaration not resolved: %+v ok=%t", a, ok)
	}

	// Matrix-expanded keys fall back to the base key.
	j2 := model.Job{Key: "build[0]", BaseKey: "build", Pipeline: raw}
	if _, ok := declaredArtifactFor(j2, pipeline.CompiledJob{}, "app"); !ok {
		t.Fatal("base-key fallback failed for matrix variant")
	}
}
