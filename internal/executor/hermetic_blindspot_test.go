package executor

import (
	"context"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

// TestContainerNeverSeesHostMarkersEvenWithInheritEnv is the K1 adversarial
// probe: InheritEnv=true must NOT leak host env into container jobs.
func TestContainerNeverSeesHostMarkersEvenWithInheritEnv(t *testing.T) {
	installFakeBins(t)
	t.Setenv("KIWI_MARKER", "leaked-from-host")
	t.Setenv("MY_CUSTOM_HOST_VAR", "also-leaked")

	script := `          [ -z "${KIWI_MARKER:-}" ] || { echo "MARKER=$KIWI_MARKER"; exit 1; }
          [ -z "${MY_CUSTOM_HOST_VAR:-}" ] || { echo "CUSTOM=$MY_CUSTOM_HOST_VAR"; exit 1; }
          echo ok
`
	g := envProbeSpec(nativeScript(script, script))
	{
		cj := g.Jobs["probe"]
		cj.Job.Runtime = "container"
		cj.Job.Image = "alpine:3.20"
		g.Jobs["probe"] = cj
	}
	ex := Executor{Opt: Options{Workspace: t.TempDir(), InheritEnv: true}, Masker: &secrets.Masker{}}
	res, err := ex.Run(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if res["probe"].Status != model.StatusSuccess {
		t.Fatalf("host env leaked into container: %+v", res["probe"])
	}
}

// TestContainerPathNotClobbered: the engine must not inject host PATH into
// container steps (K2). The fake container echoes $PATH; the job env must
// not carry a PATH key that overrides the image.
func TestContainerPathNotClobbered(t *testing.T) {
	// Direct unit probe of containerSafeEnv: PATH/HOME/TMPDIR dropped.
	in := map[string]string{
		"PATH":        "/host/bin",
		"HOME":        "/Users/host",
		"TMPDIR":      "/var/folders/x",
		"USER":        "hostuser",
		"SHELL":       "/bin/zsh",
		"CI_MISSING":  "keep-me",
		"KIWI_MARKER": "drop-me-if-in-list",
	}
	out := containerSafeEnv(in)
	for _, bad := range []string{"PATH", "HOME", "TMPDIR", "USER", "SHELL"} {
		if _, ok := out[bad]; ok {
			t.Fatalf("%s survived containerSafeEnv", bad)
		}
	}
	if out["CI_MISSING"] != "keep-me" {
		t.Fatalf("legit job env dropped: %v", out)
	}
}

// TestPassEnvIgnoredForContainer: PassEnv must not smuggle host vars into a
// container job (K1).
func TestPassEnvIgnoredForContainer(t *testing.T) {
	installFakeBins(t)
	t.Setenv("SMUGGLED", "host-value")
	script := `          [ -z "${SMUGGLED:-}" ] || { echo "SMUGGLED=$SMUGGLED"; exit 1; }; echo ok`
	g := envProbeSpec(nativeScript(script, script))
	{
		cj := g.Jobs["probe"]
		cj.Job.Runtime = "container"
		cj.Job.Image = "alpine:3.20"
		g.Jobs["probe"] = cj
	}
	ex := Executor{Opt: Options{Workspace: t.TempDir(), PassEnv: []string{"SMUGGLED"}}, Masker: &secrets.Masker{}}
	res, err := ex.Run(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if res["probe"].Status != model.StatusSuccess {
		t.Fatalf("PassEnv leaked into container: %+v", res["probe"])
	}
}
