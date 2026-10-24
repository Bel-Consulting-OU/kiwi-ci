package executor

import "testing"

func TestWindowsCandidatesPATHEXT(t *testing.T) {
	got := windowsCandidates(`C:\bin\python`, ".COM;.EXE;.BAT")
	wantPrefix := `C:\bin\python`
	if len(got) == 0 || got[0] != wantPrefix {
		t.Fatalf("candidates[0] = %q", got)
	}
	foundExe := false
	for _, c := range got {
		if c == wantPrefix+".EXE" {
			foundExe = true
		}
	}
	if !foundExe {
		t.Fatalf("missing .EXE candidate: %v", got)
	}
	// Already .exe listed: exact first only.
	got2 := windowsCandidates(`C:\bin\app.exe`, ".COM;.EXE")
	if len(got2) != 1 || got2[0] != `C:\bin\app.exe` {
		t.Fatalf("exact ext candidates = %v", got2)
	}
}
