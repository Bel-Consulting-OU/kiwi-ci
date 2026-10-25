package executor

import "testing"

func TestWindowsCandidatesPATHEXT(t *testing.T) {
	// Extensionless base: PATHEXT forms only, never the bare name
	// (Windows LookPath requires an executable extension).
	got := windowsCandidates(`C:\bin\python`, ".COM;.EXE;.BAT")
	want := []string{`C:\bin\python.COM`, `C:\bin\python.EXE`, `C:\bin\python.BAT`}
	if len(got) != len(want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidates[%d] = %q, want %q (full=%v)", i, got[i], want[i], got)
		}
	}
	// Already .exe listed: exact first only.
	got2 := windowsCandidates(`C:\bin\app.exe`, ".COM;.EXE")
	if len(got2) != 1 || got2[0] != `C:\bin\app.exe` {
		t.Fatalf("exact ext candidates = %v", got2)
	}
	// Non-PATHEXT extension: exact form first, then suffixed forms.
	got3 := windowsCandidates(`C:\bin\script.py`, ".COM;.EXE")
	if len(got3) < 2 || got3[0] != `C:\bin\script.py` {
		t.Fatalf("non-pathext candidates = %v", got3)
	}
}
