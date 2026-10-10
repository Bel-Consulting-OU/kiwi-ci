package model

import "testing"

func TestExecutionAttestationRecordKey(t *testing.T) {
	rec := ExecutionAttestationRecord{JobID: "job-1", Generation: 7}
	if got, want := rec.Key(), "job-1:7"; got != want {
		t.Fatalf("Key() = %q, want %q", got, want)
	}
	if got, want := rec.Key(), AttemptID("job-1", 7); got != want {
		t.Fatalf("Key() = %q, AttemptID = %q", got, want)
	}
}

func TestAttemptIDEncodesNegativeAndZeroGenerations(t *testing.T) {
	cases := []struct {
		jobID string
		gen   int64
		want  string
	}{
		{"j", 0, "j:0"},
		{"j", -3, "j:-3"},
		{"a/b c", 12, "a/b c:12"},
	}
	for _, tc := range cases {
		if got := AttemptID(tc.jobID, tc.gen); got != tc.want {
			t.Errorf("AttemptID(%q, %d) = %q, want %q", tc.jobID, tc.gen, got, tc.want)
		}
	}
}

func TestResourceCapacityFromProfile(t *testing.T) {
	p := RunnerProfile{MaxCPU: 2.5, MaxMemory: 1024, MaxDisk: 4096, MaxPIDs: 128}
	got := ResourceCapacityFromProfile(p)
	want := ResourceCapacity{CPU: 2.5, Memory: 1024, Disk: 4096, PIDs: 128}
	if got != want {
		t.Fatalf("ResourceCapacityFromProfile() = %+v, want %+v", got, want)
	}
	zero := ResourceCapacityFromProfile(RunnerProfile{})
	if zero != (ResourceCapacity{}) {
		t.Fatalf("zero profile must yield zero capacity, got %+v", zero)
	}
}
