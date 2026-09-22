package pipeline

// E3 follow-up pin: the COMPILED validator's service-name duplicate check must
// use the same canonicalization as raw admission and execution
// (CanonicalServiceAlias). Docker network aliases resolve case-insensitively,
// so a compiled payload carrying "Redis" and "redis" declares one runtime DNS
// name and must be rejected — previously only the literal spelling was
// compared, so the collision passed compiled validation and two containers
// could share one alias at runtime.

import (
	"strings"
	"testing"
)

// TestValidateCompiledJobRejectsCanonicalServiceAliasCollision: a compiled
// job whose two service names differ only by case (or by docker-name-invalid
// characters) is rejected with the canonical-collision error, while the
// identical-spelling duplicate keeps the historical "more than once" message.
func TestValidateCompiledJobRejectsCanonicalServiceAliasCollision(t *testing.T) {
	cj := CompiledJob{ID: "x", BaseID: "x", Job: Job{
		Steps: []Step{{Run: "true"}},
		Services: []Service{
			{Name: "Redis", Image: "postgres:16"},
			{Name: "redis", Image: "postgres:15"},
		},
	}}
	err := ValidateCompiledJob(cj)
	if err == nil || !strings.Contains(err.Error(), "both resolve to") {
		t.Fatalf("case-collision error = %v, want canonical-alias rejection", err)
	}
	if !strings.Contains(err.Error(), `"redis"`) {
		t.Fatalf("collision error = %v, want the canonical alias named", err)
	}

	cj.Job.Services = []Service{
		{Name: "db", Image: "postgres:16"},
		{Name: "db", Image: "postgres:15"},
	}
	if err := ValidateCompiledJob(cj); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("literal duplicate error = %v, want duplicate rejection", err)
	}

	// Distinct canonical names are still accepted.
	cj.Job.Services = []Service{
		{Name: "Redis", Image: "postgres:16"},
		{Name: "db", Image: "postgres:15"},
	}
	if err := ValidateCompiledJob(cj); err != nil {
		t.Fatalf("distinct aliases rejected: %v", err)
	}
}
