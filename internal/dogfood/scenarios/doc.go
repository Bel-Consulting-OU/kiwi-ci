// Package scenarios is the dogfood scenario suite: stable-ID scenarios with
// positive and negative arms, each graded by the outer eight-oracle rule.
//
// A scenario is a REAL Go test that drives the internal dogfood harness
// (internal/dogfood) and proves one audit requirement end to end at the
// level the harness can observe: safety (hostile and contradictory input is
// refused) AND liveness (the honest path still completes and evidence
// verifies), quota truthfulness, evidence tamper-evidence, and no hidden
// retries. The IDs (DF-*) are the stable contract the dogfood report and
// docs reference; renaming an ID is a contract change.
package scenarios
