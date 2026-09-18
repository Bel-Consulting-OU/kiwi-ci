package server

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// Queue reason codes for the daily budget gates. They follow the REPO_QUOTA
// convention (a machine-readable code stored on the job's QueueReason).
const (
	queueReasonDailyCostExceeded   = "DAILY_COST_EXCEEDED"
	queueReasonDailyEnergyExceeded = "DAILY_ENERGY_EXCEEDED"
	// queueReasonBudgetStateUnavailable marks that the usage store could
	// not answer the budget query, so the gate fails closed.
	queueReasonBudgetStateUnavailable = "BUDGET_STATE_UNAVAILABLE"
)

// budgetUnavailableError refuses an enqueue/lease when the usage store
// cannot answer the daily-budget query and QuotaFailOpen is false.
type budgetUnavailableError struct {
	Reason string
}

func (e *budgetUnavailableError) Error() string {
	return e.Reason + ": quota budget state unavailable"
}

// usageEntry is one completed job's recorded usage for the trailing-24h
// in-memory budget window (memory/fs mode).
type usageEntry struct {
	FinishedAt time.Time
	Cost       float64
	EnergyWh   float64
}

// satAddF adds with saturation at math.MaxFloat64 (quotas arithmetic is
// saturating; counts converted to float must be too).
func satAddF(a, b float64) float64 {
	if a > math.MaxFloat64-b {
		return math.MaxFloat64
	}
	return a + b
}

// admitQuotaLocked enforces the repo/team concurrency and queue-depth
// quotas for a new run before it is inserted. Zero limits are unlimited.
// A rejection is a 429 admission error carrying the REPO_QUOTA/TEAM_QUOTA
// reason. The memory-mode call must hold s.mu; the DB-mode call is
// self-contained.
func (s *Server) admitQuotaLocked(run model.Run, jobCount int) error {
	repoRunning, repoQueued, teamRunning, teamQueued := s.quotaCountsLocked(run)
	repoID := repoIDForRun(run)
	team := repoTeamKey(repoID)
	newQueued := float64(jobCount)
	l := s.QuotaLimits
	switch {
	case l.RepoConcurrency > 0 && float64(repoRunning) >= l.RepoConcurrency:
		return quotaDenied("REPO_QUOTA", fmt.Sprintf("repository %s already has %d running job(s), concurrency limit %g", repoID, repoRunning, l.RepoConcurrency))
	case l.TeamConcurrency > 0 && float64(teamRunning) >= l.TeamConcurrency:
		return quotaDenied("TEAM_QUOTA", fmt.Sprintf("team %s already has %d running job(s), concurrency limit %g", team, teamRunning, l.TeamConcurrency))
	case l.RepoQueueDepth > 0 && satAddF(float64(repoQueued), newQueued) > l.RepoQueueDepth:
		return quotaDenied("REPO_QUOTA", fmt.Sprintf("repository %s queue depth would reach %d, limit %g", repoID, repoQueued+jobCount, l.RepoQueueDepth))
	case l.TeamQueueDepth > 0 && satAddF(float64(teamQueued), newQueued) > l.TeamQueueDepth:
		return quotaDenied("TEAM_QUOTA", fmt.Sprintf("team %s queue depth would reach %d, limit %g", team, teamQueued+jobCount, l.TeamQueueDepth))
	}
	return nil
}

// quotaCountsLocked computes the current repo/team running and queued job
// counts for a run's canonical repository identity. Jobs are matched by
// their own canonical RepoID (derived for legacy payloads), so
// github.com/acme/backend and gitlab.company.com/acme/backend never share a
// count. The memory-mode caller holds s.mu; the DB-mode branch queries the
// SQL store.
func (s *Server) quotaCountsLocked(run model.Run) (repoRunning, repoQueued, teamRunning, teamQueued int) {
	repoID := repoIDForRun(run)
	team := repoTeamKey(repoID)
	count := func(j model.Job) (repo, teamKey string) {
		repo = repoIDForJob(j)
		return repo, repoTeamKey(repo)
	}
	if s.DB != nil {
		ctx := context.Background()
		queued, err := s.DB.ListQueuedJobs(ctx)
		if err == nil {
			for _, j := range queued {
				repo, teamKey := count(j)
				if repo == repoID {
					repoQueued++
				}
				if teamKey == team {
					teamQueued++
				}
			}
		}
		runs, err := s.DB.ListRuns(ctx, 10000)
		if err != nil {
			return
		}
		for _, r := range runs {
			if r.Status.Terminal() {
				continue
			}
			jobs, err := s.DB.ListJobsByRun(ctx, r.ID)
			if err != nil {
				continue
			}
			for _, j := range jobs {
				if j.Status != model.StatusRunning {
					continue
				}
				repo, teamKey := count(j)
				if repo == repoID {
					repoRunning++
				}
				if teamKey == team {
					teamRunning++
				}
			}
		}
		return
	}
	for _, j := range s.jobs {
		switch j.Status {
		case model.StatusRunning:
			repo, teamKey := count(j)
			if repo == repoID {
				repoRunning++
			}
			if teamKey == team {
				teamRunning++
			}
		case model.StatusQueued:
			repo, teamKey := count(j)
			if repo == repoID {
				repoQueued++
			}
			if teamKey == team {
				teamQueued++
			}
		}
	}
	return
}

// dailyBudgetExceeded reports whether the trailing-24h cost or energy
// budget is exhausted. DB mode queries UsageStore.RecentUsage; memory mode
// sums the in-memory window. The returned reason is the queue reason code
// to attach to waiting jobs while leases are refused.
func (s *Server) dailyBudgetExceeded(ctx context.Context) (reason string, exceeded bool) {
	reason, exceeded, _ = s.dailyBudgetStateDB(ctx)
	return reason, exceeded
}

// dailyBudgetStateDB evaluates the trailing-24h daily budget: memory mode
// never errors; DB mode queries UsageStore.RecentUsage and reports its
// error so the gate can fail closed when QuotaFailOpen is false.
func (s *Server) dailyBudgetStateDB(ctx context.Context) (reason string, exceeded bool, err error) {
	var cost, energy float64
	if s.DB != nil {
		if us, ok := s.DB.(storage.UsageStore); ok {
			cost, energy, err = us.RecentUsage(ctx, time.Now().UTC().Add(-24*time.Hour))
			if err != nil {
				return "", false, err
			}
		}
	} else {
		s.usageMu.Lock()
		cutoff := time.Now().UTC().Add(-24 * time.Hour)
		for _, e := range s.usage {
			if e.FinishedAt.After(cutoff) {
				cost = satAddF(cost, e.Cost)
				energy = satAddF(energy, e.EnergyWh)
			}
		}
		s.usageMu.Unlock()
	}
	switch {
	case s.DailyCostLimit > 0 && cost >= s.DailyCostLimit:
		return queueReasonDailyCostExceeded, true, nil
	case s.DailyEnergyLimit > 0 && energy >= s.DailyEnergyLimit:
		return queueReasonDailyEnergyExceeded, true, nil
	}
	return "", false, nil
}

// markQueueReasonsAll annotates every queued job with reason so operators
// can see why leases are being refused (daily budget gates).
func (s *Server) markQueueReasonsAll(ctx context.Context, reason string) {
	if s.DB != nil {
		jobs, err := s.DB.ListQueuedJobs(ctx)
		if err != nil {
			return
		}
		reasons := map[string]string{}
		for _, j := range jobs {
			if j.Status == model.StatusQueued {
				reasons[j.ID] = reason
			}
		}
		if qs, ok := s.DB.(storage.QueueReasonStore); ok {
			if err := qs.SetQueueReasons(ctx, reasons); err != nil {
				s.logError("quota: persist daily budget queue reasons failed", "error", err.Error())
			}
		}
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, j := range s.jobs {
		if j.Status != model.StatusQueued {
			continue
		}
		if j.QueueReason != reason {
			j.QueueReason = reason
			s.jobs[id] = j
		}
	}
}
