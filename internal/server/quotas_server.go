package server

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/quotas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// Queue reason codes for the daily budget gates. They follow the REPO_QUOTA
// convention (a machine-readable code stored on the job's QueueReason).
const (
	queueReasonDailyCostExceeded   = "DAILY_COST_EXCEEDED"
	queueReasonDailyEnergyExceeded = "DAILY_ENERGY_EXCEEDED"
)

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
	newQueued := float64(jobCount)
	l := s.QuotaLimits
	switch {
	case l.RepoConcurrency > 0 && float64(repoRunning) >= l.RepoConcurrency:
		return quotaDenied("REPO_QUOTA", fmt.Sprintf("repository %s already has %d running job(s), concurrency limit %g", run.Repo, repoRunning, l.RepoConcurrency))
	case l.TeamConcurrency > 0 && float64(teamRunning) >= l.TeamConcurrency:
		return quotaDenied("TEAM_QUOTA", fmt.Sprintf("team %s already has %d running job(s), concurrency limit %g", repoURLTeam(run.Repo), teamRunning, l.TeamConcurrency))
	case l.RepoQueueDepth > 0 && satAddF(float64(repoQueued), newQueued) > l.RepoQueueDepth:
		return quotaDenied("REPO_QUOTA", fmt.Sprintf("repository %s queue depth would reach %d, limit %g", run.Repo, repoQueued+jobCount, l.RepoQueueDepth))
	case l.TeamQueueDepth > 0 && satAddF(float64(teamQueued), newQueued) > l.TeamQueueDepth:
		return quotaDenied("TEAM_QUOTA", fmt.Sprintf("team %s queue depth would reach %d, limit %g", repoURLTeam(run.Repo), teamQueued+jobCount, l.TeamQueueDepth))
	}
	return nil
}

// quotaCountsLocked computes the current repo/team running and queued job
// counts for a run's repository URL. The memory-mode caller holds s.mu; the
// DB-mode branch queries the SQL store.
func (s *Server) quotaCountsLocked(run model.Run) (repoRunning, repoQueued, teamRunning, teamQueued int) {
	team := repoURLTeam(run.Repo)
	if s.DB != nil {
		ctx := context.Background()
		queued, err := s.DB.ListQueuedJobs(ctx)
		if err == nil {
			for _, j := range queued {
				if j.RepoURL == run.Repo {
					repoQueued++
				}
				if repoURLTeam(j.RepoURL) == team {
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
				if j.RepoURL == run.Repo {
					repoRunning++
				}
				if repoURLTeam(j.RepoURL) == team {
					teamRunning++
				}
			}
		}
		return
	}
	for _, j := range s.jobs {
		switch j.Status {
		case model.StatusRunning:
			if j.RepoURL == run.Repo {
				repoRunning++
			}
			if repoURLTeam(j.RepoURL) == team {
				teamRunning++
			}
		case model.StatusQueued:
			if j.RepoURL == run.Repo {
				repoQueued++
			}
			if repoURLTeam(j.RepoURL) == team {
				teamQueued++
			}
		}
	}
	return
}

// recordJobUsage computes the completed job's cost and energy from its
// frozen lease-time rates and wall-clock duration, persists them on the
// job, and aggregates them into the server usage metrics and the trailing
// in-memory window (memory mode; DB mode reads UsageStore.RecentUsage).
func (s *Server) recordJobUsage(j *model.Job, finished time.Time) {
	if j.StartedAt == nil {
		return
	}
	dur := finished.Sub(*j.StartedAt)
	cost, energy, err := quotas.ComputeUsage(dur, 1, quotas.Rates{CostPerMachineHour: j.CostRate, PowerWatts: j.PowerWatts})
	if err != nil {
		return
	}
	j.Cost = cost
	j.EnergyWh = energy
	s.metricAdd("kiwi_usage_cost_total", cost, nil)
	s.metricAdd("kiwi_usage_energy_total", energy, nil)
	if s.DB != nil {
		return
	}
	s.usageMu.Lock()
	s.usage = append(s.usage, usageEntry{FinishedAt: finished, Cost: cost, EnergyWh: energy})
	cutoff := finished.Add(-24 * time.Hour)
	kept := s.usage[:0]
	for _, e := range s.usage {
		if e.FinishedAt.After(cutoff) {
			kept = append(kept, e)
		}
	}
	s.usage = kept
	s.usageMu.Unlock()
}

// dailyBudgetExceeded reports whether the trailing-24h cost or energy
// budget is exhausted. DB mode queries UsageStore.RecentUsage; memory mode
// sums the in-memory window. The returned reason is the queue reason code
// to attach to waiting jobs while leases are refused.
func (s *Server) dailyBudgetExceeded(ctx context.Context) (reason string, exceeded bool) {
	var cost, energy float64
	if s.DB != nil {
		if us, ok := s.DB.(storage.UsageStore); ok {
			cost, energy, _ = us.RecentUsage(ctx, time.Now().UTC().Add(-24*time.Hour))
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
		return queueReasonDailyCostExceeded, true
	case s.DailyEnergyLimit > 0 && energy >= s.DailyEnergyLimit:
		return queueReasonDailyEnergyExceeded, true
	}
	return "", false
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
