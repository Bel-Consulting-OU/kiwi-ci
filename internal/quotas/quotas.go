// Package quotas computes resource usage and validates quota limits for
// runners, repositories and teams. All arithmetic is saturating: invalid
// (NaN/Inf/negative) inputs are rejected and overflow clamps at
// math.MaxFloat64 instead of wrapping.
package quotas

import (
	"fmt"
	"math"
	"time"
)

// Rates is the cost model for one machine class.
type Rates struct {
	CostPerCPUHour     float64
	CostPerMachineHour float64
	PowerWatts         float64
}

// ComputeUsage derives cost and energy from a job's duration and CPU
// allocation. cost is duration × (CostPerMachineHour + cpu×CostPerCPUHour)
// in hours; energyWh is duration × PowerWatts in hours. Invalid inputs
// (NaN, Inf, negatives) are rejected; valid results saturate at
// math.MaxFloat64.
func ComputeUsage(dur time.Duration, cpu float64, r Rates) (cost, energyWh float64, err error) {
	if dur <= 0 {
		return 0, 0, fmt.Errorf("duration must be positive, got %s", dur)
	}
	if err := validFiniteNonNegative(cpu, "cpu"); err != nil {
		return 0, 0, err
	}
	if err := validFiniteNonNegative(r.CostPerCPUHour, "cost_per_cpu_hour"); err != nil {
		return 0, 0, err
	}
	if err := validFiniteNonNegative(r.CostPerMachineHour, "cost_per_machine_hour"); err != nil {
		return 0, 0, err
	}
	if err := validFiniteNonNegative(r.PowerWatts, "power_watts"); err != nil {
		return 0, 0, err
	}
	hours := dur.Hours()
	cost = satMul(r.CostPerMachineHour, hours)
	cpuCost := satMul(r.CostPerCPUHour, cpu)
	cpuCost = satMul(cpuCost, hours)
	cost = satAdd(cost, cpuCost)
	energyWh = satMul(r.PowerWatts, hours)
	return cost, energyWh, nil
}

// Limits is a quota policy bucket. Every field must be finite and
// non-negative.
type Limits struct {
	RepoConcurrency float64
	TeamConcurrency float64
	RepoQueueDepth  float64
	TeamQueueDepth  float64
	DailyCost       float64
	DailyEnergy     float64
}

// Validate rejects NaN, infinite or negative limits.
func (l *Limits) Validate() error {
	for name, v := range map[string]float64{
		"repo_concurrency": l.RepoConcurrency,
		"team_concurrency": l.TeamConcurrency,
		"repo_queue_depth": l.RepoQueueDepth,
		"team_queue_depth": l.TeamQueueDepth,
		"daily_cost":       l.DailyCost,
		"daily_energy":     l.DailyEnergy,
	} {
		if err := validFiniteNonNegative(v, name); err != nil {
			return err
		}
	}
	return nil
}

func validFiniteNonNegative(v float64, name string) error {
	if math.IsNaN(v) {
		return fmt.Errorf("%s must not be NaN", name)
	}
	if math.IsInf(v, 0) {
		return fmt.Errorf("%s must be finite", name)
	}
	if v < 0 {
		return fmt.Errorf("%s must not be negative (got %g)", name, v)
	}
	return nil
}

// satMul multiplies with saturation at math.MaxFloat64.
func satMul(a, b float64) float64 {
	if a == 0 || b == 0 {
		return 0
	}
	if a > math.MaxFloat64/b {
		return math.MaxFloat64
	}
	return a * b
}

// satAdd adds with saturation at math.MaxFloat64.
func satAdd(a, b float64) float64 {
	if a > math.MaxFloat64-b {
		return math.MaxFloat64
	}
	return a + b
}
