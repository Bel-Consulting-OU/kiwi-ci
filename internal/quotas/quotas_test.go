package quotas

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestComputeUsageBasicMath(t *testing.T) {
	r := Rates{CostPerCPUHour: 0.5, CostPerMachineHour: 0.1, PowerWatts: 200}
	cost, energy, err := ComputeUsage(2*time.Hour, 2, r)
	if err != nil {
		t.Fatal(err)
	}
	// cost = 2h × 0.1 + 2h × 2 × 0.5 = 0.2 + 2.0 = 2.2
	if cost != 2.2 {
		t.Fatalf("cost: %v", cost)
	}
	// energy = 2h × 200W = 400 Wh
	if energy != 400 {
		t.Fatalf("energy: %v", energy)
	}
}

func TestComputeUsageRejectsInvalidInputs(t *testing.T) {
	r := Rates{CostPerCPUHour: 1, CostPerMachineHour: 1, PowerWatts: 1}
	cases := []struct {
		name  string
		dur   time.Duration
		cpu   float64
		rates Rates
	}{
		{"zero duration", 0, 1, r},
		{"negative duration", -time.Hour, 1, r},
		{"nan cpu", time.Hour, math.NaN(), r},
		{"inf cpu", time.Hour, math.Inf(1), r},
		{"negative cpu", time.Hour, -1, r},
		{"nan rate", time.Hour, 1, Rates{CostPerCPUHour: math.NaN(), CostPerMachineHour: 1, PowerWatts: 1}},
		{"inf machine rate", time.Hour, 1, Rates{CostPerCPUHour: 1, CostPerMachineHour: math.Inf(1), PowerWatts: 1}},
		{"negative power", time.Hour, 1, Rates{CostPerCPUHour: 1, CostPerMachineHour: 1, PowerWatts: -5}},
	}
	for _, c := range cases {
		if _, _, err := ComputeUsage(c.dur, c.cpu, c.rates); err == nil {
			t.Errorf("%s: want error", c.name)
		}
	}
}

func TestComputeUsageSaturatesOnOverflow(t *testing.T) {
	big := math.MaxFloat64
	r := Rates{CostPerCPUHour: big, CostPerMachineHour: big, PowerWatts: big}
	cost, energy, err := ComputeUsage(time.Hour, 2, r)
	if err != nil {
		t.Fatal(err)
	}
	if cost != math.MaxFloat64 {
		t.Fatalf("cost should saturate, got %v", cost)
	}
	if energy != math.MaxFloat64 {
		t.Fatalf("energy should saturate, got %v", energy)
	}
}

func TestLimitsValidate(t *testing.T) {
	ok := Limits{RepoConcurrency: 1, TeamConcurrency: 2, DailyCost: 3, DailyEnergy: 4}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid limits rejected: %v", err)
	}
	// Zero is allowed (no limit).
	zero := Limits{}
	if err := zero.Validate(); err != nil {
		t.Fatalf("zero limits rejected: %v", err)
	}
	bad := []Limits{
		{RepoConcurrency: -1},
		{TeamConcurrency: math.NaN()},
		{RepoQueueDepth: math.Inf(1)},
		{DailyCost: math.Inf(-1)},
		{DailyEnergy: -0.5},
	}
	for i, l := range bad {
		if err := l.Validate(); err == nil {
			t.Errorf("limits[%d]: want error", i)
		}
	}
}

func TestComputeUsageErrorMessages(t *testing.T) {
	if _, _, err := ComputeUsage(time.Hour, math.NaN(), Rates{CostPerCPUHour: 1, CostPerMachineHour: 1, PowerWatts: 1}); err == nil || !strings.Contains(err.Error(), "cpu") {
		t.Fatalf("want cpu error: %v", err)
	}
}
