package pipeline

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Duration struct {
	time.Duration
	// Set records whether the duration was explicitly present in the source
	// document. Validation uses it to reject explicit non-positive values
	// while still treating absent values as "unset".
	Set bool `yaml:"-" json:"-"`
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	if string(b) == "null" || string(b) == `""` {
		d.Duration = 0
		d.Set = false
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	if s == "" {
		d.Duration = 0
		d.Set = false
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	d.Set = true
	return nil
}

func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	if s == "" {
		d.Duration = 0
		d.Set = false
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	d.Set = true
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	// An unset duration marshals as null so a JSON round-trip does not turn
	// "absent" into an explicit zero value (which validation rejects).
	if !d.Set {
		return []byte("null"), nil
	}
	return json.Marshal(d.Duration.String())
}

// MarshalYAML emits a Duration as a plain duration scalar ("5m0s"), never as
// the nested {duration: ...} mapping the embedded time.Duration would
// otherwise produce. A post-encode rewrite of those mappings cannot tell a
// Duration from a user env/vars map whose only key happens to be "duration",
// so the scalar form is produced here instead. An unset Duration marshals as
// null; every Duration field carries omitempty, so absent values stay absent.
func (d Duration) MarshalYAML() (any, error) {
	if !d.Set {
		return nil, nil
	}
	return d.Duration.String(), nil
}

// ByteSize is a memory or disk size in bytes. UnmarshalYAML accepts plain
// byte counts ("1073741824") as well as binary-suffixed values ("512Mi",
// "512MiB", "2Gi", "1T").
type ByteSize int64

var byteSizeRegexp = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)\s*([KkMmGgTtPp]?[Ii]?[Bb]?)$`)

func (b *ByteSize) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("byte size must be a scalar (line %d)", value.Line)
	}
	s := strings.TrimSpace(value.Value)
	if s == "" {
		*b = 0
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n < 0 {
			return fmt.Errorf("byte size must not be negative, got %d", n)
		}
		*b = ByteSize(n)
		return nil
	}
	m := byteSizeRegexp.FindStringSubmatch(s)
	if m == nil {
		return fmt.Errorf("invalid byte size %q (want e.g. \"512Mi\", \"2Gi\" or plain bytes)", s)
	}
	f, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return fmt.Errorf("invalid byte size %q: %w", s, err)
	}
	if f < 0 {
		return fmt.Errorf("byte size must not be negative, got %q", s)
	}
	multipliers := map[string]float64{
		"": 1, "b": 1,
		"k": 1 << 10, "ki": 1 << 10, "kib": 1 << 10, "kb": 1 << 10,
		"m": 1 << 20, "mi": 1 << 20, "mib": 1 << 20, "mb": 1 << 20,
		"g": 1 << 30, "gi": 1 << 30, "gib": 1 << 30, "gb": 1 << 30,
		"t": 1 << 40, "ti": 1 << 40, "tib": 1 << 40, "tb": 1 << 40,
		"p": 1 << 50, "pi": 1 << 50, "pib": 1 << 50, "pb": 1 << 50,
	}
	suffix := strings.ToLower(m[2])
	mult, ok := multipliers[suffix]
	if !ok {
		return fmt.Errorf("invalid byte size suffix %q", m[2])
	}
	*b = ByteSize(f * mult)
	return nil
}

type Spec struct {
	Version     int                     `yaml:"version" json:"version"`
	Name        string                  `yaml:"name,omitempty" json:"name,omitempty"`
	On          map[string]Trigger      `yaml:"on,omitempty" json:"on,omitempty"`
	Inputs      map[string]Input        `yaml:"inputs,omitempty" json:"inputs,omitempty"`
	Env         map[string]string       `yaml:"env,omitempty" json:"env,omitempty"`
	Secrets     []string                `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	Defaults    Defaults                `yaml:"defaults,omitempty" json:"defaults,omitempty"`
	Permissions Permissions             `yaml:"permissions,omitempty" json:"permissions,omitempty"`
	Concurrency Concurrency             `yaml:"concurrency,omitempty" json:"concurrency,omitempty"`
	Packages    map[string]Package      `yaml:"packages,omitempty" json:"packages,omitempty"`
	Components  map[string]ComponentUse `yaml:"components,omitempty" json:"components,omitempty"`
	Jobs        map[string]Job          `yaml:"jobs" json:"jobs"`
	// ProvidedInputs carries the validated run inputs resolved by
	// ResolveInputs (server enqueue). Compile forwards it to
	// CompileWithInputs so the effective compiled jobs, digests and payloads
	// derive from the input-interpolated spec. It is never part of the
	// serialized pipeline: yaml/json decoding leave it nil and canonical
	// rendering ignores it.
	ProvidedInputs map[string]string `yaml:"-" json:"-"`
}

type Input struct {
	Type        string   `yaml:"type,omitempty" json:"type,omitempty"`
	Required    bool     `yaml:"required,omitempty" json:"required,omitempty"`
	Default     any      `yaml:"default,omitempty" json:"default,omitempty"`
	Options     []string `yaml:"options,omitempty" json:"options,omitempty"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
}

type Package struct {
	Paths     []string `yaml:"paths,omitempty" json:"paths,omitempty"`
	DependsOn []string `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`
}

type ComponentUse struct {
	Ref  string            `yaml:"ref" json:"ref"`
	With map[string]string `yaml:"with,omitempty" json:"with,omitempty"`
}

type Trigger struct {
	Branches       []string    `yaml:"branches,omitempty" json:"branches,omitempty"`
	BranchesIgnore []string    `yaml:"branches_ignore,omitempty" json:"branches_ignore,omitempty"`
	Tags           []string    `yaml:"tags,omitempty" json:"tags,omitempty"`
	TagsIgnore     []string    `yaml:"tags_ignore,omitempty" json:"tags_ignore,omitempty"`
	Paths          []string    `yaml:"paths,omitempty" json:"paths,omitempty"`
	PathsIgnore    []string    `yaml:"paths_ignore,omitempty" json:"paths_ignore,omitempty"`
	Actions        []string    `yaml:"actions,omitempty" json:"actions,omitempty"`
	Draft          *bool       `yaml:"draft,omitempty" json:"draft,omitempty"`
	Cron           []CronEntry `yaml:"cron,omitempty" json:"cron,omitempty"`
}

// CronEntry is one scheduled occurrence declaration under on.schedule.
type CronEntry struct {
	Cron     string   `yaml:"cron" json:"cron"`
	Branches []string `yaml:"branches,omitempty" json:"branches,omitempty"`
}

// UnmarshalYAML accepts a plain trigger mapping (push, pull_request, ...),
// a sequence of cron entries, or a single bare cron string (on.schedule).
func (t *Trigger) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		t.Cron = []CronEntry{{Cron: strings.TrimSpace(node.Value)}}
		return nil
	case yaml.SequenceNode:
		var entries []CronEntry
		if err := node.Decode(&entries); err != nil {
			return err
		}
		t.Cron = entries
		return nil
	case yaml.MappingNode:
		hasCron := false
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == "cron" {
				hasCron = true
				break
			}
		}
		if hasCron {
			var entry CronEntry
			if err := node.Decode(&entry); err != nil {
				return err
			}
			t.Cron = []CronEntry{entry}
			return nil
		}
		type plain Trigger
		var p plain
		if err := node.Decode(&p); err != nil {
			return err
		}
		*t = Trigger(p)
		return nil
	default:
		return fmt.Errorf("trigger must be a mapping or a list of cron entries")
	}
}

type Defaults struct {
	Shell   string   `yaml:"shell,omitempty" json:"shell,omitempty"`
	Timeout Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Retry   Retry    `yaml:"retry,omitempty" json:"retry,omitempty"`
}

type Concurrency struct {
	Group            string `yaml:"group,omitempty" json:"group,omitempty"`
	CancelInProgress bool   `yaml:"cancel_in_progress,omitempty" json:"cancel_in_progress,omitempty"`
}

type Environment struct {
	Name        string   `yaml:"name,omitempty" json:"name,omitempty"`
	URL         string   `yaml:"url,omitempty" json:"url,omitempty"`
	Approval    bool     `yaml:"approval,omitempty" json:"approval,omitempty"`
	Branches    []string `yaml:"branches,omitempty" json:"branches,omitempty"`
	Concurrency int      `yaml:"concurrency,omitempty" json:"concurrency,omitempty"`
}

type Permissions struct {
	IDToken bool `yaml:"id_token,omitempty" json:"id_token,omitempty"`
}

// NetworkPolicy declares how strongly a job's network access is restricted.
type NetworkPolicy int

const (
	NetworkPolicyDefault      NetworkPolicy = iota // runtime default / bridge
	NetworkPolicyNone                              // no network at all
	NetworkPolicyServicesOnly                      // only the job's declared services
	NetworkPolicyInternet                          // unrestricted internet access
)

func (n *NetworkPolicy) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("network policy must be a string or integer")
	}
	switch strings.TrimSpace(strings.ToLower(node.Value)) {
	case "", "default", "bridge":
		*n = NetworkPolicyDefault
	case "none":
		*n = NetworkPolicyNone
	case "services-only", "services_only":
		*n = NetworkPolicyServicesOnly
	case "internet", "host":
		*n = NetworkPolicyInternet
	default:
		if v, err := strconv.Atoi(node.Value); err == nil && v >= 0 && v <= 3 {
			*n = NetworkPolicy(v)
			return nil
		}
		return fmt.Errorf("unknown network policy %q", node.Value)
	}
	return nil
}

// Sandbox collects job-level sandboxing requirements. Enforced by the
// executor backends; distributed runners must honor them for untrusted jobs.
type Sandbox struct {
	Rootless       bool          `yaml:"rootless,omitempty" json:"rootless,omitempty"`
	ReadOnlyRootFS bool          `yaml:"read_only_rootfs,omitempty" json:"read_only_rootfs,omitempty"`
	Network        NetworkPolicy `yaml:"network,omitempty" json:"network,omitempty"`
}

// Placement steers a job towards runner regions and label sets.
type Placement struct {
	Regions []string `yaml:"regions,omitempty" json:"regions,omitempty"`
	Labels  []string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// Resources declares the compute resources a job requires.
type Resources struct {
	CPU    float64  `yaml:"cpu,omitempty" json:"cpu,omitempty"`
	Memory ByteSize `yaml:"memory,omitempty" json:"memory,omitempty"`
	Disk   ByteSize `yaml:"disk,omitempty" json:"disk,omitempty"`
	PIDs   int      `yaml:"pids,omitempty" json:"pids,omitempty"`
}

// TestConfig carries test-running metadata for a job.
type TestConfig struct {
	Reports         []string `yaml:"reports,omitempty" json:"reports,omitempty"`
	Manifest        string   `yaml:"manifest,omitempty" json:"manifest,omitempty"`
	Shards          int      `yaml:"shards,omitempty" json:"shards,omitempty"`
	RetryFailed     int      `yaml:"retry_failed,omitempty" json:"retry_failed,omitempty"`
	QuarantineFlaky bool     `yaml:"quarantine_flaky,omitempty" json:"quarantine_flaky,omitempty"`
}

// GenerateSpec requests a downstream child pipeline generation.
type GenerateSpec struct {
	Path     string `yaml:"path,omitempty" json:"path,omitempty"`
	MaxJobs  int    `yaml:"max_jobs,omitempty" json:"max_jobs,omitempty"`
	MaxDepth int    `yaml:"max_depth,omitempty" json:"max_depth,omitempty"`
	// Optional downgrades a rejected fragment upload (validation failure,
	// policy rejection, non-2xx response, network failure) to a warning: the
	// generating job still succeeds. When false (default) the rejected
	// fragment fails the job so a run can never silently lose its generated
	// children.
	Optional bool `yaml:"optional,omitempty" json:"optional,omitempty"`
}

// DownstreamSpec triggers a pipeline in another repository.
type DownstreamSpec struct {
	Repository string            `yaml:"repository,omitempty" json:"repository,omitempty"`
	Ref        string            `yaml:"ref,omitempty" json:"ref,omitempty"`
	Event      string            `yaml:"event,omitempty" json:"event,omitempty"`
	Inputs     map[string]string `yaml:"inputs,omitempty" json:"inputs,omitempty"`
	Wait       bool              `yaml:"wait,omitempty" json:"wait,omitempty"`
}

// SnapshotSpec captures a snapshot on the listed events.
type SnapshotSpec struct {
	On []string `yaml:"on,omitempty" json:"on,omitempty"`
}

// DeploymentSpec carries the three deployment phases as step lists.
type DeploymentSpec struct {
	Canary   []Step `yaml:"canary,omitempty" json:"canary,omitempty"`
	Verify   []Step `yaml:"verify,omitempty" json:"verify,omitempty"`
	Rollback []Step `yaml:"rollback,omitempty" json:"rollback,omitempty"`
}

type Job struct {
	Name         string            `yaml:"name,omitempty" json:"name,omitempty"`
	Needs        []string          `yaml:"needs,omitempty" json:"needs,omitempty"`
	If           string            `yaml:"if,omitempty" json:"if,omitempty"`
	Runner       []string          `yaml:"runner,omitempty" json:"runner,omitempty"`
	Runtime      string            `yaml:"runtime,omitempty" json:"runtime,omitempty"`
	Image        string            `yaml:"image,omitempty" json:"image,omitempty"`
	Network      string            `yaml:"network,omitempty" json:"network,omitempty"`
	VM           string            `yaml:"vm,omitempty" json:"vm,omitempty"`
	Shell        string            `yaml:"shell,omitempty" json:"shell,omitempty"`
	Timeout      Duration          `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Retry        Retry             `yaml:"retry,omitempty" json:"retry,omitempty"`
	Env          map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	Matrix       map[string][]any  `yaml:"matrix,omitempty" json:"matrix,omitempty"`
	Paths        []string          `yaml:"paths,omitempty" json:"paths,omitempty"`
	PathsIgnore  []string          `yaml:"paths_ignore,omitempty" json:"paths_ignore,omitempty"`
	Services     []Service         `yaml:"services,omitempty" json:"services,omitempty"`
	Steps        []Step            `yaml:"steps" json:"steps"`
	Cache        []Cache           `yaml:"cache,omitempty" json:"cache,omitempty"`
	Artifacts    []Artifact        `yaml:"artifacts,omitempty" json:"artifacts,omitempty"`
	Downloads    []ArtifactInput   `yaml:"downloads,omitempty" json:"downloads,omitempty"`
	TestReports  []string          `yaml:"test_reports,omitempty" json:"test_reports,omitempty"`
	Environment  Environment       `yaml:"environment,omitempty" json:"environment,omitempty"`
	InfraRetries int               `yaml:"infra_retries,omitempty" json:"infra_retries,omitempty"`
	Permissions  Permissions       `yaml:"permissions,omitempty" json:"permissions,omitempty"`
	Outputs      map[string]string `yaml:"outputs,omitempty" json:"outputs,omitempty"`
	Sandbox      Sandbox           `yaml:"sandbox,omitempty" json:"sandbox,omitempty"`
	Placement    Placement         `yaml:"placement,omitempty" json:"placement,omitempty"`
	Resources    Resources         `yaml:"resources,omitempty" json:"resources,omitempty"`
	Tests        TestConfig        `yaml:"tests,omitempty" json:"tests,omitempty"`
	Generate     GenerateSpec      `yaml:"generate,omitempty" json:"generate,omitempty"`
	Downstream   DownstreamSpec    `yaml:"downstream,omitempty" json:"downstream,omitempty"`
	Deployment   DeploymentSpec    `yaml:"deployment,omitempty" json:"deployment,omitempty"`
	Snapshot     SnapshotSpec      `yaml:"snapshot,omitempty" json:"snapshot,omitempty"`
	Component    string            `yaml:"component,omitempty" json:"component,omitempty"`
	With         map[string]string `yaml:"with,omitempty" json:"with,omitempty"`
	QueueTimeout Duration          `yaml:"queue_timeout,omitempty" json:"queue_timeout,omitempty"`
}

type Service struct {
	Name        string            `yaml:"name" json:"name"`
	Image       string            `yaml:"image" json:"image"`
	Env         map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	Healthcheck string            `yaml:"healthcheck,omitempty" json:"healthcheck,omitempty"`
	Interval    Duration          `yaml:"interval,omitempty" json:"interval,omitempty"`
	Timeout     Duration          `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Retries     int               `yaml:"retries,omitempty" json:"retries,omitempty"`
}

type Step struct {
	ID               string            `yaml:"id,omitempty" json:"id,omitempty"`
	Name             string            `yaml:"name,omitempty" json:"name,omitempty"`
	Run              string            `yaml:"run" json:"run"`
	If               string            `yaml:"if,omitempty" json:"if,omitempty"`
	Shell            string            `yaml:"shell,omitempty" json:"shell,omitempty"`
	WorkingDirectory string            `yaml:"working_directory,omitempty" json:"working_directory,omitempty"`
	Env              map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	Secrets          []string          `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	Timeout          Duration          `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Retry            Retry             `yaml:"retry,omitempty" json:"retry,omitempty"`
	ContinueOnError  bool              `yaml:"continue_on_error,omitempty" json:"continue_on_error,omitempty"`
}

type Retry struct {
	Max     int      `yaml:"max,omitempty" json:"max,omitempty"`
	Backoff Duration `yaml:"backoff,omitempty" json:"backoff,omitempty"`
	On      []string `yaml:"on,omitempty" json:"on,omitempty"`
}

type Cache struct {
	Name        string   `yaml:"name,omitempty" json:"name,omitempty"`
	Paths       []string `yaml:"paths" json:"paths"`
	Key         string   `yaml:"key,omitempty" json:"key,omitempty"`
	HashFiles   []string `yaml:"hash_files,omitempty" json:"hash_files,omitempty"`
	RestoreKeys []string `yaml:"restore_keys,omitempty" json:"restore_keys,omitempty"`
}

type ArtifactInput struct {
	From string `yaml:"from" json:"from"`
	Name string `yaml:"name" json:"name"`
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
}

type Artifact struct {
	Name      string          `yaml:"name" json:"name"`
	Paths     []string        `yaml:"paths" json:"paths"`
	If        string          `yaml:"if,omitempty" json:"if,omitempty"`
	Retention string          `yaml:"retention,omitempty" json:"retention,omitempty"`
	SBOM      string          `yaml:"sbom,omitempty" json:"sbom,omitempty"`
	Sigstore  *SigstoreConfig `yaml:"sigstore,omitempty" json:"sigstore,omitempty"`
	Required  bool            `yaml:"required,omitempty" json:"required,omitempty"`
	// MaxSize caps the artifact payload in bytes ("10MiB" and plain byte
	// counts both decode through ByteSize). The server enforces it at the
	// upload reader, before any staging or hashing, and rejects oversize
	// bodies with 413. Zero means the global ceiling only.
	MaxSize ByteSize `yaml:"max_size,omitempty" json:"max_size,omitempty"`
}

// SigstoreConfig declares Sigstore attestation requirements for an artifact.
type SigstoreConfig struct {
	Required bool   `yaml:"required,omitempty" json:"required,omitempty"`
	Issuer   string `yaml:"issuer,omitempty" json:"issuer,omitempty"`
	Identity string `yaml:"identity,omitempty" json:"identity,omitempty"`
}
