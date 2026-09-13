package pipeline

import (
	"encoding/json"
	"fmt"
	"time"
)

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	if string(b) == "null" || string(b) == `""` {
		d.Duration = 0
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	if s == "" {
		d.Duration = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

type Spec struct {
	Version     int                `yaml:"version" json:"version"`
	Name        string             `yaml:"name,omitempty" json:"name,omitempty"`
	Env         map[string]string  `yaml:"env,omitempty" json:"env,omitempty"`
	Secrets     []string           `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	Concurrency Concurrency        `yaml:"concurrency,omitempty" json:"concurrency,omitempty"`
	Defaults    Defaults           `yaml:"defaults,omitempty" json:"defaults,omitempty"`
	On          map[string]Trigger `yaml:"on,omitempty" json:"on,omitempty"`
	Jobs        map[string]Job     `yaml:"jobs" json:"jobs"`
}

type Trigger struct {
	Branches       []string `yaml:"branches,omitempty" json:"branches,omitempty"`
	BranchesIgnore []string `yaml:"branches_ignore,omitempty" json:"branches_ignore,omitempty"`
	Tags           []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	TagsIgnore     []string `yaml:"tags_ignore,omitempty" json:"tags_ignore,omitempty"`
	Paths          []string `yaml:"paths,omitempty" json:"paths,omitempty"`
	PathsIgnore    []string `yaml:"paths_ignore,omitempty" json:"paths_ignore,omitempty"`
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
	Name      string   `yaml:"name" json:"name"`
	Paths     []string `yaml:"paths" json:"paths"`
	If        string   `yaml:"if,omitempty" json:"if,omitempty"`
	Retention string   `yaml:"retention,omitempty" json:"retention,omitempty"`
}
