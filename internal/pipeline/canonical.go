package pipeline

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// kv is one key/value pair of an ordered map.
type kv struct {
	Key   string
	Value any
}

// orderedMap renders a map in sorted key order, so canonical output does not
// depend on Go map iteration order.
type orderedMap []kv

func (m orderedMap) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, p := range m {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := json.Marshal(p.Key)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := json.Marshal(p.Value)
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func pairs[V any](m map[string]V) orderedMap {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(orderedMap, 0, len(keys))
	for _, k := range keys {
		out = append(out, kv{Key: k, Value: m[k]})
	}
	return out
}

// canonicalSpec mirrors Spec but with map-typed fields replaced by ordered
// maps. Struct fields keep their declaration order, and every map renders in
// sorted key order, so two semantically identical specs always produce
// identical bytes.
type canonicalSpec struct {
	Version     int         `json:"version"`
	Name        string      `json:"name,omitempty"`
	Env         orderedMap  `json:"env,omitempty"`
	Secrets     []string    `json:"secrets,omitempty"`
	Concurrency Concurrency `json:"concurrency,omitempty"`
	Defaults    Defaults    `json:"defaults,omitempty"`
	Permissions Permissions `json:"permissions,omitempty"`
	On          orderedMap  `json:"on,omitempty"`
	Inputs      orderedMap  `json:"inputs,omitempty"`
	Packages    orderedMap  `json:"packages,omitempty"`
	Components  orderedMap  `json:"components,omitempty"`
	Jobs        orderedMap  `json:"jobs"`
}

type canonicalJob struct {
	Name         string              `json:"name,omitempty"`
	Needs        []string            `json:"needs,omitempty"`
	If           string              `json:"if,omitempty"`
	Runner       []string            `json:"runner,omitempty"`
	Runtime      string              `json:"runtime,omitempty"`
	Image        string              `json:"image,omitempty"`
	Network      string              `json:"network,omitempty"`
	VM           string              `json:"vm,omitempty"`
	Shell        string              `json:"shell,omitempty"`
	Timeout      Duration            `json:"timeout,omitempty"`
	Retry        Retry               `json:"retry,omitempty"`
	Env          orderedMap          `json:"env,omitempty"`
	Matrix       orderedMap          `json:"matrix,omitempty"`
	Paths        []string            `json:"paths,omitempty"`
	PathsIgnore  []string            `json:"paths_ignore,omitempty"`
	Services     []canonicalService  `json:"services,omitempty"`
	Steps        []canonicalStep     `json:"steps"`
	Cache        []Cache             `json:"cache,omitempty"`
	Artifacts    []Artifact          `json:"artifacts,omitempty"`
	Downloads    []ArtifactInput     `json:"downloads,omitempty"`
	TestReports  []string            `json:"test_reports,omitempty"`
	Environment  Environment         `json:"environment,omitempty"`
	InfraRetries int                 `json:"infra_retries,omitempty"`
	Permissions  Permissions         `json:"permissions,omitempty"`
	Outputs      orderedMap          `json:"outputs,omitempty"`
	Sandbox      Sandbox             `json:"sandbox,omitempty"`
	Placement    Placement           `json:"placement,omitempty"`
	Resources    Resources           `json:"resources,omitempty"`
	Tests        TestConfig          `json:"tests,omitempty"`
	Generate     GenerateSpec        `json:"generate,omitempty"`
	Downstream   canonicalDownstream `json:"downstream,omitempty"`
	Deployment   canonicalDeployment `json:"deployment,omitempty"`
	Snapshot     SnapshotSpec        `json:"snapshot,omitempty"`
	Component    string              `json:"component,omitempty"`
	With         orderedMap          `json:"with,omitempty"`
	QueueTimeout Duration            `json:"queue_timeout,omitempty"`
}

type canonicalService struct {
	Name        string     `json:"name"`
	Image       string     `json:"image"`
	Env         orderedMap `json:"env,omitempty"`
	Healthcheck string     `json:"healthcheck,omitempty"`
	Interval    Duration   `json:"interval,omitempty"`
	Timeout     Duration   `json:"timeout,omitempty"`
	Retries     int        `json:"retries,omitempty"`
}

type canonicalStep struct {
	ID               string     `json:"id,omitempty"`
	Name             string     `json:"name,omitempty"`
	Run              string     `json:"run"`
	If               string     `json:"if,omitempty"`
	Shell            string     `json:"shell,omitempty"`
	WorkingDirectory string     `json:"working_directory,omitempty"`
	Env              orderedMap `json:"env,omitempty"`
	Secrets          []string   `json:"secrets,omitempty"`
	Timeout          Duration   `json:"timeout,omitempty"`
	Retry            Retry      `json:"retry,omitempty"`
	ContinueOnError  bool       `json:"continue_on_error,omitempty"`
}

type canonicalDownstream struct {
	Repository string     `json:"repository,omitempty"`
	Ref        string     `json:"ref,omitempty"`
	Event      string     `json:"event,omitempty"`
	Inputs     orderedMap `json:"inputs,omitempty"`
	Wait       bool       `json:"wait,omitempty"`
}

type canonicalDeployment struct {
	Canary   []canonicalStep `json:"canary,omitempty"`
	Verify   []canonicalStep `json:"verify,omitempty"`
	Rollback []canonicalStep `json:"rollback,omitempty"`
}

type canonicalComponentUse struct {
	Ref  string     `json:"ref"`
	With orderedMap `json:"with,omitempty"`
}

func canonicalJobOf(j Job) canonicalJob {
	c := canonicalJob{
		Name: j.Name, Needs: j.Needs, If: j.If, Runner: j.Runner,
		Runtime: j.Runtime, Image: j.Image, Network: j.Network, VM: j.VM,
		Shell: j.Shell, Timeout: j.Timeout, Retry: j.Retry,
		Env: pairs(j.Env), Matrix: pairs(j.Matrix),
		Paths: j.Paths, PathsIgnore: j.PathsIgnore,
		Cache: j.Cache, Artifacts: j.Artifacts, Downloads: j.Downloads,
		TestReports: j.TestReports, Environment: j.Environment,
		InfraRetries: j.InfraRetries, Permissions: j.Permissions,
		Outputs: pairs(j.Outputs), Sandbox: j.Sandbox, Placement: j.Placement,
		Resources: j.Resources, Tests: j.Tests, Generate: j.Generate,
		Snapshot: j.Snapshot, Component: j.Component, With: pairs(j.With),
		QueueTimeout: j.QueueTimeout,
	}
	c.Services = make([]canonicalService, len(j.Services))
	for i := range j.Services {
		c.Services[i] = canonicalService{
			Name: j.Services[i].Name, Image: j.Services[i].Image,
			Env: pairs(j.Services[i].Env), Healthcheck: j.Services[i].Healthcheck,
			Interval: j.Services[i].Interval, Timeout: j.Services[i].Timeout,
			Retries: j.Services[i].Retries,
		}
	}
	c.Steps = canonicalSteps(j.Steps)
	c.Downstream = canonicalDownstream{
		Repository: j.Downstream.Repository, Ref: j.Downstream.Ref,
		Event: j.Downstream.Event, Inputs: pairs(j.Downstream.Inputs),
		Wait: j.Downstream.Wait,
	}
	c.Deployment = canonicalDeployment{
		Canary:   canonicalSteps(j.Deployment.Canary),
		Verify:   canonicalSteps(j.Deployment.Verify),
		Rollback: canonicalSteps(j.Deployment.Rollback),
	}
	return c
}

func canonicalSteps(in []Step) []canonicalStep {
	out := make([]canonicalStep, len(in))
	for i := range in {
		out[i] = canonicalStep{
			ID: in[i].ID, Name: in[i].Name, Run: in[i].Run, If: in[i].If,
			Shell: in[i].Shell, WorkingDirectory: in[i].WorkingDirectory,
			Env: pairs(in[i].Env), Secrets: in[i].Secrets,
			Timeout: in[i].Timeout, Retry: in[i].Retry,
			ContinueOnError: in[i].ContinueOnError,
		}
	}
	return out
}

// canonicalize builds the ordered clone of a Spec. Secrets are treated as a
// set: they are deduplicated and sorted, matching the server's declared-secret
// dedupe, so declaration order and repetition do not affect the digest.
func canonicalize(s *Spec) canonicalSpec {
	c := canonicalSpec{
		Version: s.Version, Name: s.Name,
		Env: pairs(s.Env), Concurrency: s.Concurrency, Defaults: s.Defaults,
		Permissions: s.Permissions, On: pairs(s.On), Inputs: pairs(s.Inputs),
		Packages: pairs(s.Packages),
	}
	seenSecrets := map[string]bool{}
	for _, name := range s.Secrets {
		seenSecrets[name] = true
	}
	secretNames := make([]string, 0, len(seenSecrets))
	for name := range seenSecrets {
		secretNames = append(secretNames, name)
	}
	sort.Strings(secretNames)
	c.Secrets = secretNames
	components := make(orderedMap, 0, len(s.Components))
	keys := make([]string, 0, len(s.Components))
	for k := range s.Components {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		components = append(components, kv{Key: k, Value: canonicalComponentUse{Ref: s.Components[k].Ref, With: pairs(s.Components[k].With)}})
	}
	c.Components = components
	jobs := make(orderedMap, 0, len(s.Jobs))
	jobKeys := make([]string, 0, len(s.Jobs))
	for k := range s.Jobs {
		jobKeys = append(jobKeys, k)
	}
	sort.Strings(jobKeys)
	for _, k := range jobKeys {
		jobs = append(jobs, kv{Key: k, Value: canonicalJobOf(s.Jobs[k])})
	}
	c.Jobs = jobs
	return c
}

// CanonicalJSON renders the pipeline in a deterministic form: fixed struct
// field order and sorted map keys. Two semantically identical specs (up to
// YAML key order and secret declaration order) produce identical bytes.
func CanonicalJSON(s *Spec) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("nil pipeline")
	}
	return json.Marshal(canonicalize(s))
}

// PipelineDigest is the SHA-256 hex digest of the canonical JSON form, usable
// as a content address for a pipeline definition.
func PipelineDigest(s *Spec) (string, error) {
	b, err := CanonicalJSON(s)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
