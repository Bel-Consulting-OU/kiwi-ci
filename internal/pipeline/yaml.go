package pipeline

// This file replaces the hand-rolled subset YAML parser with a strict
// yaml.v3 node-based pipeline. The typed Spec is decoded through yaml.v3
// itself, so scalars (numbers, booleans, timestamps) are resolved by the same
// core schema that performs the decode. Before decoding, the raw node tree is
// validated for the features Kiwi rejects: aliases, anchors, merge keys,
// custom tags, duplicate keys, excessive nesting, oversized scalars, invalid
// UTF-8 and oversized sources. Known-field strictness is enforced by
// validateKnownFields below (yaml.v3's own KnownFields mode cannot express
// the per-section tables and their line-accurate errors).

import (
	"bytes"
	"fmt"
	"io"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	maxPipelineBytes = 2 << 20 // 2 MiB source limit
	maxScalarBytes   = 1 << 20 // 1 MiB per scalar
	maxYAMLDepth     = 100
	maxYAMLNodes     = 1_000_000
)

// allowedYAMLTags are the only tags permitted in pipeline documents. Custom
// tags ("!foo") and other resolved tags fail admission.
var allowedYAMLTags = map[string]bool{
	"": true, "!!str": true, "!!bool": true, "!!int": true,
	"!!float": true, "!!null": true, "!!map": true, "!!seq": true,
	"!!timestamp": true,
}

func parseYAML(data []byte, out any) error {
	if len(data) > maxPipelineBytes {
		return fmt.Errorf("yaml: source size %d exceeds %d byte limit", len(data), maxPipelineBytes)
	}
	if !utf8.Valid(data) {
		off := firstInvalidUTF8Offset(data)
		line, col := lineCol(data, off)
		return fmt.Errorf("yaml: invalid UTF-8 at byte %d (line %d, column %d)", off, line, col)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if err == io.EOF {
			return fmt.Errorf("empty pipeline")
		}
		return yamlError(err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return fmt.Errorf("yaml: line %d: multiple documents are not allowed", extra.Line)
	} else if err != io.EOF {
		return yamlError(err)
	}
	if doc.Kind == 0 || (doc.Kind == yaml.DocumentNode && len(doc.Content) == 0) {
		return fmt.Errorf("empty pipeline")
	}
	nodes := 0
	if err := validateYAMLNode(&doc, 0, &nodes); err != nil {
		return err
	}
	if err := validateKnownFields(&doc, ""); err != nil {
		return err
	}
	target := doc
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		target = *doc.Content[0]
	}
	if target.Kind != yaml.MappingNode {
		return fmt.Errorf("yaml: line %d: pipeline must be a mapping", target.Line)
	}
	if err := target.Decode(out); err != nil {
		return fmt.Errorf("yaml: %w", err)
	}
	return nil
}

func yamlError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if len(msg) >= 5 && msg[:5] == "yaml:" {
		return err
	}
	return fmt.Errorf("yaml: %w", err)
}

func firstInvalidUTF8Offset(b []byte) int {
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size == 1 {
			return i
		}
		i += size
	}
	return -1
}

func lineCol(data []byte, off int) (line, col int) {
	line, col = 1, 1
	for i := 0; i < off && i < len(data); i++ {
		if data[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

func validateYAMLNode(n *yaml.Node, depth int, nodes *int) error {
	if depth > maxYAMLDepth {
		return fmt.Errorf("yaml: line %d: nesting exceeds %d levels", n.Line, maxYAMLDepth)
	}
	*nodes++
	if *nodes > maxYAMLNodes {
		return fmt.Errorf("yaml: line %d: document exceeds %d nodes", n.Line, maxYAMLNodes)
	}
	switch n.Kind {
	case yaml.AliasNode:
		return fmt.Errorf("yaml: line %d: aliases are not allowed", n.Line)
	case yaml.DocumentNode:
		for _, c := range n.Content {
			if err := validateYAMLNode(c, depth+1, nodes); err != nil {
				return err
			}
		}
		return nil
	}
	if n.Anchor != "" {
		return fmt.Errorf("yaml: line %d: anchors are not allowed (&%s)", n.Line, n.Anchor)
	}
	if n.Kind == yaml.ScalarNode && len(n.Value) > maxScalarBytes {
		return fmt.Errorf("yaml: line %d: scalar exceeds %d byte limit", n.Line, maxScalarBytes)
	}
	if n.Tag == "!!merge" {
		return fmt.Errorf("yaml: line %d: merge keys (<<) are not allowed", n.Line)
	}
	if !allowedYAMLTags[n.Tag] {
		return fmt.Errorf("yaml: line %d: unsupported tag %q", n.Line, n.Tag)
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]int{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Tag == "!!merge" || (k.Kind == yaml.ScalarNode && k.Value == "<<") {
				return fmt.Errorf("yaml: line %d: merge keys (<<) are not allowed", k.Line)
			}
			if first, ok := seen[k.Value]; ok {
				return fmt.Errorf("yaml: line %d: duplicate key %q (first at line %d)", k.Line, k.Value, first)
			}
			seen[k.Value] = k.Line
			if err := validateYAMLNode(k, depth+1, nodes); err != nil {
				return err
			}
			if err := validateYAMLNode(v, depth+1, nodes); err != nil {
				return err
			}
		}
		return nil
	}
	for _, c := range n.Content {
		if err := validateYAMLNode(c, depth+1, nodes); err != nil {
			return err
		}
	}
	return nil
}

// knownFieldTables maps canonical section paths to the fields allowed there.
// A "*" segment stands for any key of a map-of-sections (jobs, on, inputs,
// packages, components) or any sequence item. Paths not present in the table
// are free-form maps (env, matrix, outputs, with, downstream inputs) and are
// not key-checked, though the node-level walk above still applies.
var knownFieldTables = map[string]map[string]bool{
	"": {
		"version": true, "name": true, "on": true, "inputs": true, "env": true,
		"secrets": true, "defaults": true, "permissions": true, "concurrency": true,
		"packages": true, "components": true, "jobs": true,
	},
	"defaults":       {"shell": true, "timeout": true, "retry": true},
	"concurrency":    {"group": true, "cancel_in_progress": true},
	"permissions":    {"id_token": true},
	"defaults.retry": {"max": true, "backoff": true, "on": true},
	"on.*": {
		"branches": true, "branches_ignore": true, "tags": true, "tags_ignore": true,
		"paths": true, "paths_ignore": true, "actions": true, "draft": true,
		"cron": true,
	},
	"inputs.*":     {"type": true, "required": true, "default": true, "options": true, "description": true},
	"packages.*":   {"paths": true, "depends_on": true},
	"components.*": {"ref": true, "with": true},
	"jobs.*": {
		"name": true, "needs": true, "if": true, "runner": true, "runtime": true,
		"image": true, "network": true, "vm": true, "shell": true, "timeout": true,
		"retry": true, "env": true, "matrix": true, "paths": true, "paths_ignore": true,
		"services": true, "steps": true, "cache": true, "artifacts": true,
		"downloads": true, "test_reports": true, "environment": true,
		"infra_retries": true, "permissions": true, "outputs": true,
		"placement": true, "sandbox": true, "resources": true,
		"tests": true, "generate": true, "downstream": true, "deployment": true,
		"snapshot": true, "component": true, "with": true, "queue_timeout": true,
	},
	"jobs.*.retry":                       {"max": true, "backoff": true, "on": true},
	"jobs.*.environment":                 {"name": true, "url": true, "approval": true, "branches": true, "concurrency": true},
	"jobs.*.sandbox":                     {"rootless": true, "read_only_rootfs": true, "network": true},
	"jobs.*.placement":                   {"regions": true, "labels": true},
	"jobs.*.resources":                   {"cpu": true, "memory": true, "disk": true, "pids": true},
	"jobs.*.tests":                       {"reports": true, "manifest": true, "shards": true, "retry_failed": true, "quarantine_flaky": true},
	"jobs.*.generate":                    {"path": true, "max_jobs": true, "max_depth": true, "optional": true},
	"jobs.*.downstream":                  {"repository": true, "ref": true, "event": true, "inputs": true, "wait": true},
	"jobs.*.snapshot":                    {"on": true},
	"jobs.*.deployment":                  {"canary": true, "verify": true, "rollback": true},
	"jobs.*.services.*":                  {"name": true, "image": true, "env": true, "healthcheck": true, "interval": true, "timeout": true, "retries": true},
	"jobs.*.steps.*":                     {"id": true, "name": true, "run": true, "if": true, "shell": true, "working_directory": true, "env": true, "secrets": true, "timeout": true, "retry": true, "continue_on_error": true},
	"jobs.*.steps.*.retry":               {"max": true, "backoff": true, "on": true},
	"jobs.*.cache.*":                     {"name": true, "paths": true, "key": true, "hash_files": true, "restore_keys": true},
	"jobs.*.artifacts.*":                 {"name": true, "paths": true, "if": true, "retention": true, "sbom": true, "sigstore": true, "required": true},
	"jobs.*.artifacts.*.sigstore":        {"required": true, "issuer": true, "identity": true},
	"jobs.*.downloads.*":                 {"from": true, "name": true, "path": true},
	"jobs.*.deployment.canary.*":         {"id": true, "name": true, "run": true, "if": true, "shell": true, "working_directory": true, "env": true, "secrets": true, "timeout": true, "retry": true, "continue_on_error": true},
	"jobs.*.deployment.verify.*":         {"id": true, "name": true, "run": true, "if": true, "shell": true, "working_directory": true, "env": true, "secrets": true, "timeout": true, "retry": true, "continue_on_error": true},
	"jobs.*.deployment.rollback.*":       {"id": true, "name": true, "run": true, "if": true, "shell": true, "working_directory": true, "env": true, "secrets": true, "timeout": true, "retry": true, "continue_on_error": true},
	"jobs.*.deployment.canary.*.retry":   {"max": true, "backoff": true, "on": true},
	"jobs.*.deployment.verify.*.retry":   {"max": true, "backoff": true, "on": true},
	"jobs.*.deployment.rollback.*.retry": {"max": true, "backoff": true, "on": true},
}

// sequenceSections are job fields whose sequence items are mappings with
// their own known-field table.
var sequenceSections = map[string]bool{
	"jobs.*.steps": true, "jobs.*.services": true, "jobs.*.cache": true,
	"jobs.*.artifacts": true, "jobs.*.downloads": true,
	"jobs.*.deployment.canary": true, "jobs.*.deployment.verify": true, "jobs.*.deployment.rollback": true,
}

func validateKnownFields(n *yaml.Node, path string) error {
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			if err := validateKnownFields(c, path); err != nil {
				return err
			}
		}
		return nil
	case yaml.MappingNode:
		if table, ok := knownFieldTables[path]; ok {
			for i := 0; i+1 < len(n.Content); i += 2 {
				k := n.Content[i]
				if !table[k.Value] {
					return fmt.Errorf("yaml: line %d: unknown field %q", k.Line, k.Value)
				}
			}
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if err := validateKnownFields(v, childPath(path, k.Value)); err != nil {
				return err
			}
		}
		return nil
	case yaml.SequenceNode:
		if sequenceSections[path] {
			for _, item := range n.Content {
				if item.Kind == yaml.MappingNode {
					if err := validateKnownFields(item, path+".*"); err != nil {
						return err
					}
				} else {
					if err := validateKnownFields(item, path); err != nil {
						return err
					}
				}
			}
			return nil
		}
		for _, item := range n.Content {
			if err := validateKnownFields(item, path); err != nil {
				return err
			}
		}
		return nil
	}
	return nil
}

func childPath(path, key string) string {
	switch path {
	case "":
		return key
	case "on", "inputs", "packages", "components":
		return path + ".*"
	case "jobs":
		return "jobs.*"
	case "jobs.*":
		return "jobs.*." + key
	case "jobs.*.deployment":
		return "jobs.*.deployment." + key
	}
	return path + "." + key
}
