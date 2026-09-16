package pipeline

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// SchemaJSON is the Draft 2020-12 JSON Schema for the Kiwi pipeline language.
// It is the byte-for-byte content of .kiwi/schema.json; TestSchemaJSONMatchesKiwiFile
// pins the two together so they cannot drift.
var SchemaJSON = []byte(schemaSource)

const schemaSource = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://kiwi.ci/schemas/pipeline.json",
  "title": "Kiwi CI pipeline",
  "description": "JSON Schema for the Kiwi CI pipeline language (version 1).",
  "type": "object",
  "required": [
    "jobs"
  ],
  "properties": {
    "version": {
      "type": "integer",
      "const": 1,
      "default": 1
    },
    "name": {
      "type": "string"
    },
    "on": {
      "type": "object",
      "additionalProperties": {
        "$ref": "#/$defs/trigger"
      }
    },
    "inputs": {
      "type": "object",
      "additionalProperties": {
        "$ref": "#/$defs/input"
      }
    },
    "env": {
      "$ref": "#/$defs/stringMap"
    },
    "secrets": {
      "$ref": "#/$defs/secrets"
    },
    "defaults": {
      "$ref": "#/$defs/defaults"
    },
    "permissions": {
      "$ref": "#/$defs/permissions"
    },
    "concurrency": {
      "$ref": "#/$defs/concurrency"
    },
    "packages": {
      "type": "object",
      "additionalProperties": {
        "$ref": "#/$defs/package"
      }
    },
    "components": {
      "type": "object",
      "additionalProperties": {
        "$ref": "#/$defs/component"
      }
    },
    "jobs": {
      "type": "object",
      "minProperties": 1,
      "additionalProperties": {
        "$ref": "#/$defs/job"
      }
    }
  },
  "additionalProperties": false,
  "$defs": {
    "duration": {
      "type": "string",
      "pattern": "^\\+?([0-9]+(\\.[0-9]+)?|\\.[0-9]+)(ns|us|\u00b5s|\u03bcs|ms|s|m|h)([0-9]+(\\.[0-9]+)?(ns|us|\u00b5s|\u03bcs|ms|s|m|h))*$"
    },
    "byteSize": {
      "type": [
        "integer",
        "string"
      ],
      "minimum": 0,
      "pattern": "^[0-9]+(\\.[0-9]+)?\\s*([KkMmGgTtPp]?[Ii]?[Bb]?)?$"
    },
    "stringArray": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "stringMap": {
      "type": "object",
      "additionalProperties": {
        "type": [
          "string",
          "integer",
          "number",
          "boolean",
          "null"
        ]
      }
    },
    "shell": {
      "type": "string",
      "enum": [
        "bash",
        "sh",
        "zsh",
        "pwsh",
        "powershell",
        "fish",
        "dash",
        "ksh",
        "python"
      ]
    },
    "input": {
      "type": "object",
      "properties": {
        "type": {
          "enum": [
            "string",
            "boolean",
            "integer"
          ]
        },
        "required": {
          "type": "boolean"
        },
        "default": true,
        "options": {
          "$ref": "#/$defs/stringArray"
        },
        "description": {
          "type": "string"
        }
      },
      "additionalProperties": false
    },
    "defaults": {
      "type": "object",
      "properties": {
        "shell": {
          "$ref": "#/$defs/shell"
        },
        "timeout": {
          "$ref": "#/$defs/duration"
        },
        "retry": {
          "$ref": "#/$defs/retry"
        }
      },
      "additionalProperties": false
    },
    "retry": {
      "type": "object",
      "properties": {
        "max": {
          "type": "integer",
          "minimum": 0
        },
        "backoff": {
          "$ref": "#/$defs/duration"
        },
        "on": {
          "type": "array",
          "items": {
            "enum": [
              "any",
              "artifact",
              "cache",
              "command",
              "failure",
              "infra",
              "timeout"
            ]
          }
        }
      },
      "additionalProperties": false
    },
    "permissions": {
      "type": "object",
      "properties": {
        "id_token": {
          "type": "boolean"
        }
      },
      "additionalProperties": false
    },
    "concurrency": {
      "type": "object",
      "properties": {
        "group": {
          "type": "string"
        },
        "cancel_in_progress": {
          "type": "boolean"
        }
      },
      "additionalProperties": false
    },
    "package": {
      "type": "object",
      "properties": {
        "paths": {
          "$ref": "#/$defs/stringArray"
        },
        "depends_on": {
          "$ref": "#/$defs/stringArray"
        }
      },
      "additionalProperties": false
    },
    "component": {
      "type": "object",
      "properties": {
        "ref": {
          "type": "string"
        },
        "with": {
          "$ref": "#/$defs/stringMap"
        }
      },
      "additionalProperties": false
    },
    "environment": {
      "type": "object",
      "properties": {
        "name": {
          "type": "string"
        },
        "url": {
          "type": "string"
        },
        "approval": {
          "type": "boolean"
        },
        "branches": {
          "$ref": "#/$defs/stringArray"
        },
        "concurrency": {
          "type": "integer",
          "minimum": 0
        }
      },
      "additionalProperties": false
    },
    "sandbox": {
      "type": "object",
      "properties": {
        "rootless": {
          "type": "boolean"
        },
        "read_only_rootfs": {
          "type": "boolean"
        },
        "network": {
          "enum": [
            "default",
            "none",
            "services-only",
            "internet"
          ]
        }
      },
      "additionalProperties": false
    },
    "placement": {
      "type": "object",
      "properties": {
        "regions": {
          "$ref": "#/$defs/stringArray"
        },
        "labels": {
          "$ref": "#/$defs/stringArray"
        }
      },
      "additionalProperties": false
    },
    "resources": {
      "type": "object",
      "properties": {
        "cpu": {
          "type": "number",
          "minimum": 0
        },
        "memory": {
          "$ref": "#/$defs/byteSize"
        },
        "disk": {
          "$ref": "#/$defs/byteSize"
        },
        "pids": {
          "type": "integer",
          "minimum": 0
        }
      },
      "additionalProperties": false
    },
    "tests": {
      "type": "object",
      "properties": {
        "reports": {
          "$ref": "#/$defs/stringArray"
        },
        "manifest": {
          "type": "string"
        },
        "shards": {
          "type": "integer",
          "minimum": 0,
          "maximum": 1024
        },
        "retry_failed": {
          "type": "integer",
          "minimum": 0
        },
        "quarantine_flaky": {
          "type": "boolean"
        }
      },
      "additionalProperties": false
    },
    "generate": {
      "type": "object",
      "properties": {
        "path": {
          "type": "string"
        },
        "max_jobs": {
          "type": "integer",
          "minimum": 0
        },
        "max_depth": {
          "type": "integer",
          "minimum": 0
        }
      },
      "additionalProperties": false
    },
    "downstream": {
      "type": "object",
      "properties": {
        "repository": {
          "type": "string"
        },
        "ref": {
          "type": "string"
        },
        "event": {
          "type": "string"
        },
        "inputs": {
          "$ref": "#/$defs/stringMap"
        },
        "wait": {
          "type": "boolean"
        }
      },
      "additionalProperties": false
    },
    "snapshot": {
      "type": "object",
      "properties": {
        "on": {
          "$ref": "#/$defs/stringArray"
        }
      },
      "additionalProperties": false
    },
    "step": {
      "type": "object",
      "required": [
        "run"
      ],
      "properties": {
        "id": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "run": {
          "type": "string",
          "minLength": 1
        },
        "if": {
          "type": "string"
        },
        "shell": {
          "$ref": "#/$defs/shell"
        },
        "working_directory": {
          "type": "string"
        },
        "env": {
          "$ref": "#/$defs/stringMap"
        },
        "secrets": {
          "$ref": "#/$defs/stringArray"
        },
        "timeout": {
          "$ref": "#/$defs/duration"
        },
        "retry": {
          "$ref": "#/$defs/retry"
        },
        "continue_on_error": {
          "type": "boolean"
        }
      },
      "additionalProperties": false
    },
    "deployment": {
      "type": "object",
      "properties": {
        "canary": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/step"
          }
        },
        "verify": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/step"
          }
        },
        "rollback": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/step"
          }
        }
      },
      "additionalProperties": false
    },
    "service": {
      "type": "object",
      "required": [
        "image"
      ],
      "properties": {
        "name": {
          "type": "string"
        },
        "image": {
          "type": "string"
        },
        "env": {
          "$ref": "#/$defs/stringMap"
        },
        "healthcheck": {
          "type": "string"
        },
        "interval": {
          "$ref": "#/$defs/duration"
        },
        "timeout": {
          "$ref": "#/$defs/duration"
        },
        "retries": {
          "type": "integer",
          "minimum": 0
        }
      },
      "additionalProperties": false
    },
    "cache": {
      "type": "object",
      "required": [
        "paths"
      ],
      "properties": {
        "name": {
          "type": "string"
        },
        "paths": {
          "$ref": "#/$defs/stringArray"
        },
        "key": {
          "type": "string"
        },
        "hash_files": {
          "$ref": "#/$defs/stringArray"
        },
        "restore_keys": {
          "$ref": "#/$defs/stringArray"
        }
      },
      "additionalProperties": false
    },
    "artifact": {
      "type": "object",
      "required": [
        "paths"
      ],
      "properties": {
        "name": {
          "type": "string"
        },
        "paths": {
          "$ref": "#/$defs/stringArray"
        },
        "if": {
          "type": "string"
        },
        "retention": {
          "type": "string"
        },
        "sbom": {
          "type": "string",
          "enum": [
            "spdx-json",
            "cyclonedx-json"
          ]
        },
        "sigstore": {
          "type": "object",
          "properties": {
            "required": {
              "type": "boolean"
            },
            "issuer": {
              "type": "string"
            },
            "identity": {
              "type": "string"
            }
          },
          "additionalProperties": false
        },
        "required": {
          "type": "boolean"
        }
      },
      "additionalProperties": false
    },
    "trigger": {
      "oneOf": [
        {
          "type": "object",
          "properties": {
            "branches": {
              "$ref": "#/$defs/stringArray"
            },
            "branches_ignore": {
              "$ref": "#/$defs/stringArray"
            },
            "tags": {
              "$ref": "#/$defs/stringArray"
            },
            "tags_ignore": {
              "$ref": "#/$defs/stringArray"
            },
            "paths": {
              "$ref": "#/$defs/stringArray"
            },
            "paths_ignore": {
              "$ref": "#/$defs/stringArray"
            },
            "actions": {
              "$ref": "#/$defs/stringArray"
            },
            "draft": {
              "type": "boolean"
            }
          },
          "additionalProperties": false
        },
        {
          "type": "object",
          "required": [
            "cron"
          ],
          "properties": {
            "cron": {
              "type": "string"
            },
            "branches": {
              "$ref": "#/$defs/stringArray"
            }
          },
          "additionalProperties": false
        },
        {
          "type": "string"
        },
        {
          "type": "array",
          "items": {
            "type": "object",
            "required": [
              "cron"
            ],
            "properties": {
              "cron": {
                "type": "string"
              },
              "branches": {
                "$ref": "#/$defs/stringArray"
              }
            },
            "additionalProperties": false
          },
          "additionalProperties": false
        }
      ]
    },
    "download": {
      "type": "object",
      "properties": {
        "from": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "path": {
          "type": "string"
        }
      },
      "additionalProperties": false
    },
    "matrix": {
      "type": "object",
      "additionalProperties": {
        "type": "array",
        "minItems": 1,
        "items": {
          "type": [
            "string",
            "number",
            "boolean"
          ]
        }
      }
    },
    "job": {
      "type": "object",
      "required": [
        "steps"
      ],
      "properties": {
        "name": {
          "type": "string"
        },
        "needs": {
          "type": "array",
          "items": {
            "type": "string"
          },
          "uniqueItems": true
        },
        "if": {
          "type": "string"
        },
        "runner": {
          "$ref": "#/$defs/stringArray"
        },
        "runtime": {
          "enum": [
            "native",
            "container",
            "tart"
          ]
        },
        "image": {
          "type": "string"
        },
        "network": {
          "enum": [
            "bridge",
            "host",
            "none"
          ]
        },
        "vm": {
          "type": "string"
        },
        "shell": {
          "$ref": "#/$defs/shell"
        },
        "timeout": {
          "$ref": "#/$defs/duration"
        },
        "queue_timeout": {
          "$ref": "#/$defs/duration"
        },
        "retry": {
          "$ref": "#/$defs/retry"
        },
        "env": {
          "$ref": "#/$defs/stringMap"
        },
        "matrix": {
          "$ref": "#/$defs/matrix"
        },
        "paths": {
          "$ref": "#/$defs/stringArray"
        },
        "paths_ignore": {
          "$ref": "#/$defs/stringArray"
        },
        "services": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/service"
          }
        },
        "steps": {
          "type": "array",
          "minItems": 1,
          "items": {
            "$ref": "#/$defs/step"
          }
        },
        "cache": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/cache"
          }
        },
        "artifacts": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/artifact"
          }
        },
        "downloads": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/download"
          }
        },
        "test_reports": {
          "$ref": "#/$defs/stringArray"
        },
        "environment": {
          "$ref": "#/$defs/environment"
        },
        "infra_retries": {
          "type": "integer",
          "minimum": 0
        },
        "permissions": {
          "$ref": "#/$defs/permissions"
        },
        "outputs": {
          "$ref": "#/$defs/stringMap"
        },
        "placement": {
          "$ref": "#/$defs/placement"
        },
        "sandbox": {
          "$ref": "#/$defs/sandbox"
        },
        "resources": {
          "$ref": "#/$defs/resources"
        },
        "tests": {
          "$ref": "#/$defs/tests"
        },
        "generate": {
          "$ref": "#/$defs/generate"
        },
        "downstream": {
          "$ref": "#/$defs/downstream"
        },
        "deployment": {
          "$ref": "#/$defs/deployment"
        },
        "snapshot": {
          "$ref": "#/$defs/snapshot"
        },
        "component": {
          "type": "string"
        },
        "with": {
          "$ref": "#/$defs/stringMap"
        }
      },
      "additionalProperties": false
    },
    "secrets": {
      "type": "array",
      "items": {
        "type": "string",
        "pattern": "^[A-Za-z_][A-Za-z0-9_]{0,63}$"
      }
    }
  }
}
`

// Schema returns a copy of the embedded pipeline JSON Schema bytes.
func Schema() []byte {
	out := make([]byte, len(SchemaJSON))
	copy(out, SchemaJSON)
	return out
}

// ValidateAgainstSchema performs the schema-level checks that are cheap in
// pure Go without a third-party JSON Schema validator: required fields,
// unknown-field detection, runtime/network/shell enums, duration syntax and
// positivity, and basic structure. It returns a list of problems (empty when
// the document satisfies the schema-level expectations).
func ValidateAgainstSchema(specYAML []byte) []string {
	root, err := schemaYAMLRoot(specYAML)
	if err != nil {
		return []string{err.Error()}
	}
	return checkSchemaRoot(root)
}

func schemaYAMLRoot(data []byte) (*yaml.Node, error) {
	if len(data) > maxPipelineBytes {
		return nil, fmt.Errorf("yaml: source size %d exceeds %d byte limit", len(data), maxPipelineBytes)
	}
	if !utf8.Valid(data) {
		off := firstInvalidUTF8Offset(data)
		line, col := lineCol(data, off)
		return nil, fmt.Errorf("yaml: invalid UTF-8 at byte %d (line %d, column %d)", off, line, col)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("empty pipeline")
		}
		return nil, yamlError(err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, fmt.Errorf("yaml: line %d: multiple documents are not allowed", extra.Line)
	} else if err != io.EOF {
		return nil, yamlError(err)
	}
	if doc.Kind == 0 || (doc.Kind == yaml.DocumentNode && len(doc.Content) == 0) {
		return nil, fmt.Errorf("empty pipeline")
	}
	nodes := 0
	if err := validateYAMLNode(&doc, 0, &nodes); err != nil {
		return nil, err
	}
	if err := validateKnownFields(&doc, ""); err != nil {
		return nil, err
	}
	target := &doc
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		target = doc.Content[0]
	}
	if target.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("yaml: line %d: pipeline must be a mapping", target.Line)
	}
	return target, nil
}

func checkSchemaRoot(m *yaml.Node) []string {
	var errs []string
	if v := mappingValue(m, "version"); v != nil {
		if v.Kind != yaml.ScalarNode || v.Tag != "!!int" {
			errs = append(errs, "yaml: version must be an integer")
		} else if n, err := strconv.Atoi(v.Value); err != nil {
			errs = append(errs, "yaml: version must be an integer")
		} else if n != 0 && n != 1 {
			errs = append(errs, fmt.Sprintf("unsupported pipeline version %d", n))
		}
	}
	jobs := mappingValue(m, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode || len(jobs.Content) == 0 {
		errs = append(errs, "pipeline has no jobs")
		return errs
	}
	if d := mappingValue(m, "defaults"); d != nil {
		if d.Kind != yaml.MappingNode {
			errs = append(errs, "yaml: defaults must be a mapping")
		} else {
			if v := mappingValue(d, "shell"); v != nil {
				errs = append(errs, checkEnumString(v, "defaults.shell", shellNames)...)
			}
			if v := mappingValue(d, "timeout"); v != nil {
				errs = append(errs, checkDurationNode(v, "defaults.timeout")...)
			}
			if v := mappingValue(d, "retry"); v != nil {
				errs = append(errs, checkRetryNode(v, "defaults.retry")...)
			}
		}
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		id := jobs.Content[i].Value
		job := jobs.Content[i+1]
		if job.Kind != yaml.MappingNode {
			errs = append(errs, fmt.Sprintf("yaml: job %q must be a mapping", id))
			continue
		}
		errs = append(errs, checkSchemaJob(id, job)...)
	}
	return errs
}

var runtimeNames = map[string]bool{"": true, "native": true, "container": true, "tart": true}
var jobNetworkNames = map[string]bool{"": true, "bridge": true, "host": true, "none": true}

func checkSchemaJob(id string, j *yaml.Node) []string {
	var errs []string
	if v := mappingValue(j, "runtime"); v != nil {
		errs = append(errs, checkEnumString(v, fmt.Sprintf("job %q runtime", id), runtimeNames)...)
	}
	if v := mappingValue(j, "network"); v != nil {
		errs = append(errs, checkEnumString(v, fmt.Sprintf("job %q network", id), jobNetworkNames)...)
	}
	if v := mappingValue(j, "shell"); v != nil {
		errs = append(errs, checkEnumString(v, fmt.Sprintf("job %q shell", id), shellNames)...)
	}
	if v := mappingValue(j, "timeout"); v != nil {
		errs = append(errs, checkDurationNode(v, fmt.Sprintf("job %q timeout", id))...)
	}
	if v := mappingValue(j, "queue_timeout"); v != nil {
		errs = append(errs, checkDurationNode(v, fmt.Sprintf("job %q queue_timeout", id))...)
	}
	if v := mappingValue(j, "retry"); v != nil {
		errs = append(errs, checkRetryNode(v, fmt.Sprintf("job %q retry", id))...)
	}
	steps := mappingValue(j, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode || len(steps.Content) == 0 {
		errs = append(errs, fmt.Sprintf("job %q has no steps", id))
	} else {
		for i, sn := range steps.Content {
			where := fmt.Sprintf("job %q step %d", id, i+1)
			if sn.Kind != yaml.MappingNode {
				errs = append(errs, fmt.Sprintf("yaml: %s must be a mapping", where))
				continue
			}
			errs = append(errs, checkSchemaStep(where, sn)...)
		}
	}
	if svcs := mappingValue(j, "services"); svcs != nil {
		if svcs.Kind != yaml.SequenceNode {
			errs = append(errs, fmt.Sprintf("yaml: job %q services must be a sequence", id))
		} else {
			for i, sn := range svcs.Content {
				where := fmt.Sprintf("job %q service %d", id, i+1)
				if sn.Kind != yaml.MappingNode {
					errs = append(errs, fmt.Sprintf("yaml: %s must be a mapping", where))
					continue
				}
				img := mappingValue(sn, "image")
				if img == nil || img.Kind != yaml.ScalarNode || img.Tag == "!!null" || strings.TrimSpace(img.Value) == "" {
					errs = append(errs, fmt.Sprintf("%s has empty image", where))
				}
				if v := mappingValue(sn, "interval"); v != nil {
					errs = append(errs, checkDurationNode(v, where+" interval")...)
				}
				if v := mappingValue(sn, "timeout"); v != nil {
					errs = append(errs, checkDurationNode(v, where+" timeout")...)
				}
			}
		}
	}
	if cs := mappingValue(j, "cache"); cs != nil {
		if cs.Kind != yaml.SequenceNode {
			errs = append(errs, fmt.Sprintf("yaml: job %q cache must be a sequence", id))
		} else {
			for i, cn := range cs.Content {
				if cn.Kind != yaml.MappingNode {
					errs = append(errs, fmt.Sprintf("yaml: job %q cache %d must be a mapping", id, i+1))
					continue
				}
				if p := mappingValue(cn, "paths"); p == nil {
					errs = append(errs, fmt.Sprintf("job %q cache %d is missing required field paths", id, i+1))
				}
			}
		}
	}
	if as := mappingValue(j, "artifacts"); as != nil {
		if as.Kind != yaml.SequenceNode {
			errs = append(errs, fmt.Sprintf("yaml: job %q artifacts must be a sequence", id))
		} else {
			for i, an := range as.Content {
				if an.Kind != yaml.MappingNode {
					errs = append(errs, fmt.Sprintf("yaml: job %q artifact %d must be a mapping", id, i+1))
					continue
				}
				if p := mappingValue(an, "paths"); p == nil {
					errs = append(errs, fmt.Sprintf("job %q artifact %d is missing required field paths", id, i+1))
				}
			}
		}
	}
	if dep := mappingValue(j, "deployment"); dep != nil {
		if dep.Kind != yaml.MappingNode {
			errs = append(errs, fmt.Sprintf("yaml: job %q deployment must be a mapping", id))
		} else {
			for _, phase := range []string{"canary", "verify", "rollback"} {
				if ps := mappingValue(dep, phase); ps != nil {
					if ps.Kind != yaml.SequenceNode {
						errs = append(errs, fmt.Sprintf("yaml: job %q deployment.%s must be a sequence", id, phase))
						continue
					}
					for i, sn := range ps.Content {
						where := fmt.Sprintf("job %q deployment.%s step %d", id, phase, i+1)
						if sn.Kind != yaml.MappingNode {
							errs = append(errs, fmt.Sprintf("yaml: %s must be a mapping", where))
							continue
						}
						errs = append(errs, checkSchemaStep(where, sn)...)
					}
				}
			}
		}
	}
	return errs
}

func checkSchemaStep(where string, s *yaml.Node) []string {
	var errs []string
	run := mappingValue(s, "run")
	if run == nil || run.Kind != yaml.ScalarNode || run.Tag == "!!null" || strings.TrimSpace(run.Value) == "" {
		errs = append(errs, where+" has empty run command")
	}
	if v := mappingValue(s, "shell"); v != nil {
		errs = append(errs, checkEnumString(v, where+" shell", shellNames)...)
	}
	if v := mappingValue(s, "timeout"); v != nil {
		errs = append(errs, checkDurationNode(v, where+" timeout")...)
	}
	if v := mappingValue(s, "retry"); v != nil {
		errs = append(errs, checkRetryNode(v, where+" retry")...)
	}
	return errs
}

func checkRetryNode(v *yaml.Node, where string) []string {
	if v.Kind != yaml.MappingNode {
		return []string{fmt.Sprintf("yaml: %s must be a mapping", where)}
	}
	var errs []string
	if m := mappingValue(v, "max"); m != nil {
		if m.Kind != yaml.ScalarNode || m.Tag != "!!int" {
			errs = append(errs, fmt.Sprintf("yaml: %s max must be an integer", where))
		} else if n, err := strconv.Atoi(m.Value); err == nil && n < 0 {
			errs = append(errs, fmt.Sprintf("%s max must not be negative", where))
		}
	}
	if b := mappingValue(v, "backoff"); b != nil {
		errs = append(errs, checkDurationNode(b, where+" backoff")...)
	}
	return errs
}

func checkEnumString(v *yaml.Node, where string, allowed map[string]bool) []string {
	if v.Tag == "!!null" {
		return nil
	}
	if v.Kind != yaml.ScalarNode {
		return []string{fmt.Sprintf("yaml: %s must be a string", where)}
	}
	if v.Value == "" || allowed[v.Value] {
		return nil
	}
	names := make([]string, 0, len(allowed))
	for name := range allowed {
		if name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return []string{fmt.Sprintf("%s has unsupported value %q (want one of %s)", where, v.Value, strings.Join(names, ", "))}
}

func checkDurationNode(v *yaml.Node, where string) []string {
	if v.Kind != yaml.ScalarNode {
		return []string{fmt.Sprintf("yaml: %s must be a duration string", where)}
	}
	if v.Tag == "!!null" || v.Value == "" {
		return nil
	}
	d, err := time.ParseDuration(v.Value)
	if err != nil {
		return []string{fmt.Sprintf("yaml: %s is not a valid duration: %q", where, v.Value)}
	}
	if d <= 0 {
		return []string{fmt.Sprintf("%s must be a positive duration", where)}
	}
	return nil
}

func mappingValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
