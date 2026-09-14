# Conditions and expressions

Two evaluators exist and must agree: the legacy condition evaluator
(`internal/pipeline/condition.go`) used by job/step `if` fields, and the
expression engine (`internal/expr`) used for `${{ ... }}` interpolation
and boolean evaluation. The control plane, the SQL scheduler, and the
local executor all route job conditions through one entry point
(`ConditionAllows`), so a condition can never diverge between server and
local execution.

## Status functions

Job and step `if` conditions are evaluated against a status:

| Function | True when |
|---|---|
| `success()` | status is not `failure`, `cancelled`, or `blocked` |
| `failure()` | status is `failure` or `blocked` |
| `cancelled()` | status is `cancelled` |
| `always()` | always |

The effective status for a job is the aggregate of its dependencies:
any failed/blocked dependency makes the outcome `failure`; otherwise a
cancelled dependency makes it `cancelled`; success otherwise. For steps,
the status is the job's current status.

An empty `if` behaves like `success()`: a job without an explicit
condition is blocked when a dependency failed, and a step without an
explicit `if` runs only while the job status still admits `success()`.

## Condition syntax

- `success()`, `failure()`, `cancelled()`, `always()`
- `!expr`, `a && b`, `a || b`, parentheses
- comparisons: `left == right`, `left != right`
- left-hand values: `status`, `event`, `branch`, `env.NAME`, or a
  quoted literal; right-hand values are literals

Example:

```yaml
if: always() && branch == 'main'
```

Condition evaluation errors yield false (the step or job does not run).

## Expression engine

`${{ ... }}` holes and boolean conditions in other contexts use the
expression engine. The grammar is small and side-effect free: function
calls, string and number literals, dotted context paths, `==`/`!=`,
`&&`/`||`/`!`, and parentheses. There are no user-defined functions and
no mutation, so evaluation is deterministic.

### Contexts

Scalar contexts (usable bare):

| Context | Value |
|---|---|
| `status` | job/run status string |
| `event` | event name (`push`, `pull_request`, ...) |
| `branch` | branch being built |
| `ref` | full git ref (`refs/heads/main`) |
| `sha` | commit SHA |
| `repo` | repository URL |
| `repo.full_name` | `owner/name` form |
| `event.name` | same as `event` |
| `git.branch` / `git.ref` / `git.sha` | mirrors of `branch`/`ref`/`sha` |

Map contexts (require a field; dotted keys resolve as `a.b`):

| Context | Source |
|---|---|
| `matrix.X` | matrix dimension values |
| `inputs.X` | dispatch inputs |
| `needs.job.outputs.name` | dependency job outputs |
| `steps.id.outputs.name` | earlier step outputs |
| `runner.*` | runner metadata |
| `job.*` | job metadata (e.g. `job.id`) |
| `env.VAR` | environment variable |
| `kiwi.*` | run metadata (e.g. `kiwi.run_id`) |
| `extra.*` | extra values |

Unknown contexts and unknown fields are parse-time errors; a missing
map key is an evaluation error.

### Functions

- `contains(a, b)`, `startsWith(a, b)`, `endsWith(a, b)` — string
  predicates.
- `fromJSON(s)`, `toJSON(s)` — parse and re-emit compact JSON.
- `hashFiles('glob', ...)` — SHA-256 over the sorted matched files
  (workspace-relative path plus content), first 12 hex characters,
  evaluated against the workspace. Comma-separated globs inside one
  argument are accepted.

### Truthiness

Boolean contexts interpret strings with GitHub Actions truthiness:
`"true"` is true, `"false"` and `""` are false, anything else is an
evaluation error.

## Interpolation phases

1. **Compile time** (matrix): holes referencing only `matrix.*` are
   substituted deterministically; everything else stays literal.
2. **Execution time** (outputs): `needs.*` and `steps.*` holes are
   resolved once upstream jobs or earlier steps have finished.
3. **Server enqueue**: `repo`, `branch`, `ref`, `sha`, `event` contexts
   are available to the server-side concurrency group expansion.

Interpolation validation rejects unknown context prefixes and
unterminated holes at parse time (`internal/pipeline/validate.go`).
