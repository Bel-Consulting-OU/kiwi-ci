package kiwi

# Example deny-gate policy for the Kiwi CI OPA integration.
#
# Contract: the policy must expose data.kiwi.allow (boolean) and
# data.kiwi.deny (set of reason strings). Capabilities are NOT derived from
# this policy: OPA only admits or denies. Any deny entry, a missing or
# false allow, a compile error, or an evaluation error rejects the request.
#
# Input fields (all always present):
#   repository (string), trusted (bool), branch (string), event (string),
#   runtime (string), secrets ([]string), audiences ([]string),
#   environment (string), runner_labels ([]string), network (string)

default allow := false

# The baseline: only trusted pipelines are admitted.
allow if {
	input.trusted
}

protected_environments := {"production", "staging"}

# Untrusted pull requests must not reach protected environments.
deny contains message if {
	not input.trusted
	input.event == "pull_request"
	input.environment in protected_environments
	message := sprintf("untrusted %s cannot target protected environment %q", [input.event, input.environment])
}

# Untrusted jobs must not request internet egress.
deny contains message if {
	not input.trusted
	input.network == "internet"
	message := sprintf("untrusted job requests network %q", [input.network])
}
