# Security

Kiwi CI executes repository-controlled code. The runner is a security
boundary, not a convenience layer. This document describes how to report
problems, which versions are supported, and the response you can expect.

## Supported versions

| Version | Supported | Notes |
|---|---|---|
| 0.1.x (main branch) | Yes | Unreleased development series. All fixes land on `main` first. |
| < 0.1 | No | Pre-release snapshots are not supported. |

Security fixes are applied to the current `main` branch. Once a v0.1.0 tag
exists, tagged releases receive fixes for the latest patch line only.

## Reporting a vulnerability

If you believe you have found a security issue, report it privately.

**Do not open a public issue.**

Private channels, in order of preference:

1. **GitHub private security advisory**: open a private advisory against
   https://github.com/Bel-Consulting-OU/kiwi-ci (visible only to
   maintainers).
2. **Email**: security@bel-consulting.eu — monitored by the
   maintainers. If it bounces, use the private advisory path above;
   the advisory is the authoritative channel for coordinated
   disclosure and CVE assignment.

Include in your report:

- the affected component and version (or commit);
- a description of the vulnerability;
- steps to reproduce, including a minimal pipeline YAML where relevant;
- impact and any conditions required (trusted vs. untrusted runs,
  single-tenant vs. multi-tenant deployments);
- whether you have a proposed fix or want coordinated disclosure.

### Response expectations

- **Acknowledgment**: within 48 hours of a report via either channel.
- **Triage**: a severity assessment and a decision (fix, mitigation,
  out of scope) within 7 days.
- **Fix**: for confirmed issues we aim to ship a fix within **90 days**.
  Severe issues (untrusted code escape, secret disclosure, lease
  impersonation) are treated as blockers and fixed ahead of normal work.
- **Disclosure**: coordinated release. We publish an advisory after the
  fix lands, unless you ask us to delay. We will credit reporters who
  want credit.

If 90 days pass without a fix, you are free to disclose on your own
schedule. We prefer coordinated disclosure but do not require it.

## Scope

In scope:

- runner-side code execution boundaries (native/container/Tart
  isolation, `internal/executor`, `internal/safefs`);
- the control plane API (`internal/server`), including lease handling,
  webhook verification, OIDC token issuance, secret delivery, and
  artifact/cache endpoints;
- admission policy (`internal/policy`), capability intersection, and
  trust-domain handling;
- runner identity and enrollment (`internal/runnerpki`, mTLS binding,
  protocol negotiation);
- storage and state handling (`internal/storage`, leases, receipts);
- the pipeline parser/expression engine (`internal/pipeline`,
  `internal/expr`): parser crashes, denial-of-service inputs, and
  expression injection.

Out of scope:

- issues that require the attacker to already control the host the
  runner executes on;
- misconfigurations that require operator action beyond documented
  settings (for example, running untrusted pipelines with
  `runtime: native` after explicitly overriding policy);
- third-party forges, cloud providers, or secret stores themselves.

## Embargo and coordinated disclosure

Reported vulnerabilities are embargoed until a fix is available or the
90-day window closes. Under embargo:

- do not share exploitation details publicly;
- you may share the fact that you reported an issue with people who
  need to know (for example, your own operations team).

We will keep you informed of progress and agree with you on a
publication date before the advisory goes out.

## Architecture notes

The security design (trust modes, capability policy, leases, mTLS,
secret delivery) is documented in [docs/security-model.md](docs/security-model.md)
and [docs/threat-model.md](docs/threat-model.md). Deployment hardening
guidance lives in [docs/production-deployment.md](docs/production-deployment.md)
and [docs/runner-security.md](docs/runner-security.md).
