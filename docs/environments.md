# Environments and deployments

Environments gate sensitive work (production, staging) behind approvals
and concurrency limits, and record deployment lifecycles.

## Declaration

```yaml
jobs:
  deploy:
    needs: [build]
    environment:
      name: production
      url: https://app.example.com
      approval: true
      branches: [main]
      concurrency: 1
    deployment:
      canary:
        - run: ./deploy.sh --canary
      verify:
        - run: ./deploy.sh --verify
      rollback:
        - run: ./deploy.sh --rollback
    steps:
      - run: ./deploy.sh
```

- `environment.name` — matches `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`.
- `environment.approval` — the job waits in `waiting_approval` until an
  operator approves it.
- `environment.branches` — restrict the environment to these branches.
- `environment.concurrency` — maximum simultaneous running jobs in this
  environment (0 = unlimited).

Jobs targeting an environment require the `Deployments` capability in
the effective policy; untrusted pipelines can never target
environments.

## Approvals

- Approval is required per job; the queue reason `WAITING_APPROVAL` is
  reported until someone approves.
- `POST /api/v1/jobs/{id}/approve` (or `kiwi approve <job>`) approves a
  waiting job. The approving actor is recorded from the authenticated
  principal.
- Jobs whose environment branch filter does not match the run's branch
  are blocked.

## Concurrency

The scheduler counts running jobs per environment and refuses to lease
new ones once the limit is reached (`ENVIRONMENT_LOCKED` queue reason).
The limit applies across the whole control plane, not per runner.

## Deployment lifecycle

`deployment.canary`, `deployment.verify`, and `deployment.rollback`
declare the three deployment phases as step lists. The control plane
records a deployment per environment job (`model.Deployment`): start
time, approving actor, commit, and final status. Records are exposed
via `POST /api/v1/jobs/{id}/deployments` (explicit record creation) and
`GET /api/v1/runs/{id}/deployments` (listing).

## Persistence

Deployment records persist durably: through `DeploymentStore` in
PostgreSQL mode, and through the data-dir state file in filesystem
mode. Snapshot records persist through `SnapshotStore` in DB mode and
the state file otherwise. Keep deployment capability on dedicated
runner pools and use environment concurrency to serialize production
deployments.
