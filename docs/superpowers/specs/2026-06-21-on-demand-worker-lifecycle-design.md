# On-Demand Worker Lifecycle

**Date:** 2026-06-21
**Audience:** Pencheff API/runtime maintainers and deployers.
**Status:** Approved design, pending implementation plan.

## Goal

Reduce steady-state resource usage from the heavy `pencheff-worker` image by making
the worker run only while scan or scan-adjacent work is pending. The existing
always-on deployment must remain the default and must be switchable through one
root `.env` variable.

## Configuration

Add a root `.env` setting:

```env
WORKER_ALWAYS_ON=true
```

Semantics:

- `WORKER_ALWAYS_ON=true`: preserve the current setup. `docker compose up -d`
  starts `worker`, and the worker uses the existing `restart: unless-stopped`
  behavior.
- `WORKER_ALWAYS_ON=false`: the heavy worker is stopped by default. The API
  starts it before scan work is queued, and the worker asks to stop after the
  work queue drains.

Optional settings may be added with conservative defaults:

- `WORKER_CONTROLLER_URL=http://worker-controller:8080`
- `WORKER_IDLE_GRACE_SECONDS=30`

## Architecture

Use a small always-on `worker-controller` sidecar rather than mounting the
Docker socket into the API container.

Responsibilities:

- `api`: decides when scan work is being commissioned or when schedules are due.
- `worker-controller`: owns Docker/Compose access and exposes internal-only
  lifecycle endpoints.
- `worker`: runs the existing Celery tasks and requests a stop only after it is
  idle.

The controller exposes a minimal internal HTTP API:

- `POST /worker/start`: idempotently start the Compose `worker` service.
- `POST /worker/stop-if-idle`: stop `worker` only if the controller/API idle
  checks agree there is no pending work.
- `GET /healthz`: container healthcheck.

Only `worker-controller` mounts `/var/run/docker.sock`. The API calls the
controller over the Compose network. The controller must validate a shared
internal token or bind only to the private service network.

## Compose Behavior

The production Compose stack gains `worker-controller`.

In always-on mode:

- `worker-controller` may start, but it does not interfere with the worker.
- `worker` keeps today's startup and restart behavior.

In on-demand mode:

- `worker` is not started as part of the default long-running stack.
- `worker-controller` remains running and can start `worker` on request.
- The worker service definition remains in Compose so `docker compose up worker`
  uses the same image, env, DNS, dependencies, volumes, and command as today.

Implementation can use a Compose profile such as `profiles: ["worker"]` on the
heavy worker plus controller commands that explicitly start that profiled
service. The exact Compose invocation must be deploy-tested on the target VM
because Compose profile behavior differs between "project already running" and
"start one service" workflows.

## API and Scheduler Flow

Manual scan flow:

1. API receives the scan commission request.
2. If `WORKER_ALWAYS_ON=false`, API calls `POST /worker/start`.
3. API writes the `scans` or `repo_scans` row as `queued`.
4. API enqueues the Celery task exactly as today.
5. The worker processes the task and downstream scan-adjacent tasks.
6. The worker calls `stop-if-idle` during task-finalization paths.

Scheduled scan flow:

1. The always-on API process owns due-schedule discovery in on-demand mode.
2. When a schedule is due, API starts the worker through the controller.
3. API creates the queued scan row and advances `last_run_at` / `next_run_at`.
4. API enqueues the existing Celery scan task.
5. Worker shutdown follows the same idle check as manual scans.

The existing `scheduled_scan_task.dispatch_due_scans` can remain available for
always-on deployments. In on-demand mode, scheduled dispatch must not rely on a
Celery beat task running inside the stopped heavy worker.

## Idle Detection

Stopping must be conservative. `stop-if-idle` should refuse to stop the worker
when any of these are true:

- any `scans.status` is `queued` or `running`;
- any `repo_scans.status` is `queued` or `running`;
- Redis/Celery reports reserved, active, or queued scan-adjacent tasks;
- the idle grace window has not elapsed since the last task completion.

Scan-adjacent work includes full scans, repo scans, scheduled scans, reports,
notifications, security-lake ingest, correlation, rechecks, agentic fixes, and
bulk fixes. This prevents post-scan tasks from being stranded when the heavy
worker stops.

If the idle check cannot read the DB or broker, it must leave the worker
running and log the reason.

## Failure Handling

- Starting an already-running worker is a no-op.
- If worker start fails, the API returns a clear scan-queueing error rather than
  leaving a scan row stuck forever in `queued`.
- If stop fails, the scan result remains valid; only resource cleanup is
  delayed.
- Zombie-scan recovery remains available. In on-demand mode it should run when
  the worker starts and may also be triggered by the API-side scheduler.

## Security

The Docker socket is effectively root on the host. It must be kept out of the
API container. The controller should have the smallest possible API surface,
avoid arbitrary command execution, and only operate on the known Compose project
and `worker` service.

## Tests

Backend tests should cover:

- `WORKER_ALWAYS_ON=true` does not call the controller during manual scan
  enqueue.
- `WORKER_ALWAYS_ON=false` starts the worker before manual scan enqueue.
- scheduled dispatch in on-demand mode starts the worker before creating scans.
- stop is skipped while another scan/repo scan is queued or running.
- stop is requested after the final scan-adjacent task completes and idle grace
  has elapsed.
- controller failures are surfaced without creating permanently queued scans.

Deployment verification should cover:

- `docker compose up -d` preserves current behavior with
  `WORKER_ALWAYS_ON=true`.
- with `WORKER_ALWAYS_ON=false`, the heavy worker is absent after boot, starts
  when a manual scan is commissioned, and stops after the scan drains.
- a due scheduled scan wakes the worker without any manual action.

## Out of Scope

- Slimming the worker image. This design reduces runtime residency, not image
  disk footprint.
- Moving every non-scan background job to a separate lightweight worker. That
  can be done later if always-on email/retention behavior becomes important in
  on-demand deployments.
