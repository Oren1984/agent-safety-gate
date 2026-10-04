# Sandbox

Agent tool actions execute in one place only: a throwaway container started by `safety_gate/sandbox.py`.
"Runs in Docker" is not the boundary. The boundary is the set of restrictions below.

## Restrictions

All of them are in `run_flags()`:

| Flag | Effect |
|---|---|
| `--network none` | No network stack beyond loopback: no egress, no DNS, no ports |
| `--read-only` | Root filesystem is immutable |
| `--cap-drop ALL` | No Linux capabilities |
| `--security-opt no-new-privileges` | No privilege gain through setuid binaries |
| `--user 10001:10001` | Non-root user (also set in the image) |
| `--pids-limit 64`, `--memory 128m`, `--cpus 0.5` | Resource limits |
| `--tmpfs /tmp:rw,noexec,nosuid,size=16m` | Small non-executable scratch space |
| `--mount type=bind,source=<run>/workspace,target=/workspace` | The only writable host path, one directory per run |
| `--rm` | Container is discarded after each batch |

Not present, by design: `--privileged`, published ports, `--env` / `--env-file`, the Docker socket,
any other host mount, any secret. The container receives its actions as JSON on stdin and returns
results as JSON on stdout.

The image (`sandbox/Dockerfile`) is `python:3.12-slim` plus `tool_runner.py`. It is built on first use
as `agent-safety-gate-sandbox:local`.

## The executor does no checking

`sandbox/tool_runner.py` performs whatever it is given, including path traversal and arbitrary shell.
That is intentional: containment has to come from the container, so that the sandbox remains an
independent layer when the policy layer is wrong.

## Containment drill

In scenario C, after the permitted actions run, the actions that policy **blocked** are replayed in a
second container against an empty scratch directory. This answers "what if every gate above had failed?"

| Blocked action | Result inside the sandbox |
|---|---|
| `read_secret deploy_token` | `FileNotFoundError` — no secrets are mounted |
| `http_request` to `updates.example.invalid` | `Temporary failure in name resolution` — no network |
| `write_file ../outside/notes.txt` | `Read-only file system` |
| `shell rm -rf /workspace/*` | Runs, but only the empty scratch directory is reachable |

These are recorded as `sandbox.containment` and `sandbox.network_denied` audit events.

## Verified by tests

`tests/test_sandbox.py` (skipped when Docker is not running):

- runs as uid 10001; only interface is `lo`; effective capability set is 0; rootfs is read-only; no Docker socket; no host environment variables
- outbound connections fail by name and by IP (`192.0.2.1`, a reserved documentation address: "Network is unreachable")
- writes land in the workspace and nowhere else
- the run flags contain the restrictions above and none of the forbidden options

## Limits

Containers share the host kernel. This is defense in depth for a POC, not a hardened multi-tenant
sandbox; a stronger boundary would be gVisor or a microVM. If Docker is unavailable the pipeline
executes nothing.
