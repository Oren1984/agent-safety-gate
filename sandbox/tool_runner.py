"""Tool executor that runs INSIDE the sandbox container.

Reads {"actions": [{"tool", "args"}, ...]} on stdin, performs each action and
prints a JSON list of results. It deliberately does no policy checking: the
container's restrictions are what contain it.
"""
import json
import os
import subprocess
import sys
import urllib.request

WORKSPACE = "/workspace"


def _path(p):
    return os.path.normpath(os.path.join(WORKSPACE, p))


def write_file(args):
    target = _path(args["path"])
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(args.get("content", ""))
    return f"wrote {target}"


def read_file(args):
    with open(_path(args["path"]), encoding="utf-8") as fh:
        return fh.read()


def delete_file(args):
    os.remove(_path(args["path"]))
    return "deleted"


def read_secret(args):
    with open(f"/run/secrets/{args['name']}", encoding="utf-8") as fh:
        return fh.read()


def http_request(args):
    req = urllib.request.Request(args["url"], data=str(args.get("body", "")).encode(), method=args.get("method", "GET"))
    with urllib.request.urlopen(req, timeout=3) as resp:
        return f"HTTP {resp.status}"


def shell(args):
    # shell=True is the point of this tool: an arbitrary agent command, run only
    # inside the locked-down container and only after the host-side gates.
    out = subprocess.run(args["command"], shell=True, capture_output=True, text=True, timeout=10)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or f"exit {out.returncode}")
    return out.stdout.strip()


def deploy(args):
    # Simulated: no deployment exists. Leaves a marker so the verifier can see it.
    with open(_path("DEPLOY_SIMULATED.txt"), "w", encoding="utf-8") as fh:
        fh.write(f"simulated deploy to {args.get('target')}\n")
    return "simulated deploy (no real system touched)"


def probe(args):
    """Report the restrictions this container actually runs under."""
    status = open("/proc/self/status", encoding="utf-8").read()
    cap_eff = next(line.split()[1] for line in status.splitlines() if line.startswith("CapEff"))
    try:
        open("/opt/probe", "w").close()
        rootfs = "writable"
    except OSError as exc:
        rootfs = exc.strerror
    return {
        "uid": os.getuid(),
        "interfaces": sorted(os.listdir("/sys/class/net")),
        "cap_eff": cap_eff,
        "rootfs": rootfs,
        "docker_socket": os.path.exists("/var/run/docker.sock"),
        "env_keys": sorted(os.environ),
    }


TOOLS = {f.__name__: f for f in (write_file, read_file, delete_file, read_secret, http_request, shell, deploy, probe)}


def main():
    results = []
    for action in json.load(sys.stdin)["actions"]:
        try:
            results.append({"ok": True, "output": TOOLS[action["tool"]](action.get("args", {}))})
        except Exception as exc:  # report every failure to the host, never crash the batch
            results.append({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
    json.dump(results, sys.stdout)


if __name__ == "__main__":
    main()
