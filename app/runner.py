"""
Async job runner. Each submitted job spawns a subprocess via asyncio,
writes stdout/stderr to the run's result directory, enforces a per-tool
timeout, and updates the SQLite index on completion.
"""
import asyncio
import json
import os
import shutil
import uuid
from datetime import datetime, timezone

import db
from tools import TOOLS, validate_target

DATA_DIR = os.environ.get("PROBEDECK_DATA", "/data")
RESULTS_DIR = os.path.join(DATA_DIR, "results")

# Live subprocesses keyed by job_id, so a cancel request can kill one mid-run.
# Entries are added when the process spawns and removed when it exits.
_PROCS = {}
# job_ids the user explicitly cancelled — distinguishes a deliberate stop from
# a timeout or a tool error when the killed process unwinds in _execute.
_CANCELLED = set()


def cancel_job(job_id: str) -> bool:
    """Kill a running job's process if we still hold it. Returns whether a
    live process was found. The _execute loop then records it as cancelled."""
    proc = _PROCS.get(job_id)
    if proc and proc.returncode is None:
        _CANCELLED.add(job_id)
        proc.kill()
        return True
    return False

# Coerce line buffering so tools flush output as it's produced instead of
# letting libc sit on a full 4KB block buffer until the process exits (the
# default when stdout is a pipe rather than a tty). Without this, "live"
# streaming would still only appear at completion for ping/traceroute/nmap.
# Detected once; if stdbuf is missing we fall back to running the bare argv.
_STDBUF = shutil.which("stdbuf")


def _now():
    return datetime.now(timezone.utc).isoformat()


def _launch_argv(argv):
    """Wrap the real command for execution. The DB/UI keep the clean argv;
    this only affects how the process is spawned. No effect on tools that
    buffer their whole output internally (mtr --report, iperf3 --json), which
    only emit on completion regardless."""
    if _STDBUF:
        return ["stdbuf", "-oL", "-eL", *argv]
    return argv


async def _stream_to_file(proc, out_path):
    """Drain stdout into output.txt as it arrives so /output can tail the
    file mid-run. Unbuffered writes (buffering=0) so a poller sees each chunk
    immediately. Reads in chunks rather than by line to avoid asyncio's
    64KiB line-length limit on tools that emit one large JSON document."""
    with open(out_path, "wb", buffering=0) as f:
        while True:
            chunk = await proc.stdout.read(4096)
            if not chunk:
                break
            f.write(chunk)
    await proc.wait()


async def run_job(tool: str, target: str, opts: dict) -> str:
    if tool not in TOOLS:
        raise ValueError(f"Unknown tool: {tool}")
    spec = TOOLS[tool]

    if spec.get("needs_target"):
        target = validate_target(target)

    job_id = uuid.uuid4().hex[:12]
    result_dir = os.path.join(RESULTS_DIR, job_id)
    os.makedirs(result_dir, exist_ok=True)

    # Keep the user-supplied opts for faithful re-runs; the per-run _pcap_path
    # is derived fresh each time so it isn't part of what we persist.
    opts_json = json.dumps(opts)

    # Native probes run in-process; CLI tools build an argv and spawn.
    if spec.get("native"):
        args_desc = spec["describe"](target, opts)  # may raise ValueError
        db.insert_run({
            "id": job_id, "tool": tool, "target": target, "args": args_desc,
            "opts": opts_json, "status": "running", "started_at": _now(),
            "result_dir": result_dir,
        })
        asyncio.create_task(_execute_native(job_id, spec, target, opts, result_dir))
        return job_id

    if spec.get("pcap"):
        opts = {**opts, "_pcap_path": os.path.join(result_dir, "capture.pcap")}

    argv = spec["build"](target, opts)

    db.insert_run({
        "id": job_id,
        "tool": tool,
        "target": target,
        "args": " ".join(argv),
        "opts": opts_json,
        "status": "running",
        "started_at": _now(),
        "result_dir": result_dir,
    })

    asyncio.create_task(_execute(job_id, argv, spec, result_dir))
    return job_id


async def _execute_native(job_id, spec, target, opts, result_dir):
    """Run an in-process probe coroutine, write its text to output.txt, and
    record completion — the no-subprocess analogue of _execute."""
    out_path = os.path.join(result_dir, "output.txt")
    status, exit_code = "done", 0
    try:
        text = await asyncio.wait_for(
            spec["probe"](target, opts), timeout=spec.get("timeout", 20))
        with open(out_path, "w", errors="replace") as f:
            f.write(text)
    except asyncio.TimeoutError:
        with open(out_path, "w") as f:
            f.write("[probedeck] probe timed out\n")
        status, exit_code = "timeout", -1
    except Exception as e:
        with open(out_path, "w") as f:
            f.write(f"[probedeck] probe error: {e}\n")
        status, exit_code = "error", -1
    db.finish_run(job_id, status, exit_code, _now())


async def _execute(job_id, argv, spec, result_dir):
    out_path = os.path.join(result_dir, "output.txt")
    timeout = spec.get("timeout", 60)
    status, exit_code = "done", None

    try:
        proc = await asyncio.create_subprocess_exec(
            *_launch_argv(argv),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        _PROCS[job_id] = proc
        try:
            # _stream_to_file creates and fills output.txt as data arrives.
            await asyncio.wait_for(_stream_to_file(proc, out_path), timeout=timeout)
            exit_code = proc.returncode
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            with open(out_path, "ab") as f:
                f.write(b"\n[probedeck] killed: exceeded timeout of %ds\n" % timeout)
            status, exit_code = "timeout", -1

        # A user cancel kills the process too; surface it as its own status
        # rather than a generic non-zero-exit error.
        if job_id in _CANCELLED:
            with open(out_path, "ab") as f:
                f.write(b"\n[probedeck] cancelled by user\n")
            status, exit_code = "cancelled", -1

        # json tools emit a single json document; mirror the captured output
        # to output.json so the json download/parse path keeps working.
        if spec.get("json") and status == "done":
            shutil.copyfile(out_path, os.path.join(result_dir, "output.json"))

        if status == "done" and exit_code not in (0, None):
            status = "error"

    except FileNotFoundError:
        with open(out_path, "w") as f:
            f.write("[probedeck] tool binary not found in image\n")
        status, exit_code = "error", -1
    except Exception as e:
        with open(out_path, "ab") as f:
            f.write(f"\n[probedeck] runner error: {e}\n".encode("utf-8", "replace"))
        status, exit_code = "error", -1
    finally:
        _PROCS.pop(job_id, None)
        _CANCELLED.discard(job_id)

    db.finish_run(job_id, status, exit_code, _now())
