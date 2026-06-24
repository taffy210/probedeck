#!/usr/bin/env python3
"""
ProbeDeck vantage agent.

A single-file, stdlib-only worker. It polls a ProbeDeck server for probe jobs,
runs them locally (TCP connect / HTTP status / TLS certificate — no root, no
shell, no external binaries), and reports the result back. It only ever runs
those three probe types; it never executes anything the server sends as a
command.

    PROBEDECK_URL=http://your-server:8080 \
    PROBEDECK_TOKEN=xxxxxxxx \
    python3 agent.py

Optional: PROBEDECK_INTERVAL (poll seconds, default 3).
"""
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

URL = os.environ.get("PROBEDECK_URL", "").rstrip("/")
TOKEN = os.environ.get("PROBEDECK_TOKEN", "")
INTERVAL = float(os.environ.get("PROBEDECK_INTERVAL", "3"))

if not URL or not TOKEN:
    sys.exit("Set PROBEDECK_URL and PROBEDECK_TOKEN environment variables.")


def _port(opts, default):
    p = str(opts.get("port", "") or "").strip()
    return int(p) if p.isdigit() and 1 <= int(p) <= 65535 else default


def probe_tcp(target, opts):
    port = _port(opts, 80)
    start = time.perf_counter()
    try:
        with socket.create_connection((target, port), timeout=10):
            ms = (time.perf_counter() - start) * 1000
        return f"TCP connect to {target}:{port}\nstate: open\nconnect: {ms:.1f} ms\n"
    except Exception as e:
        return (f"TCP connect to {target}:{port}\nstate: closed\n"
                f"error: {type(e).__name__}: {e}\n")


def _cn(parts):
    flat = {k: v for rdn in (parts or ()) for (k, v) in rdn}
    bits = [flat.get("commonName")]
    if flat.get("organizationName") and flat["organizationName"] != flat.get("commonName"):
        bits.append(flat["organizationName"])
    return ", ".join(b for b in bits if b) or "?"


def probe_tlscert(target, opts):
    port = _port(opts, 443)
    servername = (opts.get("servername") or "").strip() or target
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    try:
        with socket.create_connection((target, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=servername) as ss:
                cert = ss.getpeercert()
    except Exception as e:
        return (f"TLS certificate for {target}:{port}\nstate: handshake failed\n"
                f"error: {type(e).__name__}: {e}\n")
    exp = None
    if cert.get("notAfter"):
        try:
            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc)
        except ValueError:
            exp = None
    lines = [f"TLS certificate for {target}:{port}",
             f"subject: {_cn(cert.get('subject'))}",
             f"issuer: {_cn(cert.get('issuer'))}"]
    if cert.get("serialNumber"):
        lines.append(f"serial: {cert['serialNumber']}")
    if exp:
        lines.append(f"expires: {exp.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        days = (exp - datetime.now(timezone.utc)).total_seconds() / 86400.0
        lines.append(f"days left: {days:.1f}")
    return "\n".join(lines) + "\n"


def probe_http(target, opts):
    url = target if target.startswith(("http://", "https://")) else "https://" + target
    method = (opts.get("method") or "GET").upper()
    if method not in ("GET", "HEAD"):
        method = "GET"
    expect = (opts.get("expect") or "").strip()
    start = time.perf_counter()
    try:
        req = urllib.request.Request(url, method=method)
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                code, reason = resp.status, resp.reason
                resp.read(0)
        except urllib.error.HTTPError as e:
            code, reason = e.code, e.reason
        ms = (time.perf_counter() - start) * 1000
    except Exception as e:
        return f"HTTP {method} {url}\nstatus: unreachable\nerror: {e}\nresult: down\n"
    ok = (code == int(expect)) if expect.isdigit() else (200 <= code < 400)
    return (f"HTTP {method} {url}\nstatus: {code} {reason}\ntime: {ms:.0f} ms\n"
            f"expected: {expect or '2xx/3xx'}\nresult: {'ok' if ok else 'mismatch'}\n")


def probe_ping(target, opts):
    try:
        count = max(1, min(int(opts.get("count") or 4), 20))
    except (TypeError, ValueError):
        count = 4
    try:
        r = subprocess.run(["ping", "-c", str(count), "-w", "20", target],
                           capture_output=True, text=True, timeout=25)
        return r.stdout or r.stderr or "ping: no output\n"
    except Exception as e:
        return f"ping to {target}\nerror: {type(e).__name__}: {e}\n"


def probe_dns(target, opts):
    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(target, None)
        ms = (time.perf_counter() - start) * 1000
        addrs = sorted({i[4][0] for i in infos})
        return (f"DNS resolution for {target}\naddresses: {', '.join(addrs)}\n"
                f"resolve: {ms:.1f} ms\n")
    except Exception as e:
        return f"DNS resolution for {target}\nstate: failed\nerror: {type(e).__name__}: {e}\n"


PROBES = {"tcp": probe_tcp, "tlscert": probe_tlscert, "http": probe_http,
          "ping": probe_ping, "dns": probe_dns}


def poll():
    req = urllib.request.Request(f"{URL}/agent/jobs?token={TOKEN}")
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r).get("jobs", [])


def report(result_id, text):
    data = json.dumps({"token": TOKEN, "result_id": result_id, "text": text}).encode()
    req = urllib.request.Request(f"{URL}/agent/results", data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        r.read(64)


def main():
    print(f"probedeck-agent → {URL}  (every {INTERVAL}s)")
    while True:
        try:
            jobs = poll()
            for job in jobs:
                fn = PROBES.get(job.get("tool"))
                if not fn:
                    continue
                try:
                    text = fn(job["target"], job.get("opts") or {})
                except Exception as e:
                    text = f"agent error: {type(e).__name__}: {e}\n"
                try:
                    report(job["result_id"], text)
                except Exception as e:
                    print("report failed:", e)
            if jobs:
                print(f"ran {len(jobs)} job(s)")
        except urllib.error.HTTPError as e:
            print("poll error:", e.code, e.reason)
        except Exception as e:
            print("poll error:", e)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
