"""
Native (in-process) probes: TCP connect, TLS certificate expiry, and HTTP
status checks.

Unlike the CLI tools these never spawn a subprocess — they open a socket /
urllib request directly against an already-validated host, so there's no shell
and no argv at all (an even smaller attack surface than the argv tools). Each
returns a block of human-readable text that the same summarize / metric
pipeline parses, so history, compare, console summaries and monitors all work
without special-casing.
"""
import asyncio
import socket
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone


def _port(opts, default):
    p = str(opts.get("port", "") or "").strip()
    if not p:
        return default
    if not p.isdigit() or not (1 <= int(p) <= 65535):
        raise ValueError("Port must be 1-65535.")
    return int(p)


# --- TCP connect ----------------------------------------------------------

def describe_tcp(target, opts):
    return f"tcp connect {target}:{_port(opts, 80)}"


async def tcp_probe(target, opts):
    port = _port(opts, 80)
    start = time.perf_counter()
    try:
        fut = asyncio.open_connection(target, port)
        _, writer = await asyncio.wait_for(fut, timeout=10)
        ms = (time.perf_counter() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return (f"TCP connect to {target}:{port}\n"
                f"state: open\n"
                f"connect: {ms:.1f} ms\n")
    except Exception as e:
        return (f"TCP connect to {target}:{port}\n"
                f"state: closed\n"
                f"error: {type(e).__name__}: {e}\n")


# --- TLS certificate ------------------------------------------------------

def describe_tls(target, opts):
    return f"tls cert {target}:{_port(opts, 443)}"


def _cn(parts):
    """Pull a commonName (and org) out of cert subject/issuer tuples."""
    flat = {k: v for rdn in (parts or ()) for (k, v) in rdn}
    bits = [flat.get("commonName")]
    if flat.get("organizationName") and flat["organizationName"] != flat.get("commonName"):
        bits.append(flat["organizationName"])
    return ", ".join(b for b in bits if b) or "?"


def _tls_sync(host, port, servername):
    # Verify against the system trust store so getpeercert() returns the parsed
    # fields, but tolerate a hostname/SNI mismatch (we only need the dates).
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=servername) as ss:
            return ss.getpeercert()


async def tls_probe(target, opts):
    port = _port(opts, 443)
    servername = (opts.get("servername") or "").strip() or target
    loop = asyncio.get_event_loop()
    try:
        cert = await asyncio.wait_for(
            loop.run_in_executor(None, _tls_sync, target, port, servername),
            timeout=12)
    except Exception as e:
        return (f"TLS certificate for {target}:{port}\n"
                f"state: handshake failed\n"
                f"error: {type(e).__name__}: {e}\n"
                f"(an expired or untrusted cert will fail the handshake here)\n")

    not_after = cert.get("notAfter")
    exp = None
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc)
        except ValueError:
            exp = None
    days = None
    if exp:
        days = (exp - datetime.now(timezone.utc)).total_seconds() / 86400.0

    lines = [f"TLS certificate for {target}:{port}",
             f"subject: {_cn(cert.get('subject'))}",
             f"issuer: {_cn(cert.get('issuer'))}"]
    if cert.get("serialNumber"):
        lines.append(f"serial: {cert['serialNumber']}")
    if exp:
        lines.append(f"expires: {exp.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    if days is not None:
        lines.append(f"days left: {days:.1f}")
    return "\n".join(lines) + "\n"


# --- HTTP status ----------------------------------------------------------

# --- ping / dns (used by vantage checks; ping needs the system binary) -----

async def ping_probe(target, opts):
    try:
        count = max(1, min(int(opts.get("count", 4) or 4), 20))
    except (TypeError, ValueError):
        count = 4
    argv = ["ping", "-c", str(count), "-w", "20", target]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=25)
        return out.decode("utf-8", "replace")
    except Exception as e:
        return f"ping to {target}\nerror: {type(e).__name__}: {e}\n"


async def dns_probe(target, opts):
    loop = asyncio.get_event_loop()
    start = time.perf_counter()
    try:
        infos = await loop.run_in_executor(None, socket.getaddrinfo, target, None)
        ms = (time.perf_counter() - start) * 1000
        addrs = sorted({i[4][0] for i in infos})
        return (f"DNS resolution for {target}\n"
                f"addresses: {', '.join(addrs)}\n"
                f"resolve: {ms:.1f} ms\n")
    except Exception as e:
        return (f"DNS resolution for {target}\n"
                f"state: failed\nerror: {type(e).__name__}: {e}\n")


def describe_http(target, opts):
    return f"http {(opts.get('method') or 'GET').upper()} {_http_url(target)}"


def _http_url(target):
    return target if target.startswith(("http://", "https://")) else "https://" + target


def _http_sync(url, method, timeout=12):
    req = urllib.request.Request(url, method=method)
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code, reason = resp.status, resp.reason
            resp.read(0)
    except urllib.error.HTTPError as e:
        code, reason = e.code, e.reason
    ms = (time.perf_counter() - start) * 1000
    return code, reason, ms


async def http_probe(target, opts):
    url = _http_url(target)
    method = (opts.get("method") or "GET").upper()
    if method not in ("GET", "HEAD"):
        method = "GET"
    expect = (opts.get("expect") or "").strip()
    loop = asyncio.get_event_loop()
    try:
        code, reason, ms = await asyncio.wait_for(
            loop.run_in_executor(None, _http_sync, url, method), timeout=15)
    except Exception as e:
        return (f"HTTP {method} {url}\n"
                f"status: unreachable\n"
                f"error: {type(e).__name__}: {e}\n"
                f"result: down\n")

    if expect.isdigit():
        ok = code == int(expect)
        exp_txt = expect
    else:
        ok = 200 <= code < 400
        exp_txt = "2xx/3xx"
    return (f"HTTP {method} {url}\n"
            f"status: {code} {reason}\n"
            f"time: {ms:.0f} ms\n"
            f"expected: {exp_txt}\n"
            f"result: {'ok' if ok else 'mismatch'}\n")
