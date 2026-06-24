"""
Path insight. Runs a numeric traceroute, then annotates each hop's IP with its
ASN, network owner and country via the Team Cymru whois service — turning a
list of anonymous IPs into "it's dying at the Cogent handoff in Frankfurt".

The traceroute and every whois lookup run in argv form against validated /
non-routable-filtered IPs, so no shell and no untrusted-target surface.
"""
import asyncio
import ipaddress
import re

from tools import validate_target

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _is_global(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


async def _traceroute(target):
    # -n numeric, -q 1 one probe/hop, -w 2 short wait, -m 30 hop cap.
    argv = ["traceroute", "-n", "-q", "1", "-w", "2", "-m", "30", target]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=90)
        return out.decode("utf-8", "replace")
    except Exception:
        return ""


def _parse_hops(text):
    """Each traceroute line starts with a hop number; pull the first IP and
    the first RTT, or mark the hop as a timeout."""
    hops = []
    for ln in text.splitlines():
        m = re.match(r"\s*(\d+)\s+(.*)", ln)
        if not m:
            continue
        hopno, rest = int(m.group(1)), m.group(2)
        ipm = _IP_RE.search(rest)
        rttm = re.search(r"([\d.]+)\s*ms", rest)
        hops.append({
            "hop": hopno,
            "ip": ipm.group(1) if ipm else None,
            "rtt": rttm.group(1) if rttm else None,
            "timeout": "*" in rest and not ipm,
        })
    return hops


async def _cymru(ip):
    """Team Cymru verbose lookup for one IP. Returns (asn, owner, cc)."""
    argv = ["whois", "-h", "whois.cymru.com", f" -v {ip}"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        text = out.decode("utf-8", "replace")
    except Exception:
        return None, None, None
    # Output is a header row then a pipe-delimited data row:
    # AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    for ln in text.splitlines():
        if ln.lower().startswith("as") and "|" in ln and "IP" in ln:
            continue
        if "|" in ln:
            cols = [c.strip() for c in ln.split("|")]
            if len(cols) >= 7 and cols[0].isdigit():
                return cols[0], cols[6], cols[3]
    return None, None, None


async def trace(target):
    target = validate_target(target)
    text = await _traceroute(target)
    hops = _parse_hops(text)

    # Look up each distinct globally-routable IP once, concurrently.
    ips = {h["ip"] for h in hops if h["ip"] and _is_global(h["ip"])}
    lookups = await asyncio.gather(*[_cymru(ip) for ip in ips])
    info = dict(zip(ips, lookups))

    prev_asn = None
    for h in hops:
        asn = owner = cc = None
        if h["ip"]:
            if _is_global(h["ip"]):
                asn, owner, cc = info.get(h["ip"], (None, None, None))
            else:
                owner = "private / local"
        h["asn"], h["owner"], h["cc"] = asn, owner, cc
        # Flag the hop where the network operator changes — handoffs are where
        # paths tend to break.
        h["boundary"] = bool(asn and prev_asn and asn != prev_asn)
        if asn:
            prev_asn = asn

    networks = []
    seen = set()
    for h in hops:
        if h["asn"] and h["asn"] not in seen:
            seen.add(h["asn"])
            networks.append({"asn": h["asn"], "owner": h["owner"], "cc": h["cc"]})

    reached = bool(hops) and hops[-1]["ip"] is not None
    return {"target": target, "hops": hops, "networks": networks,
            "reached": reached, "raw": text}
