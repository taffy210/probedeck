"""
DNS propagation check. Fans one query out across many public resolvers (and
the domain's own authoritative nameservers) at once, then flags where answers
disagree — useful right after changing a record to see who's caught up.

Every query is a plain `dig` in argv form against a resolver from a fixed
server-side list (or an authoritative NS discovered for the domain), so the
no-shell / validated-target guarantees still hold.
"""
import asyncio
import re

from tools import validate_target

# Curated public resolvers: (label, IP). Kept to well-known anycast services.
PUBLIC_RESOLVERS = [
    ("Cloudflare",     "1.1.1.1"),
    ("Google",         "8.8.8.8"),
    ("Quad9",          "9.9.9.9"),
    ("OpenDNS",        "208.67.222.222"),
    ("AdGuard",        "94.140.14.14"),
    ("Level3",         "4.2.2.2"),
    ("Comodo",         "8.26.56.26"),
    ("DNS.Watch",      "84.200.69.80"),
    ("Yandex",         "77.88.8.8"),
    ("CleanBrowsing",  "185.228.168.9"),
    ("ControlD",       "76.76.2.0"),
    ("Verisign",       "64.6.64.6"),
]

RTYPES = {"A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR"}


async def _dig(label, resolver, domain, rtype, kind):
    """Query one resolver. Returns a result dict with the sorted rdata set."""
    argv = ["dig", "+nocmd", "+noall", "+answer", "+stats",
            "+time=3", "+tries=1", f"@{resolver}", domain, rtype]
    text = ""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=6)
        text = out.decode("utf-8", "replace")
    except Exception:
        text = ""

    answers = []
    for ln in text.splitlines():
        s = ln.strip()
        if not s or s.startswith(";"):
            continue
        parts = s.split()
        if len(parts) >= 5:  # name ttl class type rdata...
            answers.append(" ".join(parts[4:]))
    answers = sorted(set(answers))

    ms = None
    m = re.search(r"Query time:\s*(\d+)\s*msec", text)
    if m:
        ms = int(m.group(1))

    return {"label": label, "resolver": resolver, "kind": kind,
            "answers": answers, "ms": ms, "ok": bool(answers)}


async def _authoritative_ns(domain):
    """Best-effort: ask a public resolver for the domain's NS names so we can
    also query the source of truth directly."""
    res = await _dig("ns-discovery", "1.1.1.1", domain, "NS", "public")
    names = []
    for a in res["answers"]:
        host = a.rstrip(".")
        try:
            names.append(validate_target(host))
        except ValueError:
            continue
    return names[:6]


async def check(domain, rtype):
    domain = validate_target(domain)
    rtype = (rtype or "A").upper()
    if rtype not in RTYPES:
        rtype = "A"

    tasks = [_dig(lbl, ip, domain, rtype, "public") for lbl, ip in PUBLIC_RESOLVERS]

    # Add authoritative nameservers when we can find them.
    ns_names = []
    if rtype != "NS":
        try:
            ns_names = await _authoritative_ns(domain)
        except Exception:
            ns_names = []
    for ns in ns_names:
        tasks.append(_dig(ns, ns, domain, rtype, "authoritative"))

    results = await asyncio.gather(*tasks)

    # Group by answer set to spot disagreement; pick the most common as the
    # reference ("majority") and mark everyone else as differing.
    groups = {}
    for r in results:
        key = " | ".join(r["answers"]) if r["answers"] else ""
        groups.setdefault(key, []).append(r)
    answered = {k: v for k, v in groups.items() if k}
    majority = max(answered, key=lambda k: len(answered[k]), default="")
    for r in results:
        key = " | ".join(r["answers"]) if r["answers"] else ""
        if not r["answers"]:
            r["state"] = "noanswer"
        elif key == majority:
            r["state"] = "match"
        else:
            r["state"] = "differs"

    distinct = len(answered)
    return {
        "domain": domain, "rtype": rtype,
        "results": results,
        "distinct": distinct,
        "in_sync": distinct <= 1,
        "majority": majority,
        "responded": sum(1 for r in results if r["ok"]),
        "total": len(results),
    }
