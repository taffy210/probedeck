"""
Command builders for each diagnostic tool.

Every builder returns a list (argv form, never a shell string) so there is no
shell interpolation and therefore no command injection surface. The target is
validated against a strict allowlist before it ever reaches a builder.
"""
import re
import shlex

import probes

# Hostnames, IPv4/IPv6 literals, and CIDR. Deliberately strict: no spaces,
# no shell metacharacters, nothing that could break argv assumptions.
_TARGET_RE = re.compile(
    r"^[A-Za-z0-9]"          # must start alnum
    r"[A-Za-z0-9._:\-/]{0,253}"  # host/ip/cidr body
    r"[A-Za-z0-9]$"          # must end alnum
)


def validate_target(target: str) -> str:
    target = (target or "").strip()
    if not target or len(target) > 255:
        raise ValueError("Target is required and must be under 255 characters.")
    if not _TARGET_RE.match(target):
        raise ValueError(
            "Target contains invalid characters. Use a hostname, IP, or CIDR."
        )
    return target


def _split_extra(extra: str) -> list:
    """Operator-supplied raw args. Split with shlex, then reject any token
    that smuggles in a redirect or chaining metacharacter."""
    if not extra:
        return []
    tokens = shlex.split(extra)
    bad = {";", "&", "&&", "|", "||", ">", ">>", "<", "`", "$("}
    for t in tokens:
        if any(b in t for b in bad):
            raise ValueError(f"Disallowed token in extra args: {t}")
    return tokens


# Each entry: builder(target, opts) -> argv, plus metadata the UI reads.
def _mtr(target, opts):
    cycles = str(int(opts.get("cycles", 10)))
    return ["mtr", "--report", "--report-cycles", cycles, "--json", target]


def _ping(target, opts):
    count = str(int(opts.get("count", 5)))
    return ["ping", "-c", count, "-w", "30", target]


def _traceroute(target, opts):
    return ["traceroute", "-w", "2", target]


def _dig(target, opts):
    argv = ["dig", "+nocmd", "+noall", "+answer", "+stats"]
    resolver = opts.get("resolver", "").strip()
    if resolver:
        validate_target(resolver)
        argv.append(f"@{resolver}")
    rtype = opts.get("rtype", "A").strip().upper()
    if rtype not in {"A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR", "ANY"}:
        rtype = "A"
    argv += [target, rtype]
    return argv


def _nslookup(target, opts):
    argv = ["nslookup", target]
    resolver = opts.get("resolver", "").strip()
    if resolver:
        validate_target(resolver)
        argv.append(resolver)
    return argv


def _iperf3(target, opts):
    argv = ["iperf3", "-c", target, "--json"]
    if opts.get("reverse"):
        argv.append("-R")
    duration = str(int(opts.get("duration", 10)))
    argv += ["-t", duration]
    port = opts.get("port", "").strip()
    if port:
        if not port.isdigit() or not (1 <= int(port) <= 65535):
            raise ValueError("iperf3 port must be 1-65535.")
        argv += ["-p", port]
    return argv


def _nmap(target, opts):
    # Non-aggressive default: top ports, no OS detection, polite timing.
    argv = ["nmap", "-T3", "--top-ports", "100", target]
    argv += _split_extra(opts.get("extra", ""))
    return argv


def _curl_timing(target, opts):
    # Build a URL if a bare host was given.
    url = target
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    fmt = ("dns=%{time_namelookup}s connect=%{time_connect}s "
           "tls=%{time_appconnect}s ttfb=%{time_starttransfer}s "
           "total=%{time_total}s code=%{http_code}\\n")
    return ["curl", "-sS", "-o", "/dev/null", "-w", fmt, "--max-time", "30", url]


def _whois(target, opts):
    return ["whois", target]


def _tcpdump(target, opts):
    # Hard limits so a forgotten capture cannot fill the disk:
    # -c packet cap and a duration enforced by the runner via -G/-W rotation
    # is overkill here, so we cap packets and the runner also times out.
    count = str(int(opts.get("count", 500)))
    argv = ["tcpdump", "-n", "-c", count, "-w", opts["_pcap_path"]]
    iface = opts.get("iface", "").strip()
    if iface:
        if not re.match(r"^[A-Za-z0-9._-]{1,32}$", iface):
            raise ValueError("Invalid interface name.")
        argv += ["-i", iface]
    # host filter scoped to the validated target
    argv += ["host", target]
    return argv


TOOLS = {
    "mtr":        {"build": _mtr,        "label": "MTR",        "json": True,  "needs_target": True,  "timeout": 120},
    "ping":       {"build": _ping,       "label": "Ping",       "json": False, "needs_target": True,  "timeout": 40},
    "traceroute": {"build": _traceroute, "label": "Traceroute", "json": False, "needs_target": True,  "timeout": 120},
    "dig":        {"build": _dig,        "label": "DNS (dig)",  "json": False, "needs_target": True,  "timeout": 20},
    "nslookup":   {"build": _nslookup,   "label": "nslookup",   "json": False, "needs_target": True,  "timeout": 20},
    "iperf3":     {"build": _iperf3,     "label": "iperf3",     "json": True,  "needs_target": True,  "timeout": 60},
    "nmap":       {"build": _nmap,       "label": "nmap",       "json": False, "needs_target": True,  "timeout": 300},
    "curl":       {"build": _curl_timing,"label": "HTTP timing","json": False, "needs_target": True,  "timeout": 35},
    "whois":      {"build": _whois,      "label": "whois",      "json": False, "needs_target": True,  "timeout": 30},
    "tcpdump":    {"build": _tcpdump,    "label": "Packet capture", "json": False, "needs_target": True, "timeout": 120, "pcap": True},
    # Native (in-process) probes — no subprocess. They expose a `probe`
    # coroutine and a `describe` for the command line shown in history.
    "tcp":        {"probe": probes.tcp_probe,  "describe": probes.describe_tcp,
                   "label": "TCP port",  "json": False, "needs_target": True, "timeout": 15, "native": True},
    "tlscert":    {"probe": probes.tls_probe,  "describe": probes.describe_tls,
                   "label": "TLS cert",  "json": False, "needs_target": True, "timeout": 18, "native": True},
    "http":       {"probe": probes.http_probe, "describe": probes.describe_http,
                   "label": "HTTP check", "json": False, "needs_target": True, "timeout": 20, "native": True},
}
