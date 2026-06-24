"""
Turn a finished run's raw output into a handful of headline stats so the
console shows a verdict, not just a wall of text. Every parser is defensive:
anything it can't read yields an empty list and the UI simply omits the strip.
"""
import json
import re


def _ping(text):
    out = []
    m = re.search(r"(\d+)\s+packets transmitted,\s+(\d+)\s+received.*?([\d.]+)%\s+packet loss",
                  text, re.S)
    if m:
        out.append(("loss", f"{m.group(3)}%"))
        out.append(("recv", f"{m.group(2)}/{m.group(1)}"))
    m = re.search(r"min/avg/max(?:/mdev)?\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)", text)
    if m:
        out.append(("avg rtt", f"{m.group(2)} ms"))
        out.append(("min/max", f"{m.group(1)}/{m.group(3)} ms"))
    return out


def _mtr(text):
    try:
        hubs = json.loads(text)["report"]["hubs"]
    except Exception:
        return []
    if not hubs:
        return []
    dest = hubs[-1]
    worst = max(hubs, key=lambda h: h.get("Loss%", 0))
    out = [("hops", str(len(hubs)))]
    if "Avg" in dest:
        out.append(("dest avg", f"{dest['Avg']} ms"))
    out.append(("worst loss", f"{worst.get('Loss%', 0)}%"))
    return out


def _iperf3(text):
    try:
        end = json.loads(text)["end"]
    except Exception:
        return []
    out = []
    for key, label in (("sum_sent", "sent"), ("sum_received", "recv")):
        bps = end.get(key, {}).get("bits_per_second")
        if bps:
            out.append((label, f"{bps / 1e6:.1f} Mbit/s"))
    retx = end.get("sum_sent", {}).get("retransmits")
    if retx is not None:
        out.append(("retransmits", str(retx)))
    return out


def _traceroute(text):
    hops = re.findall(r"^\s*(\d+)\s+", text, re.M)
    if not hops:
        return []
    out = [("hops", hops[-1])]
    # Trailing all-timeout hops mean the destination never answered.
    last = text.strip().splitlines()[-1] if text.strip() else ""
    out.append(("reached", "no" if last.count("*") >= 3 else "yes"))
    return out


def _curl(text):
    out = []
    for field, label in (("total", "total"), ("ttfb", "ttfb"),
                         ("connect", "connect"), ("tls", "tls")):
        m = re.search(rf"\b{field}=([\d.]+)s", text)
        if m:
            out.append((label, f"{float(m.group(1)) * 1000:.0f} ms"))
    m = re.search(r"\bcode=(\d+)", text)
    if m:
        out.append(("http", m.group(1)))
    return out


def _nmap(text):
    open_ports = re.findall(r"^(\d+)/\w+\s+open\b", text, re.M)
    if not re.search(r"\bopen\b|\bclosed\b|\bfiltered\b", text):
        return []
    return [("open ports", str(len(open_ports)))]


def _dig(text):
    # +answer lines are the records; +stats gives the query time.
    answers = [ln for ln in text.splitlines()
               if ln.strip() and not ln.lstrip().startswith(";")]
    out = [("answers", str(len(answers)))]
    m = re.search(r"Query time:\s*(\d+)\s*msec", text)
    if m:
        out.append(("query", f"{m.group(1)} ms"))
    return out


def _tcpdump(text):
    m = re.search(r"(\d+)\s+packets captured", text)
    return [("captured", m.group(1))] if m else []


def _kv(text):
    """Parse the `key: value` lines the native probes emit (split on the first
    colon so values like a timestamp keep their own colons)."""
    d = {}
    for ln in text.splitlines():
        if ":" in ln:
            k, v = ln.split(":", 1)
            d[k.strip().lower()] = v.strip()
    return d


def _tcp(text):
    d = _kv(text)
    out = []
    if "state" in d:
        out.append(("state", d["state"]))
    if "connect" in d:
        out.append(("connect", d["connect"]))
    return out


def _tlscert(text):
    d = _kv(text)
    out = []
    if "state" in d:
        out.append(("state", d["state"]))
    if "days left" in d:
        out.append(("days left", d["days left"]))
    if "expires" in d:
        out.append(("expires", d["expires"][:10]))
    if "issuer" in d:
        out.append(("issuer", d["issuer"]))
    return out


def _http(text):
    d = _kv(text)
    out = []
    if "status" in d:
        out.append(("status", d["status"]))
    if "time" in d:
        out.append(("time", d["time"]))
    if "result" in d:
        out.append(("result", d["result"]))
    return out


def _dns(text):
    d = _kv(text)
    out = []
    if d.get("state"):
        out.append(("state", d["state"]))
    if d.get("addresses"):
        out.append(("addresses", d["addresses"]))
    if "resolve" in d:
        out.append(("resolve", d["resolve"]))
    return out


_PARSERS = {
    "ping": _ping,
    "mtr": _mtr,
    "iperf3": _iperf3,
    "traceroute": _traceroute,
    "curl": _curl,
    "nmap": _nmap,
    "dig": _dig,
    "tcpdump": _tcpdump,
    "tcp": _tcp,
    "tlscert": _tlscert,
    "http": _http,
    "dns": _dns,
}


def summarize(tool, text):
    """Return a list of (label, value) stat pairs, or [] when nothing parses."""
    parser = _PARSERS.get(tool)
    if not parser or not text:
        return []
    try:
        return parser(text)
    except Exception:
        return []
