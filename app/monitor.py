"""
Recurring monitors. A background scheduler ticks each enabled monitor on its
interval, runs the probe once (no history row, no files), extracts a single
metric (latency / loss / throughput) and stores it as a time-series sample the
UI draws as a sparkline.

Reuses the same argv builders and target allowlist as one-off runs, so the
no-shell / validated-target guarantees hold here too.
"""
import asyncio
import json
import re
import urllib.request
from datetime import datetime, timezone

import db
import summarize
from tools import TOOLS

# Tools that yield a meaningful scalar to trend. tcpdump/whois/dns are excluded
# from monitoring because there's nothing useful to plot over time.
MONITORABLE = {"ping", "mtr", "iperf3", "curl", "tcp", "tlscert", "http", "dig"}

# Tools that expose no scalar to trend but a stable fingerprint to watch for
# change (drift monitoring). dig tracks its answer set; tlscert its serial.
FINGERPRINTABLE = {"dig", "tlscert"}

_inflight = set()  # monitor ids currently sampling, to avoid overlap


def _now():
    return datetime.now(timezone.utc).isoformat()


def _num(s):
    if not s:
        return None
    m = re.search(r"-?[\d.]+", s)
    return float(m.group()) if m else None


def metric_for(tool, text):
    """Reduce raw output to (ok, value, unit, loss). value/loss may be None."""
    pairs = dict(summarize.summarize(tool, text))
    value = unit = loss = None
    if tool == "ping":
        value, unit, loss = _num(pairs.get("avg rtt")), "ms", _num(pairs.get("loss"))
    elif tool == "mtr":
        value, unit, loss = _num(pairs.get("dest avg")), "ms", _num(pairs.get("worst loss"))
    elif tool == "iperf3":
        value, unit = _num(pairs.get("recv") or pairs.get("sent")), "Mbit/s"
    elif tool == "curl":
        value, unit = _num(pairs.get("total")), "ms"
    elif tool == "tcp":
        value, unit = _num(pairs.get("connect")), "ms"
        if pairs.get("state") == "closed":
            return False, None, "ms", None
    elif tool == "tlscert":
        value, unit = _num(pairs.get("days left")), "days"
        if pairs.get("state") == "handshake failed":
            return False, None, "days", None
    elif tool == "http":
        value, unit = _num(pairs.get("time")), "ms"
        if pairs.get("result") in ("down", "mismatch"):
            return False, value, "ms", None
    elif tool == "dig":
        # No scalar to trend — reachability is "did we get an answer set".
        return (fingerprint_for("dig", text) is not None), None, "", None
    elif tool == "dns":
        if not pairs.get("addresses"):
            return False, None, "ms", None
        return True, _num(pairs.get("resolve")), "ms", None
    # Reachable if we got a number, and (for loss-aware tools) not a total loss.
    ok = value is not None and (loss is None or loss < 100)
    return ok, value, unit, loss


def fingerprint_for(tool, text):
    """A stable string identifying the current answer for change-detection, or
    None when the probe didn't yield one."""
    if not text:
        return None
    if tool == "dig":
        answers = []
        for ln in text.splitlines():
            s = ln.strip()
            if not s or s.startswith(";"):
                continue
            parts = s.split()
            if len(parts) >= 5:  # name ttl class type rdata...
                answers.append(" ".join(parts[4:]))
        answers = sorted(set(answers))
        return " | ".join(answers) if answers else None
    if tool == "tlscert":
        d = dict(summarize.summarize("tlscert", text))
        m = re.search(r"^serial:\s*(\S+)", text, re.M)
        serial = m.group(1) if m else None
        # Prefer the serial (changes on reissue); fall back to the expiry date.
        if serial:
            return f"serial:{serial}"
        return f"expires:{d['expires']}" if d.get("expires") else None
    return None


async def sample_once(mon):
    """Run one probe for a monitor and persist the resulting sample."""
    tool = mon["tool"]
    spec = TOOLS.get(tool)
    if not spec or spec.get("pcap"):
        return
    opts = json.loads(mon.get("opts") or "{}")

    # Cap the probe so it can't overrun its own interval.
    timeout = min(spec.get("timeout", 60), max(10, mon["interval_sec"] - 2))
    text = ""

    if spec.get("native"):
        # In-process probe — no subprocess to build or kill.
        try:
            text = await asyncio.wait_for(spec["probe"](mon["target"], opts),
                                          timeout=timeout)
        except Exception:
            text = ""
    else:
        try:
            argv = spec["build"](mon["target"], opts)
        except Exception:
            db.add_sample(mon["id"], _now(), False, None, None, None)
            db.touch_monitor(mon["id"], _now())
            return
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT)
            try:
                out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                text = out.decode("utf-8", "replace")
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
        except Exception:
            text = ""

    ok, value, unit, loss = metric_for(tool, text)
    db.add_sample(mon["id"], _now(), ok, value, unit, loss)
    db.touch_monitor(mon["id"], _now())
    await _apply_alerts(mon, ok, value, unit, loss)
    await _check_drift(mon, tool, text)


# --- alerting -------------------------------------------------------------

def _evaluate(mon, ok, value, loss):
    """Decide whether this sample breaches the monitor's rules.
    Returns (breached, reason, metric) where metric is the offending value.

    warn_latency is a ceiling (alert when value goes ABOVE it — latency, http
    time); warn_floor is a floor (alert when value drops BELOW it — cert days
    remaining, iperf3 throughput); warn_loss is a packet-loss ceiling."""
    if not ok:
        return True, "down", value
    wl = mon.get("warn_latency")
    if wl and value is not None and value > wl:
        return True, "high", value
    wf = mon.get("warn_floor")
    if wf and value is not None and value < wf:
        return True, "low", value
    wp = mon.get("warn_loss")
    if wp and loss is not None and loss > wp:
        return True, "loss", loss
    return False, None, value


def in_maintenance(monitor_id, now=None):
    """Is the monitor inside an active maintenance window right now? Windows
    with a NULL monitor_id apply to every monitor. Daily windows compare the
    UTC time-of-day and handle ranges that wrap past midnight."""
    now = now or datetime.now(timezone.utc)
    tod = now.strftime("%H:%M")
    for w in db.list_maintenance():
        if w["monitor_id"] is not None and w["monitor_id"] != monitor_id:
            continue
        if w["kind"] == "once":
            try:
                s = datetime.fromisoformat(w["starts_at"])
                e = datetime.fromisoformat(w["ends_at"])
            except ValueError:
                continue
            if s <= now <= e:
                return True
        elif w["kind"] == "daily":
            s, e = w["starts_at"], w["ends_at"]
            if (s <= e and s <= tod <= e) or (s > e and (tod >= s or tod <= e)):
                return True
    return False


async def _apply_alerts(mon, ok, value, unit, loss):
    """Run the breach state machine: open an incident once breaches reach the
    monitor's down_after threshold, close it on the next healthy sample, and
    fire the webhook on each open/close edge."""
    breached, reason, metric = _evaluate(mon, ok, value, loss)
    streak = mon.get("breach_streak") or 0
    open_id = mon.get("open_incident_id")
    down_after = mon.get("down_after") or 2
    now = _now()

    # Maintenance windows silence alerts: don't open incidents or fire while
    # suppressed (streak is frozen so there's no storm when the window ends),
    # but let an already-open incident resolve quietly on recovery.
    if in_maintenance(mon["id"]):
        if not breached and open_id:
            db.close_incident(open_id, now)
            db.set_alert_state(mon["id"], 0, None)
        return

    if breached:
        streak += 1
        if open_id:
            if metric is not None:
                db.update_incident(open_id, metric)
        elif streak >= down_after:
            open_id = db.open_incident(mon["id"], now, reason, metric)
            await _fire(mon, "down", reason, metric, unit)
    else:
        if open_id:
            db.close_incident(open_id, now)
            await _fire(mon, "up", None, value, unit)
            open_id = None
        streak = 0

    db.set_alert_state(mon["id"], streak, open_id)


def _fmt(value, unit):
    if value is None:
        return ""
    return f" ({value:g}{unit or ''})"


def _post_webhook(url, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=6) as resp:  # noqa: S310 (operator URL)
        resp.read(1024)


async def _send(mon, msg, status, reason=None):
    """POST a JSON alert to the monitor's webhook, if configured. The body
    carries both `content` (Discord) and `text` (Slack/ntfy) so one URL works
    across the common chat/notification services."""
    url = (mon.get("webhook_url") or "").strip()
    if not url or not url.startswith(("http://", "https://")):
        return
    payload = {"content": msg, "text": msg, "username": "ProbeDeck",
               "monitor": mon["label"], "status": status, "reason": reason}
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _post_webhook, url, payload)
    except Exception:
        pass  # a dead webhook must never break the sampling loop


async def _fire(mon, status, reason, value, unit):
    words = {"down": "unreachable", "high": "above threshold",
             "low": "below threshold", "loss": "packet loss"}
    if status == "down":
        why = words.get(reason, reason)
        msg = f"🔴 ProbeDeck: {mon['label']} is DOWN" + \
              (f" — {why}{_fmt(value, unit)}" if reason else "")
    else:
        msg = f"🟢 ProbeDeck: {mon['label']} recovered{_fmt(value, unit)}"
    await _send(mon, msg, status, reason)


async def _check_drift(mon, tool, text):
    """Detect a change in a watched fingerprint (DNS answer set / cert serial)
    and record it as a point-in-time drift event + alert."""
    if tool not in FINGERPRINTABLE:
        return
    fp = fingerprint_for(tool, text)
    if fp is None:
        return
    prev = mon.get("last_fp")
    if (mon.get("watch_drift") and prev and fp != prev
            and not in_maintenance(mon["id"])):
        db.add_event_incident(mon["id"], _now(), "drift", f"{prev}  →  {fp}")
        await _send(mon, f"🟠 ProbeDeck: {mon['label']} changed\n{prev}  →  {fp}",
                    "drift", "drift")
    if fp != prev:
        db.set_monitor_fp(mon["id"], fp)


def _due(mon, now):
    last = mon.get("last_run_at")
    if not last:
        return True
    try:
        elapsed = (now - datetime.fromisoformat(last)).total_seconds()
    except Exception:
        return True
    return elapsed >= mon["interval_sec"]


async def _tick():
    now = datetime.now(timezone.utc)
    for mon in db.list_monitors(enabled_only=True):
        if mon["id"] in _inflight or not _due(mon, now):
            continue
        _inflight.add(mon["id"])

        async def _run(m):
            try:
                await sample_once(m)
            finally:
                _inflight.discard(m["id"])

        asyncio.create_task(_run(mon))


async def scheduler():
    """Long-lived loop: every few seconds, fire any monitors that are due."""
    while True:
        try:
            await _tick()
        except Exception:
            pass
        await asyncio.sleep(5)
