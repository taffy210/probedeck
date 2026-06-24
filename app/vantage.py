"""
Multi-vantage probing. A *check* runs the same probe from several places at
once — this server ("central") plus any registered remote agents — so you can
tell "down for everyone" from "down from here".

Pull model: agents poll /agent/jobs with their token, run the probe locally,
and POST the result back. Agents only ever run a fixed, root-free, shell-free
probe set (TCP / HTTP / TLS); they never execute server-supplied commands, and
the target is allowlist-validated here before it's ever handed out.
"""
import json
import secrets
from datetime import datetime, timezone

import db
import probes
from monitor import metric_for
from tools import validate_target

# The probe types a vantage check supports. All are pure-stdlib and need no
# elevated privileges, so an agent runs anywhere a Python interpreter does.
VANTAGE_TOOLS = {
    "tcp": probes.tcp_probe,
    "http": probes.http_probe,
    "tlscert": probes.tls_probe,
    "ping": probes.ping_probe,
    "dns": probes.dns_probe,
}


def _now():
    return datetime.now(timezone.utc).isoformat()


def new_token():
    return secrets.token_urlsafe(24)


def _metric(tool, text):
    ok, value, unit, _loss = metric_for(tool, text)
    return ok, value, unit


async def new_check(tool, target, opts):
    """Create a check, run the central vantage inline, and queue a pending
    result for every enabled remote vantage."""
    if tool not in VANTAGE_TOOLS:
        raise ValueError("Unsupported vantage probe.")
    target = validate_target(target)
    db.prune_checks()
    check_id = db.add_check(tool, target, json.dumps(opts), _now())

    # Central vantage (this server) runs immediately.
    try:
        text = await VANTAGE_TOOLS[tool](target, opts)
        ok, value, unit = _metric(tool, text)
    except Exception as e:
        text, ok, value, unit = f"central error: {e}", False, None, None
    db.add_check_result(check_id, None, "done", ok, value, unit, text, _now())

    # Remote vantages get a pending slot their agent will pick up.
    for v in db.list_vantages(enabled_only=True):
        db.add_check_result(check_id, v["id"], "pending", None, None, None, None, None)

    return check_id


def agent_jobs(vantage):
    """Return (and claim) the pending probe jobs for a vantage's agent."""
    db.set_vantage_seen(vantage["id"], _now())
    jobs = []
    for r in db.claim_agent_jobs(vantage["id"]):
        jobs.append({"result_id": r["id"], "tool": r["tool"],
                     "target": r["target"], "opts": json.loads(r["opts"] or "{}")})
    return jobs


def agent_report(vantage, result_id, text):
    """Store an agent's reported output against its claimed result."""
    r = db.get_check_result(result_id)
    if not r or r["vantage_id"] != vantage["id"]:
        return False
    chk = db.get_check(r["check_id"])
    if not chk:
        return False
    ok, value, unit = _metric(chk["tool"], text or "")
    db.update_check_result(result_id, "done", ok, value, unit, text, _now())
    return True


def check_view(check_id):
    """Assemble a check + its per-vantage results for rendering. Marks results
    still outstanding after a grace period as 'no response' so the card can
    stop polling instead of spinning forever on a dead agent."""
    chk = db.get_check(check_id)
    if not chk:
        return None
    results = db.list_check_results(check_id)
    age = 0
    try:
        age = (datetime.now(timezone.utc)
               - datetime.fromisoformat(chk["created_at"])).total_seconds()
    except Exception:
        pass
    rows, pending = [], 0
    for r in results:
        status = r["status"]
        if status in ("pending", "running"):
            if age > 45:
                status = "noresponse"
            else:
                pending += 1
        rows.append({
            "name": "central (this server)" if r["vantage_id"] is None else r["vname"],
            "loc": "" if r["vantage_id"] is None else (r["vloc"] or ""),
            "central": r["vantage_id"] is None,
            "status": status, "ok": r["ok"], "value": r["value"], "unit": r["unit"],
        })
    reachable = sum(1 for r in rows if r["ok"])
    answered = sum(1 for r in rows if r["status"] == "done")
    return {"check": chk, "rows": rows, "pending": pending,
            "reachable": reachable, "answered": answered, "total": len(rows)}
