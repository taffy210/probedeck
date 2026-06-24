import json
import os
import shutil

from fastapi import FastAPI, Request, Form, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import (HTMLResponse, FileResponse, PlainTextResponse,
                               RedirectResponse, Response, JSONResponse)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import asyncio

import auth
import db
import dnsprop
import monitor
import pathinsight
import runner
import summarize
import vantage
from tools import TOOLS, validate_target

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app):
    """Run the recurring-monitor scheduler for the lifetime of the app."""
    task = asyncio.create_task(monitor.scheduler())
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="ProbeDeck", lifespan=lifespan)
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

db.init_db()

PROFILE_KINDS = ["gateway", "iperf", "resolver", "host", "other"]
MONITOR_INTERVALS = [60, 300, 900, 1800, 3600]


def _spark(samples, w=170, h=34, pad=3):
    """Build SVG polyline points for a monitor's recent values, plus the
    value range for axis labels. Returns None when there's nothing to plot."""
    vals = [s["value"] for s in samples if s["value"] is not None]
    if not vals:
        return None
    lo, hi = min(vals), max(vals)
    span = (hi - lo) or 1.0
    step = (w - 2 * pad) / max(1, len(samples) - 1)
    pts = []
    for i, s in enumerate(samples):
        if s["value"] is None:
            continue
        x = pad + i * step
        y = pad + (h - 2 * pad) * (1 - (s["value"] - lo) / span)
        pts.append(f"{x:.1f},{y:.1f}")
    return {"points": " ".join(pts), "w": w, "h": h, "lo": lo, "hi": hi}


def _uptime(monitor_id):
    total, ok = db.sample_stats(monitor_id)
    return round(100.0 * ok / total, 1) if total else None


def _status_of(m, latest):
    """Tile colour: red if an incident is open, amber on a current breach or
    loss, green when healthy, grey when there's no data yet."""
    if m.get("open_incident_id"):
        return "down"
    if not latest:
        return "idle"
    if not latest["ok"]:
        return "down"
    if latest.get("loss"):
        return "warn"
    return "ok"


def _monitors_view():
    view = []
    for m in db.list_monitors():
        samples = db.list_samples(m["id"])
        latest = samples[-1] if samples else None
        unit = next((s["unit"] for s in reversed(samples) if s["unit"]), "")
        status = _status_of(m, latest)
        if monitor.in_maintenance(m["id"]):
            status = "maint"
        view.append({"m": m, "latest": latest, "n": len(samples),
                     "spark": _spark(samples), "unit": unit,
                     "uptime": _uptime(m["id"]), "status": status})
    return view


def _percentile(vals, pct):
    if not vals:
        return None
    s = sorted(vals)
    k = (len(s) - 1) * pct / 100.0
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def _chart(samples, w=620, h=160, pad=24):
    """Build a larger time-series chart for the detail view: a latency polyline
    plus per-sample loss bars, with p50/p95 reference stats."""
    vals = [s["value"] for s in samples if s["value"] is not None]
    if not vals:
        return None
    lo, hi = min(vals), max(vals)
    span = (hi - lo) or 1.0
    n = len(samples)
    step = (w - 2 * pad) / max(1, n - 1)
    line, bars = [], []
    for i, s in enumerate(samples):
        x = pad + i * step
        if s["value"] is not None:
            y = pad + (h - 2 * pad) * (1 - (s["value"] - lo) / span)
            line.append(f"{x:.1f},{y:.1f}")
        loss = s.get("loss") or 0
        if loss > 0:
            bh = (h - 2 * pad) * min(loss, 100) / 100.0
            bars.append({"x": x - 1.5, "y": h - pad - bh, "h": bh})
        if not s["ok"]:
            bars.append({"x": x - 1.5, "y": pad, "h": h - 2 * pad, "down": True})
    return {
        "w": w, "h": h, "pad": pad,
        "line": " ".join(line), "bars": bars,
        "lo": lo, "hi": hi,
        "p50": _percentile(vals, 50), "p95": _percentile(vals, 95),
    }


def _run_row(request, run, poll):
    """Render a console run row, attaching headline stats once it's finished."""
    summary = []
    if run and run["status"] != "running":
        path = os.path.join(run["result_dir"], "output.txt")
        if os.path.exists(path):
            with open(path, errors="replace") as f:
                summary = summarize.summarize(run["tool"], f.read())
    return templates.TemplateResponse(
        "_run_row.html",
        {"request": request, "run": run, "poll": poll,
         "tools": TOOLS, "summary": summary})


@app.middleware("http")
async def require_login(request: Request, call_next):
    """Gate every route behind a valid session cookie when auth is enabled.
    The login page and static assets (which style it) stay open; anything
    else redirects unauthenticated callers to /login. htmx requests get an
    HX-Redirect so the client navigates instead of swapping a login page
    into a fragment."""
    if auth.ENABLED:
        path = request.url.path
        # The public status board (labels + uptime only, no targets) and its
        # refresh fragment stay open even when login is enabled.
        # Agent API is authenticated by per-vantage token (checked in-handler),
        # not the login cookie, so it bypasses the redirect.
        is_open = (path in ("/login", "/status", "/statusbars", "/sw.js",
                            "/agent.py", "/agent/jobs", "/agent/results")
                   or path.startswith("/static"))
        if not is_open and not auth.valid_token(request.cookies.get(auth.COOKIE_NAME, "")):
            if request.headers.get("hx-request") == "true":
                resp = Response(status_code=401)
                resp.headers["HX-Redirect"] = "/login"
                return resp
            return RedirectResponse("/login", status_code=303)
    return await call_next(request)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if not auth.ENABLED or auth.valid_token(request.cookies.get(auth.COOKIE_NAME, "")):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "bad": False})


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request,
                       username: str = Form(...), password: str = Form(...)):
    if not auth.ENABLED:
        return RedirectResponse("/", status_code=303)
    if auth.check_credentials(username, password):
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(auth.COOKIE_NAME, auth.issue_token(),
                        max_age=auth.MAX_AGE, httponly=True, samesite="lax")
        return resp
    return templates.TemplateResponse("login.html", {"request": request, "bad": True},
                                      status_code=401)


@app.post("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(auth.COOKIE_NAME)
    return resp


@app.get("/sw.js")
async def service_worker():
    """Serve the worker from the root so its scope covers the whole app
    (a worker under /static could only control /static)."""
    return FileResponse(
        os.path.join("static", "sw.js"), media_type="application/javascript",
        headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"})


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "tools": TOOLS,
        "profiles": db.list_profiles(),
        "profile_kinds": PROFILE_KINDS,
        "auth_enabled": auth.ENABLED,
    })


@app.post("/run", response_class=HTMLResponse)
async def submit(request: Request):
    form = await request.form()
    tool = form.get("tool")
    target = form.get("target", "")

    # Two pseudo-tools don't map to a single argv: they fan out / post-process,
    # so they render their own console card instead of a pollable run row.
    if tool == "dnsprop":
        try:
            res = await dnsprop.check(target, form.get("rtype", "A"))
        except ValueError as e:
            return templates.TemplateResponse(
                "_error.html", {"request": request, "message": str(e)},
                status_code=400)
        return templates.TemplateResponse(
            "_dnsprop.html", {"request": request, "res": res})
    if tool == "path":
        try:
            res = await pathinsight.trace(target)
        except ValueError as e:
            return templates.TemplateResponse(
                "_error.html", {"request": request, "message": str(e)},
                status_code=400)
        return templates.TemplateResponse(
            "_path.html", {"request": request, "res": res})
    if tool == "vantage":
        vtool = form.get("vtool", "tcp")
        vopts = {k: form.get(k) for k in
                 ("port", "expect", "method", "servername", "count")
                 if form.get(k)}
        try:
            check_id = await vantage.new_check(vtool, target, vopts)
        except ValueError as e:
            return templates.TemplateResponse(
                "_error.html", {"request": request, "message": str(e)},
                status_code=400)
        return templates.TemplateResponse(
            "_vantage.html", {"request": request, "v": vantage.check_view(check_id)})

    opts = {k: v for k, v in form.items() if k not in ("tool", "target")}
    # cast checkbox-style values
    if "reverse" in opts:
        opts["reverse"] = opts["reverse"] in ("on", "true", "1")
    try:
        job_id = await runner.run_job(tool, target, opts)
    except ValueError as e:
        return templates.TemplateResponse("_error.html",
                                          {"request": request, "message": str(e)},
                                          status_code=400)
    run = db.get_run(job_id)
    return _run_row(request, run, poll=True)


@app.get("/status/{job_id}", response_class=HTMLResponse)
async def status(request: Request, job_id: str):
    run = db.get_run(job_id)
    if not run:
        raise HTTPException(404)
    poll = run["status"] == "running"
    return _run_row(request, run, poll=poll)


@app.get("/history", response_class=HTMLResponse)
async def history(request: Request, tool: str = "", q: str = ""):
    runs = db.list_runs(tool=tool or None, q=q or None)
    return templates.TemplateResponse("_history.html",
                                      {"request": request, "runs": runs, "tools": TOOLS})


@app.post("/history/clear", response_class=HTMLResponse)
async def clear_history(request: Request):
    # Remove each run's saved output directory, then drop the index rows.
    for run in db.list_runs(limit=1_000_000):
        d = run.get("result_dir")
        if d and os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)
    db.clear_runs()
    return templates.TemplateResponse("_history.html",
                                      {"request": request, "runs": [], "tools": TOOLS})


@app.post("/rerun/{job_id}", response_class=HTMLResponse)
async def rerun(request: Request, job_id: str):
    """Re-fire a past run with its original tool, target, and options. Runs a
    fresh job (re-validates the target, regenerates any pcap path) rather than
    replaying the old argv verbatim."""
    old = db.get_run(job_id)
    if not old:
        raise HTTPException(404)
    opts = json.loads(old.get("opts") or "{}")
    try:
        new_id = await runner.run_job(old["tool"], old["target"], opts)
    except ValueError as e:
        return templates.TemplateResponse("_error.html",
                                          {"request": request, "message": str(e)},
                                          status_code=400)
    run = db.get_run(new_id)
    return _run_row(request, run, poll=True)


@app.post("/runs/{job_id}/cancel", response_class=HTMLResponse)
async def cancel_run(request: Request, job_id: str):
    runner.cancel_job(job_id)
    run = db.get_run(job_id)
    if not run:
        raise HTTPException(404)
    poll = run["status"] == "running"
    return _run_row(request, run, poll=poll)


@app.post("/runs/{job_id}/delete", response_class=HTMLResponse)
async def delete_run(request: Request, job_id: str):
    run = db.get_run(job_id)
    if run:
        d = run.get("result_dir")
        if d and os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)
        db.delete_run(job_id)
    runs = db.list_runs()
    return templates.TemplateResponse("_history.html",
                                      {"request": request, "runs": runs, "tools": TOOLS})


@app.get("/compare", response_class=HTMLResponse)
async def compare(request: Request, a: str, b: str):
    """Render two finished runs side by side: headline stats plus full output."""
    cols = []
    for rid in (a, b):
        run = db.get_run(rid)
        if not run:
            raise HTTPException(404)
        text = ""
        path = os.path.join(run["result_dir"], "output.txt")
        if os.path.exists(path):
            with open(path, errors="replace") as f:
                text = f.read()
        cols.append({"run": run,
                     "summary": summarize.summarize(run["tool"], text),
                     "output": text})
    return templates.TemplateResponse("_compare.html",
                                      {"request": request, "cols": cols})


@app.get("/output/{job_id}", response_class=PlainTextResponse)
async def output(job_id: str):
    run = db.get_run(job_id)
    if not run:
        raise HTTPException(404)
    path = os.path.join(run["result_dir"], "output.txt")
    if not os.path.exists(path):
        return PlainTextResponse("(no output yet)")
    with open(path, "r", errors="replace") as f:
        return PlainTextResponse(f.read())


@app.get("/download/{job_id}/{kind}")
async def download(job_id: str, kind: str):
    run = db.get_run(job_id)
    if not run:
        raise HTTPException(404)
    names = {"txt": "output.txt", "json": "output.json", "pcap": "capture.pcap"}
    if kind not in names:
        raise HTTPException(400)
    path = os.path.join(run["result_dir"], names[kind])
    if not os.path.exists(path):
        raise HTTPException(404, "File not available for this run.")
    fname = f"{run['tool']}_{job_id}.{kind}"
    return FileResponse(path, filename=fname, media_type="application/octet-stream")


@app.post("/profiles", response_class=HTMLResponse)
async def add_profile(request: Request,
                      name: str = Form(...),
                      kind: str = Form(...),
                      value: str = Form(...)):
    db.add_profile(name.strip(), kind.strip(), value.strip())
    return templates.TemplateResponse("_profiles.html",
                                      {"request": request,
                                       "profiles": db.list_profiles()})


@app.post("/profiles/{profile_id}/delete", response_class=HTMLResponse)
async def remove_profile(request: Request, profile_id: int):
    db.delete_profile(profile_id)
    return templates.TemplateResponse("_profiles.html",
                                      {"request": request,
                                       "profiles": db.list_profiles()})


def _monitors_response(request):
    return templates.TemplateResponse(
        "_monitors.html", {"request": request, "monitors": _monitors_view()})


@app.get("/monitors", response_class=HTMLResponse)
async def monitors(request: Request):
    return _monitors_response(request)


@app.post("/monitors", response_class=HTMLResponse)
async def add_monitor(request: Request):
    form = await request.form()
    tool = form.get("tool", "")
    target = form.get("target", "").strip()
    if tool not in monitor.MONITORABLE:
        raise HTTPException(400, "This tool can't be monitored.")
    if not target:
        raise HTTPException(400, "A target is required.")
    try:
        target = validate_target(target)
    except ValueError as e:
        raise HTTPException(400, str(e))
    try:
        interval = int(form.get("interval", 300))
    except ValueError:
        interval = 300
    interval = max(30, min(interval, 86400))
    alert_keys = ("interval", "label", "warn_latency", "warn_floor", "warn_loss",
                  "down_after", "webhook_url", "notify", "notify_present", "watch_drift")
    opts = {k: v for k, v in form.items()
            if k not in ("tool", "target") and k not in alert_keys}
    if "reverse" in opts:
        opts["reverse"] = opts["reverse"] in ("on", "true", "1")
    wl, wf, wp, da, hook, notify, drift = _alert_fields(form)
    label = (form.get("label") or f"{tool} {target}").strip()
    db.add_monitor(label, tool, target, json.dumps(opts), interval,
                   runner._now(), warn_latency=wl, warn_floor=wf, warn_loss=wp,
                   down_after=da, webhook_url=hook, notify=notify, watch_drift=drift)
    return _monitors_response(request)


def _alert_fields(form):
    """Parse the alert-rule inputs shared by monitor create + edit."""
    def num(name):
        v = (form.get(name) or "").strip()
        try:
            return float(v) if v else None
        except ValueError:
            return None
    wl = num("warn_latency")
    wf = num("warn_floor")
    wp = num("warn_loss")
    try:
        da = max(1, int(form.get("down_after") or 2))
    except ValueError:
        da = 2
    hook = (form.get("webhook_url") or "").strip() or None
    if hook and not hook.startswith(("http://", "https://")):
        hook = None
    # The browser-notify checkbox only appears in the form when checked. A
    # hidden notify_present marker tells us the alert section was submitted at
    # all, so we can distinguish "unchecked" from "section not shown".
    if "notify_present" in form:
        notify = 1 if form.get("notify") in ("on", "true", "1") else 0
    else:
        notify = 1
    drift = 1 if form.get("watch_drift") in ("on", "true", "1") else 0
    return wl, wf, wp, da, hook, notify, drift


@app.post("/monitors/{monitor_id}/toggle", response_class=HTMLResponse)
async def toggle_monitor(request: Request, monitor_id: int):
    m = db.get_monitor(monitor_id)
    if m:
        db.set_monitor_enabled(monitor_id, not m["enabled"])
    return _monitors_response(request)


@app.post("/monitors/{monitor_id}/run", response_class=HTMLResponse)
async def run_monitor_now(request: Request, monitor_id: int):
    m = db.get_monitor(monitor_id)
    if m:
        await monitor.sample_once(m)
    return _monitors_response(request)


@app.post("/monitors/{monitor_id}/delete", response_class=HTMLResponse)
async def remove_monitor(request: Request, monitor_id: int):
    db.delete_monitor(monitor_id)
    return _monitors_response(request)


@app.post("/monitors/{monitor_id}/alerts")
async def edit_alerts(request: Request, monitor_id: int):
    m = db.get_monitor(monitor_id)
    if not m:
        raise HTTPException(404)
    form = await request.form()
    wl, wf, wp, da, hook, notify, drift = _alert_fields(form)
    db.update_monitor_alerts(monitor_id, wl, wf, wp, da, hook, notify, drift)
    return RedirectResponse(f"/monitors/{monitor_id}", status_code=303)


# --- dashboard / detail ---------------------------------------------------

def _fmt_duration(secs):
    secs = int(secs)
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60}s"
    return f"{secs // 3600}h {(secs % 3600) // 60}m"


def _incident_rows(rows):
    """Attach a human-readable duration to each incident (open ones run to now)."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    for r in rows:
        try:
            start = datetime.fromisoformat(r["started_at"])
            end = datetime.fromisoformat(r["resolved_at"]) if r["resolved_at"] else now
            r["duration"] = _fmt_duration((end - start).total_seconds())
        except Exception:
            r["duration"] = None
    return rows


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "monitors": _monitors_view(),
        "incidents": _incident_rows(db.list_incidents(limit=30)),
        "windows": db.list_maintenance(),
        "all_monitors": db.list_monitors(),
        "vantages": db.list_vantages(),
        "base_url": str(request.base_url).rstrip("/"),
        "auth_enabled": auth.ENABLED,
    })


@app.get("/dashboard/tiles", response_class=HTMLResponse)
async def dashboard_tiles(request: Request):
    return templates.TemplateResponse("_tiles.html", {
        "request": request, "monitors": _monitors_view()})


# --- public status board --------------------------------------------------

def _status_ticks(monitor_id, n=60):
    """Recent samples as colour states (oldest→newest) for the history bar."""
    ticks = []
    for s in db.list_samples(monitor_id, limit=n):
        if not s["ok"]:
            ticks.append("down")
        elif s.get("loss"):
            ticks.append("warn")
        else:
            ticks.append("ok")
    return ticks


def _status_view():
    """Public-facing view: labels, current state, uptime and history only —
    deliberately no targets, opts or hostnames."""
    rows, worst = [], "ok"
    rank = {"ok": 0, "idle": 0, "warn": 1, "down": 2}
    for v in _monitors_view():
        m = v["m"]
        if not m["enabled"]:
            continue
        st = v["status"]
        rows.append({"label": m["label"], "tool": m["tool"], "status": st,
                     "uptime": v["uptime"], "ticks": _status_ticks(m["id"]),
                     "latest": v["latest"], "unit": v["unit"]})
        if rank.get(st, 0) > rank.get(worst, 0):
            worst = st
    overall = {"ok": ("operational", "All systems operational"),
               "warn": ("degraded", "Degraded performance"),
               "down": ("outage", "Active outage")}[worst if rows else "ok"]
    return rows, overall


@app.get("/status", response_class=HTMLResponse)
async def status_board(request: Request):
    rows, overall = _status_view()
    return templates.TemplateResponse("status.html", {
        "request": request, "rows": rows, "overall": overall,
        "incidents": _incident_rows(db.list_incidents(limit=15))})


@app.get("/statusbars", response_class=HTMLResponse)
async def status_bars(request: Request):
    rows, overall = _status_view()
    return templates.TemplateResponse("_statusboard.html", {
        "request": request, "rows": rows, "overall": overall,
        "incidents": _incident_rows(db.list_incidents(limit=15))})


# --- maintenance windows --------------------------------------------------

def _norm_dt(s):
    """Normalise a datetime-local value to a tz-aware (UTC) ISO string."""
    from datetime import datetime, timezone
    s = (s or "").strip().replace(" ", "T")
    if not s:
        return None
    dt = None
    for cand in (s, s + ":00"):  # datetime-local may omit seconds on some browsers
        try:
            dt = datetime.fromisoformat(cand)
            break
        except ValueError:
            continue
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _maintenance_response(request):
    return templates.TemplateResponse("_maintenance.html", {
        "request": request, "windows": db.list_maintenance(),
        "monitors": db.list_monitors()})


@app.get("/maintenance", response_class=HTMLResponse)
async def maintenance_list(request: Request):
    return _maintenance_response(request)


@app.post("/maintenance", response_class=HTMLResponse)
async def add_maintenance(request: Request):
    form = await request.form()
    kind = form.get("kind", "once")
    scope = (form.get("monitor_id") or "").strip()
    monitor_id = int(scope) if scope.isdigit() else None
    label = (form.get("label") or "").strip() or "maintenance"
    if kind == "daily":
        starts, ends = (form.get("start_tod") or "").strip(), (form.get("end_tod") or "").strip()
        if not (starts and ends):
            raise HTTPException(400, "Daily windows need a start and end time.")
    else:
        kind = "once"
        starts, ends = _norm_dt(form.get("starts_at")), _norm_dt(form.get("ends_at"))
        if not (starts and ends):
            raise HTTPException(400, "One-off windows need a start and end datetime.")
    db.add_maintenance(monitor_id, label, kind, starts, ends, runner._now())
    return _maintenance_response(request)


@app.post("/maintenance/{window_id}/delete", response_class=HTMLResponse)
async def remove_maintenance(request: Request, window_id: int):
    db.delete_maintenance(window_id)
    return _maintenance_response(request)


# --- multi-vantage --------------------------------------------------------

@app.get("/checks/{check_id}", response_class=HTMLResponse)
async def check_poll(request: Request, check_id: int):
    v = vantage.check_view(check_id)
    if not v:
        raise HTTPException(404)
    return templates.TemplateResponse("_vantage.html", {"request": request, "v": v})


def _vantages_response(request):
    return templates.TemplateResponse("_vantages.html", {
        "request": request, "vantages": db.list_vantages(),
        "base_url": str(request.base_url).rstrip("/")})


@app.get("/vantages", response_class=HTMLResponse)
async def vantages_list(request: Request):
    return _vantages_response(request)


@app.post("/vantages", response_class=HTMLResponse)
async def add_vantage(request: Request):
    form = await request.form()
    name = (form.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "A vantage name is required.")
    location = (form.get("location") or "").strip()
    db.add_vantage(name, location, vantage.new_token(), runner._now())
    return _vantages_response(request)


@app.post("/vantages/{vantage_id}/delete", response_class=HTMLResponse)
async def remove_vantage(request: Request, vantage_id: int):
    db.delete_vantage(vantage_id)
    return _vantages_response(request)


def _agent_vantage(request, token):
    v = db.get_vantage_by_token(token)
    if not v or not v["enabled"]:
        raise HTTPException(401, "Invalid or disabled vantage token.")
    return v


@app.get("/agent/jobs")
async def agent_jobs(request: Request, token: str = ""):
    v = _agent_vantage(request, token)
    return JSONResponse({"jobs": vantage.agent_jobs(v)})


@app.post("/agent/results")
async def agent_results(request: Request):
    body = await request.json()
    v = _agent_vantage(request, (body.get("token") or "").strip())
    ok = vantage.agent_report(v, body.get("result_id"), body.get("text") or "")
    return JSONResponse({"ok": bool(ok)})


@app.get("/agent.py")
async def agent_script():
    return FileResponse(os.path.join("static", "agent.py"),
                        media_type="text/x-python",
                        headers={"Content-Disposition": "inline; filename=agent.py"})


@app.get("/monitors/{monitor_id}", response_class=HTMLResponse)
async def monitor_detail(request: Request, monitor_id: int):
    m = db.get_monitor(monitor_id)
    if not m:
        raise HTTPException(404)
    samples = db.list_samples(monitor_id, limit=200)
    latest = samples[-1] if samples else None
    unit = next((s["unit"] for s in reversed(samples) if s["unit"]), "")
    return templates.TemplateResponse("monitor_detail.html", {
        "request": request, "m": m, "samples": samples,
        "latest": latest, "unit": unit,
        "uptime": _uptime(monitor_id),
        "status": _status_of(m, latest),
        "chart": _chart(samples),
        "incidents": _incident_rows(db.list_incidents(monitor_id=monitor_id, limit=50)),
        "intervals": MONITOR_INTERVALS,
        "auth_enabled": auth.ENABLED,
    })


# --- incidents (browser-notification feed) --------------------------------

@app.get("/incidents")
async def incidents_feed():
    """Compact JSON of recent incidents so the client can fire browser
    notifications on new open/close transitions."""
    rows = db.list_incidents(limit=40)
    out = [{
        "id": r["id"], "monitor_id": r["monitor_id"],
        "label": r["monitor_label"], "reason": r["reason"],
        "peak": r["peak"], "started_at": r["started_at"],
        "resolved_at": r["resolved_at"], "detail": r["detail"],
    } for r in rows]
    return JSONResponse({"incidents": out,
                         "open": sum(1 for r in out if not r["resolved_at"])})


@app.post("/incidents/ack")
async def incidents_ack():
    db.ack_incidents()
    return JSONResponse({"ok": True})


# --- websocket live output ------------------------------------------------

@app.websocket("/ws/output/{job_id}")
async def ws_output(ws: WebSocket, job_id: str):
    """Stream a run's output.txt as it grows, then a final control frame so the
    client can swap in the finished row. Replaces the 2s per-row polling."""
    if auth.ENABLED and not auth.valid_token(ws.cookies.get(auth.COOKIE_NAME, "")):
        await ws.close(code=1008)
        return
    await ws.accept()
    run = db.get_run(job_id)
    if not run:
        await ws.send_json({"type": "done", "status": "error"})
        await ws.close()
        return
    path = os.path.join(run["result_dir"], "output.txt")
    pos = 0
    try:
        while True:
            if os.path.exists(path):
                with open(path, "r", errors="replace") as f:
                    f.seek(pos)
                    chunk = f.read()
                    pos = f.tell()
                if chunk:
                    await ws.send_json({"type": "chunk", "data": chunk})
            cur = db.get_run(job_id)
            if not cur or cur["status"] != "running":
                # one last drain in case output landed between read and status
                if os.path.exists(path):
                    with open(path, "r", errors="replace") as f:
                        f.seek(pos)
                        tail = f.read()
                    if tail:
                        await ws.send_json({"type": "chunk", "data": tail})
                await ws.send_json({"type": "done",
                                    "status": cur["status"] if cur else "error"})
                break
            await asyncio.sleep(0.4)
    except WebSocketDisconnect:
        return
    except Exception:
        pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
