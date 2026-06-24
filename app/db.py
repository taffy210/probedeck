import sqlite3
import os
from contextlib import contextmanager

DATA_DIR = os.environ.get("PROBEDECK_DATA", "/data")
DB_PATH = os.path.join(DATA_DIR, "probedeck.db")


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(os.path.join(DATA_DIR, "results"), exist_ok=True)
    with get_conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS runs (
                id          TEXT PRIMARY KEY,
                tool        TEXT NOT NULL,
                target      TEXT,
                args        TEXT,
                opts        TEXT,
                status      TEXT NOT NULL,
                exit_code   INTEGER,
                started_at  TEXT NOT NULL,
                finished_at TEXT,
                result_dir  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS profiles (
                id    INTEGER PRIMARY KEY AUTOINCREMENT,
                name  TEXT NOT NULL,
                kind  TEXT NOT NULL,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS monitors (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                label        TEXT NOT NULL,
                tool         TEXT NOT NULL,
                target       TEXT NOT NULL,
                opts         TEXT,
                interval_sec INTEGER NOT NULL,
                enabled      INTEGER NOT NULL DEFAULT 1,
                created_at   TEXT NOT NULL,
                last_run_at  TEXT
            );

            CREATE TABLE IF NOT EXISTS samples (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                monitor_id INTEGER NOT NULL,
                ts         TEXT NOT NULL,
                ok         INTEGER NOT NULL,
                value      REAL,
                unit       TEXT,
                loss       REAL
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                monitor_id  INTEGER NOT NULL,
                started_at  TEXT NOT NULL,
                resolved_at TEXT,
                reason      TEXT,
                peak        REAL,
                acked       INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS maintenance (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                monitor_id INTEGER,           -- NULL = applies to all monitors
                label      TEXT,
                kind       TEXT NOT NULL,      -- 'once' | 'daily'
                starts_at  TEXT NOT NULL,      -- ISO datetime (once) or 'HH:MM' (daily, UTC)
                ends_at    TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vantages (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL,
                location   TEXT,
                token      TEXT NOT NULL UNIQUE,
                enabled    INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_seen  TEXT
            );

            CREATE TABLE IF NOT EXISTS checks (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                tool       TEXT NOT NULL,
                target     TEXT NOT NULL,
                opts       TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS check_results (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                check_id    INTEGER NOT NULL,
                vantage_id  INTEGER,           -- NULL = central (this server)
                status      TEXT NOT NULL DEFAULT 'pending',
                ok          INTEGER,
                value       REAL,
                unit        TEXT,
                text        TEXT,
                reported_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_cr_check ON check_results(check_id);
            CREATE INDEX IF NOT EXISTS idx_cr_pend ON check_results(vantage_id, status);

            CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_samples_mon ON samples(monitor_id, ts);
            CREATE INDEX IF NOT EXISTS idx_inc_mon ON incidents(monitor_id, id DESC);
            """
        )
        # Migrate older DBs created before the opts column existed.
        cols = {r["name"] for r in c.execute("PRAGMA table_info(runs)")}
        if "opts" not in cols:
            c.execute("ALTER TABLE runs ADD COLUMN opts TEXT")
        # Alerting columns were added to monitors after the table shipped; add
        # any that are missing so old and new DBs converge on the same schema.
        mcols = {r["name"] for r in c.execute("PRAGMA table_info(monitors)")}
        for col, ddl in (
            ("warn_latency",    "ALTER TABLE monitors ADD COLUMN warn_latency REAL"),
            ("warn_floor",      "ALTER TABLE monitors ADD COLUMN warn_floor REAL"),
            ("warn_loss",       "ALTER TABLE monitors ADD COLUMN warn_loss REAL"),
            ("down_after",      "ALTER TABLE monitors ADD COLUMN down_after INTEGER DEFAULT 2"),
            ("webhook_url",     "ALTER TABLE monitors ADD COLUMN webhook_url TEXT"),
            ("notify",          "ALTER TABLE monitors ADD COLUMN notify INTEGER DEFAULT 1"),
            ("breach_streak",   "ALTER TABLE monitors ADD COLUMN breach_streak INTEGER DEFAULT 0"),
            ("open_incident_id","ALTER TABLE monitors ADD COLUMN open_incident_id INTEGER"),
            ("watch_drift",     "ALTER TABLE monitors ADD COLUMN watch_drift INTEGER DEFAULT 0"),
            ("last_fp",         "ALTER TABLE monitors ADD COLUMN last_fp TEXT"),
        ):
            if col not in mcols:
                c.execute(ddl)
        # incidents gained a free-text detail (used by drift events: old → new).
        icols = {r["name"] for r in c.execute("PRAGMA table_info(incidents)")}
        if "detail" not in icols:
            c.execute("ALTER TABLE incidents ADD COLUMN detail TEXT")


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def insert_run(run):
    with get_conn() as c:
        c.execute(
            """INSERT INTO runs
               (id, tool, target, args, opts, status, started_at, result_dir)
               VALUES (?,?,?,?,?,?,?,?)""",
            (run["id"], run["tool"], run["target"], run["args"], run.get("opts"),
             run["status"], run["started_at"], run["result_dir"]),
        )


def finish_run(run_id, status, exit_code, finished_at):
    with get_conn() as c:
        c.execute(
            "UPDATE runs SET status=?, exit_code=?, finished_at=? WHERE id=?",
            (status, exit_code, finished_at, run_id),
        )


def get_run(run_id):
    with get_conn() as c:
        row = c.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return dict(row) if row else None


def list_runs(tool=None, q=None, limit=100):
    sql = "SELECT * FROM runs"
    clauses, params = [], []
    if tool:
        clauses.append("tool=?")
        params.append(tool)
    if q:
        clauses.append("(target LIKE ? OR args LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%"])
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY started_at DESC LIMIT ?"
    params.append(limit)
    with get_conn() as c:
        return [dict(r) for r in c.execute(sql, params).fetchall()]


def delete_run(run_id):
    with get_conn() as c:
        c.execute("DELETE FROM runs WHERE id=?", (run_id,))


def clear_runs():
    """Wipe the run index. Caller removes the on-disk result directories
    (read their paths from the rows first)."""
    with get_conn() as c:
        c.execute("DELETE FROM runs")


def add_profile(name, kind, value):
    with get_conn() as c:
        c.execute("INSERT INTO profiles (name, kind, value) VALUES (?,?,?)",
                  (name, kind, value))


def list_profiles():
    with get_conn() as c:
        return [dict(r) for r in
                c.execute("SELECT * FROM profiles ORDER BY kind, name").fetchall()]


def delete_profile(profile_id):
    with get_conn() as c:
        c.execute("DELETE FROM profiles WHERE id=?", (profile_id,))


# --- monitors -------------------------------------------------------------

def add_monitor(label, tool, target, opts, interval_sec, created_at,
                warn_latency=None, warn_floor=None, warn_loss=None, down_after=2,
                webhook_url=None, notify=1, watch_drift=0):
    with get_conn() as c:
        cur = c.execute(
            """INSERT INTO monitors
               (label, tool, target, opts, interval_sec, enabled, created_at,
                warn_latency, warn_floor, warn_loss, down_after, webhook_url,
                notify, watch_drift)
               VALUES (?,?,?,?,?,1,?,?,?,?,?,?,?,?)""",
            (label, tool, target, opts, interval_sec, created_at,
             warn_latency, warn_floor, warn_loss, down_after, webhook_url,
             notify, watch_drift))
        return cur.lastrowid


def update_monitor_alerts(monitor_id, warn_latency, warn_floor, warn_loss,
                          down_after, webhook_url, notify, watch_drift):
    with get_conn() as c:
        c.execute(
            """UPDATE monitors SET warn_latency=?, warn_floor=?, warn_loss=?,
                                   down_after=?, webhook_url=?, notify=?,
                                   watch_drift=? WHERE id=?""",
            (warn_latency, warn_floor, warn_loss, down_after, webhook_url,
             notify, watch_drift, monitor_id))


def set_monitor_fp(monitor_id, fp):
    with get_conn() as c:
        c.execute("UPDATE monitors SET last_fp=? WHERE id=?", (fp, monitor_id))


def list_monitors(enabled_only=False):
    sql = "SELECT * FROM monitors"
    if enabled_only:
        sql += " WHERE enabled=1"
    sql += " ORDER BY id"
    with get_conn() as c:
        return [dict(r) for r in c.execute(sql).fetchall()]


def get_monitor(monitor_id):
    with get_conn() as c:
        row = c.execute("SELECT * FROM monitors WHERE id=?", (monitor_id,)).fetchone()
        return dict(row) if row else None


def set_monitor_enabled(monitor_id, enabled):
    with get_conn() as c:
        c.execute("UPDATE monitors SET enabled=? WHERE id=?",
                  (1 if enabled else 0, monitor_id))


def touch_monitor(monitor_id, when):
    with get_conn() as c:
        c.execute("UPDATE monitors SET last_run_at=? WHERE id=?", (when, monitor_id))


def delete_monitor(monitor_id):
    with get_conn() as c:
        c.execute("DELETE FROM samples WHERE monitor_id=?", (monitor_id,))
        c.execute("DELETE FROM incidents WHERE monitor_id=?", (monitor_id,))
        c.execute("DELETE FROM monitors WHERE id=?", (monitor_id,))


def add_sample(monitor_id, ts, ok, value, unit, loss):
    with get_conn() as c:
        c.execute(
            """INSERT INTO samples (monitor_id, ts, ok, value, unit, loss)
               VALUES (?,?,?,?,?,?)""",
            (monitor_id, ts, 1 if ok else 0, value, unit, loss))
        # Keep only the most recent 200 samples per monitor.
        c.execute(
            """DELETE FROM samples WHERE monitor_id=? AND id NOT IN
               (SELECT id FROM samples WHERE monitor_id=? ORDER BY id DESC LIMIT 200)""",
            (monitor_id, monitor_id))


def list_samples(monitor_id, limit=60):
    with get_conn() as c:
        rows = c.execute(
            "SELECT * FROM samples WHERE monitor_id=? ORDER BY id DESC LIMIT ?",
            (monitor_id, limit)).fetchall()
        return [dict(r) for r in reversed(rows)]


# --- alerting / incidents -------------------------------------------------

def set_alert_state(monitor_id, breach_streak, open_incident_id):
    with get_conn() as c:
        c.execute(
            "UPDATE monitors SET breach_streak=?, open_incident_id=? WHERE id=?",
            (breach_streak, open_incident_id, monitor_id))


def open_incident(monitor_id, started_at, reason, peak):
    with get_conn() as c:
        cur = c.execute(
            """INSERT INTO incidents (monitor_id, started_at, reason, peak)
               VALUES (?,?,?,?)""",
            (monitor_id, started_at, reason, peak))
        return cur.lastrowid


def update_incident(incident_id, peak):
    """Track the worst value seen during an open incident."""
    with get_conn() as c:
        c.execute(
            """UPDATE incidents SET peak=MAX(COALESCE(peak, ?), ?)
               WHERE id=?""",
            (peak, peak, incident_id))


def close_incident(incident_id, resolved_at):
    with get_conn() as c:
        c.execute("UPDATE incidents SET resolved_at=? WHERE id=?",
                  (resolved_at, incident_id))


def add_event_incident(monitor_id, when, reason, detail):
    """A point-in-time event (e.g. a drift): opens and resolves at the same
    instant so it lands in the incident log without lingering as 'ongoing'."""
    with get_conn() as c:
        cur = c.execute(
            """INSERT INTO incidents (monitor_id, started_at, resolved_at, reason, detail)
               VALUES (?,?,?,?,?)""",
            (monitor_id, when, when, reason, detail))
        return cur.lastrowid


def list_incidents(monitor_id=None, limit=50, open_only=False):
    sql = ("SELECT i.*, m.label AS monitor_label, m.tool AS monitor_tool "
           "FROM incidents i JOIN monitors m ON m.id = i.monitor_id")
    clauses, params = [], []
    if monitor_id is not None:
        clauses.append("i.monitor_id=?")
        params.append(monitor_id)
    if open_only:
        clauses.append("i.resolved_at IS NULL")
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY i.id DESC LIMIT ?"
    params.append(limit)
    with get_conn() as c:
        return [dict(r) for r in c.execute(sql, params).fetchall()]


def ack_incidents():
    """Mark every resolved incident acknowledged (clears notification badges)."""
    with get_conn() as c:
        c.execute("UPDATE incidents SET acked=1")


def sample_stats(monitor_id, limit=200):
    """Return (total, ok_count) over the retained sample window for uptime."""
    with get_conn() as c:
        row = c.execute(
            """SELECT COUNT(*) AS n, COALESCE(SUM(ok),0) AS ok FROM
               (SELECT ok FROM samples WHERE monitor_id=? ORDER BY id DESC LIMIT ?)""",
            (monitor_id, limit)).fetchone()
        return row["n"], row["ok"]


# --- maintenance windows --------------------------------------------------

def add_maintenance(monitor_id, label, kind, starts_at, ends_at, created_at):
    with get_conn() as c:
        cur = c.execute(
            """INSERT INTO maintenance
               (monitor_id, label, kind, starts_at, ends_at, created_at)
               VALUES (?,?,?,?,?,?)""",
            (monitor_id, label, kind, starts_at, ends_at, created_at))
        return cur.lastrowid


def list_maintenance():
    sql = ("SELECT w.*, m.label AS monitor_label FROM maintenance w "
           "LEFT JOIN monitors m ON m.id = w.monitor_id ORDER BY w.kind, w.starts_at")
    with get_conn() as c:
        return [dict(r) for r in c.execute(sql).fetchall()]


def delete_maintenance(window_id):
    with get_conn() as c:
        c.execute("DELETE FROM maintenance WHERE id=?", (window_id,))


# --- vantages & multi-vantage checks --------------------------------------

def add_vantage(name, location, token, created_at):
    with get_conn() as c:
        cur = c.execute(
            """INSERT INTO vantages (name, location, token, created_at)
               VALUES (?,?,?,?)""", (name, location, token, created_at))
        return cur.lastrowid


def list_vantages(enabled_only=False):
    sql = "SELECT * FROM vantages"
    if enabled_only:
        sql += " WHERE enabled=1"
    sql += " ORDER BY id"
    with get_conn() as c:
        return [dict(r) for r in c.execute(sql).fetchall()]


def get_vantage_by_token(token):
    if not token:
        return None
    with get_conn() as c:
        row = c.execute("SELECT * FROM vantages WHERE token=?", (token,)).fetchone()
        return dict(row) if row else None


def set_vantage_seen(vantage_id, when):
    with get_conn() as c:
        c.execute("UPDATE vantages SET last_seen=? WHERE id=?", (when, vantage_id))


def delete_vantage(vantage_id):
    with get_conn() as c:
        c.execute("DELETE FROM vantages WHERE id=?", (vantage_id,))


def add_check(tool, target, opts, created_at):
    with get_conn() as c:
        cur = c.execute(
            "INSERT INTO checks (tool, target, opts, created_at) VALUES (?,?,?,?)",
            (tool, target, opts, created_at))
        return cur.lastrowid


def prune_checks(keep=200):
    """Cap retained checks (and their results) so ad-hoc vantage runs don't
    grow the DB without bound."""
    with get_conn() as c:
        c.execute(
            """DELETE FROM check_results WHERE check_id IN
               (SELECT id FROM checks WHERE id NOT IN
                  (SELECT id FROM checks ORDER BY id DESC LIMIT ?))""", (keep,))
        c.execute(
            """DELETE FROM checks WHERE id NOT IN
               (SELECT id FROM checks ORDER BY id DESC LIMIT ?)""", (keep,))


def get_check(check_id):
    with get_conn() as c:
        row = c.execute("SELECT * FROM checks WHERE id=?", (check_id,)).fetchone()
        return dict(row) if row else None


def add_check_result(check_id, vantage_id, status, ok, value, unit, text, reported_at):
    with get_conn() as c:
        cur = c.execute(
            """INSERT INTO check_results
               (check_id, vantage_id, status, ok, value, unit, text, reported_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (check_id, vantage_id, status, ok, value, unit, text, reported_at))
        return cur.lastrowid


def get_check_result(result_id):
    with get_conn() as c:
        row = c.execute("SELECT * FROM check_results WHERE id=?", (result_id,)).fetchone()
        return dict(row) if row else None


def update_check_result(result_id, status, ok, value, unit, text, reported_at):
    with get_conn() as c:
        c.execute(
            """UPDATE check_results SET status=?, ok=?, value=?, unit=?, text=?,
                                        reported_at=? WHERE id=?""",
            (status, 1 if ok else (0 if ok is not None else None), value, unit,
             text, reported_at, result_id))


def list_check_results(check_id):
    """All results for a check with the vantage name/location joined in
    (central rows have a NULL vantage_id)."""
    sql = ("SELECT r.*, v.name AS vname, v.location AS vloc "
           "FROM check_results r LEFT JOIN vantages v ON v.id = r.vantage_id "
           "WHERE r.check_id=? ORDER BY (r.vantage_id IS NOT NULL), r.vantage_id")
    with get_conn() as c:
        return [dict(r) for r in c.execute(sql, (check_id,)).fetchall()]


def claim_agent_jobs(vantage_id, limit=10):
    """Hand pending results for this vantage to its agent, flipping them to
    'running' so a second poll won't re-issue the same work."""
    with get_conn() as c:
        rows = c.execute(
            """SELECT r.id, c.tool, c.target, c.opts
               FROM check_results r JOIN checks c ON c.id = r.check_id
               WHERE r.vantage_id=? AND r.status='pending'
               ORDER BY r.id LIMIT ?""",
            (vantage_id, limit)).fetchall()
        ids = [r["id"] for r in rows]
        for rid in ids:
            c.execute("UPDATE check_results SET status='running' WHERE id=?", (rid,))
        return [dict(r) for r in rows]
