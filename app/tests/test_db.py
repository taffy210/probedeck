"""
DB-backed tests: incident lifecycle, maintenance-window evaluation, and the
multi-vantage check view. Uses the PROBEDECK_DATA sqlite db (point it at a
temp dir when running). Each test isolates itself by clearing tables.
"""
import unittest
from datetime import datetime, timezone

import db
import monitor
import vantage


def _now():
    return datetime.now(timezone.utc).isoformat()


class DBCase(unittest.TestCase):
    def setUp(self):
        db.init_db()
        with db.get_conn() as c:
            for t in ("monitors", "incidents", "maintenance",
                      "vantages", "checks", "check_results", "samples"):
                c.execute(f"DELETE FROM {t}")


class TestIncidents(DBCase):
    def test_open_update_close(self):
        mid = db.add_monitor("m", "ping", "1.1.1.1", "{}", 60, _now())
        iid = db.open_incident(mid, _now(), "down", 12.0)
        db.update_incident(iid, 30.0)  # higher peak should win
        db.update_incident(iid, 5.0)   # lower peak should not lower it
        rows = db.list_incidents(monitor_id=mid)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["peak"], 30.0)
        self.assertIsNone(rows[0]["resolved_at"])
        db.close_incident(iid, _now())
        self.assertIsNotNone(db.list_incidents(monitor_id=mid)[0]["resolved_at"])

    def test_event_incident_is_resolved_immediately(self):
        mid = db.add_monitor("m", "dig", "example.com", "{}", 60, _now())
        db.add_event_incident(mid, _now(), "drift", "a -> b")
        row = db.list_incidents(monitor_id=mid)[0]
        self.assertEqual(row["reason"], "drift")
        self.assertEqual(row["detail"], "a -> b")
        self.assertEqual(row["started_at"], row["resolved_at"])

    def test_sample_stats_and_uptime(self):
        mid = db.add_monitor("m", "ping", "1.1.1.1", "{}", 60, _now())
        for ok in (1, 1, 0, 1):
            db.add_sample(mid, _now(), ok, 1.0, "ms", 0)
        total, okc = db.sample_stats(mid)
        self.assertEqual((total, okc), (4, 3))


class TestMaintenance(DBCase):
    def test_daily_window_all_monitors(self):
        db.add_maintenance(None, "all", "daily", "00:00", "23:59", _now())
        self.assertTrue(monitor.in_maintenance(1))
        self.assertTrue(monitor.in_maintenance(999))

    def test_scoped_window(self):
        db.add_maintenance(2, "just-2", "daily", "00:00", "23:59", _now())
        self.assertFalse(monitor.in_maintenance(1))
        self.assertTrue(monitor.in_maintenance(2))

    def test_no_window(self):
        self.assertFalse(monitor.in_maintenance(1))

    def test_once_window_in_and_out(self):
        now = datetime.now(timezone.utc)
        past = now.replace(year=now.year - 1).isoformat()
        future = now.replace(year=now.year + 1).isoformat()
        db.add_maintenance(None, "active", "once", past, future, _now())
        self.assertTrue(monitor.in_maintenance(1))
        with db.get_conn() as c:
            c.execute("DELETE FROM maintenance")
        db.add_maintenance(None, "stale", "once", past, past, _now())
        self.assertFalse(monitor.in_maintenance(1))


class TestVantageView(DBCase):
    def test_check_view_counts(self):
        cid = db.add_check("tcp", "github.com", "{}", _now())
        # central reachable
        db.add_check_result(cid, None, "done", True, 3.2, "ms", "ok", _now())
        # one remote vantage, still pending
        vid = db.add_vantage("london", "uk", "tok-1", _now())
        db.add_check_result(cid, vid, "pending", None, None, None, None, None)
        v = vantage.check_view(cid)
        self.assertEqual(v["total"], 2)
        self.assertEqual(v["reachable"], 1)
        self.assertEqual(v["pending"], 1)
        names = [r["name"] for r in v["rows"]]
        self.assertIn("central (this server)", names)
        self.assertIn("london", names)

    def test_agent_claim_flips_to_running(self):
        cid = db.add_check("tcp", "h", '{"port": "443"}', _now())
        vid = db.add_vantage("v", "", "tok-2", _now())
        rid = db.add_check_result(cid, vid, "pending", None, None, None, None, None)
        jobs = db.claim_agent_jobs(vid)
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["id"], rid)
        # a second claim returns nothing (already running)
        self.assertEqual(db.claim_agent_jobs(vid), [])
        self.assertEqual(db.get_check_result(rid)["status"], "running")

    def test_token_lookup(self):
        db.add_vantage("v", "", "secret-tok", _now())
        self.assertIsNotNone(db.get_vantage_by_token("secret-tok"))
        self.assertIsNone(db.get_vantage_by_token("nope"))
        self.assertIsNone(db.get_vantage_by_token(""))


if __name__ == "__main__":
    unittest.main()
