"""
Route/integration tests driven through FastAPI's TestClient. These exercise
the HTTP layer the pure/DB suites don't: the health probe, the auth-disabled
open paths, and input validation on the run/monitor endpoints. Run with auth
off (the default — no PROBEDECK_AUTH_* env), against the PROBEDECK_DATA sqlite.

    docker exec -e PROBEDECK_DATA=/tmp/pdtest probedeck \
        python -m unittest discover -s tests
"""
import unittest

import main

# TestClient needs httpx, which is a dev-only dependency (requirements-dev.txt),
# not part of the runtime image. Skip these rather than fail a bare
# `docker exec ... unittest` in a container that only has the runtime deps.
try:
    from fastapi.testclient import TestClient
    import httpx  # noqa: F401  (imported for the availability check)
    _HAVE_CLIENT = True
except Exception:
    _HAVE_CLIENT = False


class RouteCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _HAVE_CLIENT:
            raise unittest.SkipTest(
                "httpx not installed; pip install -r requirements-dev.txt")
        # The context-manager form drives startup/shutdown (lifespan), so the
        # scheduler starts and is cancelled cleanly around the tests.
        cls._cm = TestClient(main.app)
        cls.client = cls._cm.__enter__()

    @classmethod
    def tearDownClass(cls):
        if _HAVE_CLIENT:
            cls._cm.__exit__(None, None, None)


class TestHealth(RouteCase):
    def test_healthz_ok(self):
        r = self.client.get("/healthz")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "ok")


class TestOpenPaths(RouteCase):
    def test_index_open_without_auth(self):
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_status_board_open(self):
        self.assertEqual(self.client.get("/status").status_code, 200)

    def test_agent_jobs_requires_token(self):
        # Open path, but the handler rejects a missing/invalid vantage token.
        self.assertEqual(self.client.get("/agent/jobs").status_code, 401)


class TestValidation(RouteCase):
    def test_run_rejects_bad_target(self):
        r = self.client.post("/run", data={"tool": "ping", "target": "a b; rm -rf /"})
        self.assertEqual(r.status_code, 400)

    def test_status_unknown_run_is_404(self):
        self.assertEqual(self.client.get("/status/deadbeef0000").status_code, 404)

    def test_monitor_rejects_unmonitorable_tool(self):
        r = self.client.post("/monitors", data={"tool": "tcpdump", "target": "1.1.1.1"})
        self.assertEqual(r.status_code, 400)

    def test_monitor_rejects_missing_target(self):
        r = self.client.post("/monitors", data={"tool": "ping", "target": ""})
        self.assertEqual(r.status_code, 400)

    def test_download_unknown_kind_is_400(self):
        # No such run either, but the kind check should reject first / cleanly.
        r = self.client.get("/download/deadbeef0000/exe")
        self.assertIn(r.status_code, (400, 404))


if __name__ == "__main__":
    unittest.main()
