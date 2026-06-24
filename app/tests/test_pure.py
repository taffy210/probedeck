"""
Pure-logic tests (no DB, no network): output parsers, metric extraction,
fingerprinting, alert evaluation, target validation, path parsing, and the
small math helpers in main. Run in-container:

    docker exec -e PROBEDECK_DATA=/tmp/pdtest probedeck \
        python -m unittest discover -s tests
"""
import unittest

import summarize
import monitor
import tools
import pathinsight
import probes


PING_OUT = """PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=59 time=12.3 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=59 time=11.1 ms
64 bytes from 1.1.1.1: icmp_seq=3 ttl=59 time=13.5 ms

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 11.1/12.3/13.5/0.800 ms
"""

MTR_JSON = ('{"report":{"hubs":['
            '{"count":1,"host":"a","Loss%":0,"Avg":1.2},'
            '{"count":2,"host":"b","Loss%":5,"Avg":10.5}]}}')

IPERF_JSON = ('{"end":{"sum_sent":{"bits_per_second":100000000,"retransmits":3},'
              '"sum_received":{"bits_per_second":95000000}}}')

CURL_OUT = "dns=0.010s connect=0.020s tls=0.050s ttfb=0.100s total=0.200s code=200\n"

TCP_OUT = "TCP connect to h:443\nstate: open\nconnect: 12.3 ms\n"
TCP_CLOSED = "TCP connect to h:9\nstate: closed\nerror: TimeoutError: \n"

TLS_OUT = ("TLS certificate for h:443\nsubject: h\nissuer: Some CA\n"
           "serial: ABC123\nexpires: 2026-09-01 00:00:00 UTC\ndays left: 68.4\n")
TLS_FAIL = "TLS certificate for h:443\nstate: handshake failed\nerror: x\n"

HTTP_OK = "HTTP GET https://h\nstatus: 200 OK\ntime: 70 ms\nexpected: 2xx/3xx\nresult: ok\n"
HTTP_BAD = "HTTP GET https://h\nstatus: 500 Server Error\ntime: 70 ms\nexpected: 2xx/3xx\nresult: mismatch\n"

DNS_OUT = "DNS resolution for h\naddresses: 1.2.3.4, 5.6.7.8\nresolve: 11.1 ms\n"
DIG_OUT = ("example.com.\t\t300\tIN\tA\t104.20.23.154\n"
           "example.com.\t\t300\tIN\tA\t172.66.147.243\n"
           ";; Query time: 12 msec\n")


class TestSummarize(unittest.TestCase):
    def test_ping(self):
        d = dict(summarize.summarize("ping", PING_OUT))
        self.assertEqual(d["loss"], "0%")
        self.assertEqual(d["recv"], "3/3")
        self.assertEqual(d["avg rtt"], "12.3 ms")

    def test_mtr(self):
        d = dict(summarize.summarize("mtr", MTR_JSON))
        self.assertEqual(d["hops"], "2")
        self.assertEqual(d["dest avg"], "10.5 ms")
        self.assertEqual(d["worst loss"], "5%")

    def test_iperf3(self):
        d = dict(summarize.summarize("iperf3", IPERF_JSON))
        self.assertEqual(d["recv"], "95.0 Mbit/s")
        self.assertEqual(d["retransmits"], "3")

    def test_curl(self):
        d = dict(summarize.summarize("curl", CURL_OUT))
        self.assertEqual(d["total"], "200 ms")
        self.assertEqual(d["http"], "200")

    def test_native(self):
        self.assertEqual(dict(summarize.summarize("tcp", TCP_OUT))["state"], "open")
        self.assertEqual(dict(summarize.summarize("tlscert", TLS_OUT))["days left"], "68.4")
        self.assertEqual(dict(summarize.summarize("http", HTTP_OK))["result"], "ok")
        self.assertIn("1.2.3.4", dict(summarize.summarize("dns", DNS_OUT))["addresses"])

    def test_unknown_and_empty(self):
        self.assertEqual(summarize.summarize("nope", "x"), [])
        self.assertEqual(summarize.summarize("ping", ""), [])


class TestMetric(unittest.TestCase):
    def test_latency_tools(self):
        self.assertEqual(monitor.metric_for("ping", PING_OUT), (True, 12.3, "ms", 0.0))
        ok, v, u, _ = monitor.metric_for("curl", CURL_OUT)
        self.assertTrue(ok); self.assertEqual(u, "ms"); self.assertAlmostEqual(v, 200, 0)

    def test_tcp(self):
        self.assertEqual(monitor.metric_for("tcp", TCP_OUT)[0], True)
        self.assertEqual(monitor.metric_for("tcp", TCP_CLOSED), (False, None, "ms", None))

    def test_tls_and_http(self):
        ok, v, u, _ = monitor.metric_for("tlscert", TLS_OUT)
        self.assertTrue(ok); self.assertEqual(u, "days"); self.assertAlmostEqual(v, 68.4, 1)
        self.assertFalse(monitor.metric_for("tlscert", TLS_FAIL)[0])
        self.assertTrue(monitor.metric_for("http", HTTP_OK)[0])
        self.assertFalse(monitor.metric_for("http", HTTP_BAD)[0])

    def test_dns_and_dig(self):
        ok, v, u, _ = monitor.metric_for("dns", DNS_OUT)
        self.assertTrue(ok); self.assertEqual(u, "ms")
        self.assertTrue(monitor.metric_for("dig", DIG_OUT)[0])


class TestFingerprint(unittest.TestCase):
    def test_dig_sorted_set(self):
        fp = monitor.fingerprint_for("dig", DIG_OUT)
        self.assertEqual(fp, "104.20.23.154 | 172.66.147.243")

    def test_tls_serial(self):
        self.assertEqual(monitor.fingerprint_for("tlscert", TLS_OUT), "serial:ABC123")

    def test_none_for_unsupported(self):
        self.assertIsNone(monitor.fingerprint_for("ping", PING_OUT))
        self.assertIsNone(monitor.fingerprint_for("dig", ""))


class TestEvaluate(unittest.TestCase):
    def test_thresholds(self):
        self.assertEqual(monitor._evaluate({"warn_latency": 10}, True, 20, None),
                         (True, "high", 20))
        self.assertEqual(monitor._evaluate({"warn_floor": 10}, True, 5, None),
                         (True, "low", 5))
        self.assertEqual(monitor._evaluate({"warn_loss": 1}, True, 5, 5)[:2],
                         (True, "loss"))
        self.assertEqual(monitor._evaluate({}, False, None, None)[:2], (True, "down"))
        self.assertEqual(monitor._evaluate({"warn_latency": 100}, True, 20, 0)[0], False)


class TestValidateTarget(unittest.TestCase):
    def test_accepts(self):
        for t in ("example.com", "1.2.3.4", "a-b.example.org",
                  "10.0.0.0/8", "2001:db8::1", "https://example.com"):
            self.assertEqual(tools.validate_target(t), t)

    def test_rejects(self):
        for t in ("evil;rm -rf /", "a b", "", ">x", "$(whoami)", "a|b", "`x`"):
            with self.assertRaises(ValueError):
                tools.validate_target(t)

    def test_extra_args_block_metachars(self):
        self.assertEqual(tools._split_extra("-sV -p 22"), ["-sV", "-p", "22"])
        with self.assertRaises(ValueError):
            tools._split_extra("-x; rm")


class TestPathInsight(unittest.TestCase):
    def test_parse_hops(self):
        text = " 1  192.168.1.1  1.234 ms\n 2  * * *\n 3  10.0.0.1  5.6 ms\n"
        hops = pathinsight._parse_hops(text)
        self.assertEqual(hops[0]["ip"], "192.168.1.1")
        self.assertEqual(hops[0]["rtt"], "1.234")
        self.assertTrue(hops[1]["timeout"])
        self.assertEqual(hops[2]["ip"], "10.0.0.1")

    def test_is_global(self):
        self.assertTrue(pathinsight._is_global("8.8.8.8"))
        self.assertFalse(pathinsight._is_global("192.168.1.1"))
        self.assertFalse(pathinsight._is_global("not-an-ip"))


class TestProbeHelpers(unittest.TestCase):
    def test_port_validation(self):
        self.assertEqual(probes._port({"port": "8443"}, 443), 8443)
        self.assertEqual(probes._port({}, 443), 443)
        with self.assertRaises(ValueError):
            probes._port({"port": "99999"}, 443)

    def test_cn_extraction(self):
        subject = ((("commonName", "example.com"),), (("organizationName", "Acme"),))
        self.assertIn("example.com", probes._cn(subject))


class TestMainHelpers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import main  # triggers db.init_db() against PROBEDECK_DATA
        cls.main = main

    def test_percentile(self):
        self.assertEqual(self.main._percentile([1, 2, 3, 4], 50), 2.5)
        self.assertEqual(self.main._percentile([10], 95), 10)
        self.assertIsNone(self.main._percentile([], 50))

    def test_fmt_duration(self):
        self.assertEqual(self.main._fmt_duration(45), "45s")
        self.assertEqual(self.main._fmt_duration(90), "1m 30s")
        self.assertEqual(self.main._fmt_duration(3700), "1h 1m")

    def test_spark(self):
        self.assertIsNone(self.main._spark([{"value": None}]))
        s = self.main._spark([{"value": 1}, {"value": 3}, {"value": 2}])
        self.assertEqual(s["lo"], 1)
        self.assertEqual(s["hi"], 3)
        self.assertIn(",", s["points"])

    def test_status_of(self):
        self.assertEqual(self.main._status_of({"open_incident_id": 1}, None), "down")
        self.assertEqual(self.main._status_of({}, None), "idle")
        self.assertEqual(self.main._status_of({}, {"ok": 1, "loss": 0}), "ok")
        self.assertEqual(self.main._status_of({}, {"ok": 0, "loss": None}), "down")
        self.assertEqual(self.main._status_of({}, {"ok": 1, "loss": 5}), "warn")


if __name__ == "__main__":
    unittest.main()
