import csv
import importlib.util
import io
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest


HAPROXY_DIR = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("jpe_upload_guard", HAPROXY_DIR / "jpe_upload_guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
IP = guard.ip_key("192.0.2.1")
ARGS = SimpleNamespace(
    counter_table="bk_jpe_upload_stats", mark_table="bk_jpe_upload_marks",
    frontend="reality_in", backend="bk_trojan_jpe",
)
PROFILE_SNIS = {
    "trojan-jpe": "jp-east-stream.ssw-servers.com",
    "naive-jpe": "jp-east.sswnat.com",
    "trojan-sg": "sg.ssw-servers.com",
    "naive-sg": "sg.sswnat.com",
}


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "state.sqlite3"
        self.ledger = guard.Ledger(self.path, window=30, threshold=1000, hold=100, interval=10)

    def tearDown(self):
        self.ledger.close()
        self.directory.cleanup()

    def sample(self, now, uploaded, epoch="1"):
        return self.ledger.advance({IP: uploaded}, epoch, now)

    def test_uploads_across_connections_accumulate_to_threshold(self):
        self.sample(0, 0)
        self.sample(10, 600)
        active, created, _ = self.sample(20, 1000)
        self.assertEqual(created, {IP: 1000})
        self.assertEqual(active[IP], 120)

    def test_old_uploads_leave_the_rolling_window(self):
        self.sample(0, 0)
        self.sample(10, 600)
        self.sample(20, 600)
        self.sample(30, 600)
        active, created, _ = self.sample(40, 1000)
        self.assertFalse(active)
        self.assertFalse(created)
        self.assertEqual(self.ledger.db.execute("SELECT SUM(bytes) FROM samples").fetchone()[0], 400)

    def test_existing_lifetime_counter_is_not_treated_as_recent_upload(self):
        self.assertFalse(self.sample(0, 100000000000)[1])
        self.assertFalse(self.sample(10, 100000000001)[1])

    def test_new_ip_upload_before_its_first_poll_is_counted(self):
        self.ledger.advance({}, "1", 0)
        self.assertEqual(self.sample(10, 1000)[1], {IP: 1000})

    def test_new_ip_after_long_sampling_gap_uses_a_fresh_baseline(self):
        self.ledger.advance({}, "1", 0)
        self.assertFalse(self.sample(100, 1000000)[1])

    def test_hold_does_not_extend_and_quota_restarts_after_expiry(self):
        self.sample(0, 0)
        self.sample(10, 1000)
        active, _, _ = self.sample(20, 9000)
        self.assertEqual(active[IP], 110)
        active, created, expired = self.sample(110, 10000)
        self.assertFalse(active)
        self.assertFalse(created)
        self.assertEqual(expired, {IP})
        self.assertFalse(self.sample(120, 10999)[1])
        self.assertEqual(self.sample(130, 11000)[1], {IP: 1000})

    def test_haproxy_counter_reset_preserves_known_window_history(self):
        self.sample(0, 0)
        self.sample(10, 600)
        self.assertEqual(self.sample(20, 400, epoch="2")[1], {IP: 1000})

    def test_restart_preserves_baseline_history_and_deadline(self):
        self.sample(0, 0)
        self.sample(10, 600)
        self.ledger.close()
        self.ledger = guard.Ledger(self.path, window=30, threshold=1000, hold=100, interval=10)
        self.assertEqual(self.sample(20, 1000)[0][IP], 120)
        self.ledger.close()
        self.ledger = guard.Ledger(self.path, window=30, threshold=1000, hold=100, interval=10)
        self.assertEqual(self.sample(30, 2000)[0][IP], 120)

    def test_long_sampling_gap_does_not_assign_unknown_history_to_current_window(self):
        self.sample(0, 0)
        self.assertFalse(self.sample(100, 1000000)[1])

    def test_manual_release_resets_the_baseline(self):
        self.sample(0, 0)
        self.sample(10, 1000)
        self.ledger.release(IP)
        active, created, expired = self.sample(20, 1000000)
        self.assertFalse(active)
        self.assertFalse(created)
        self.assertEqual(expired, {IP})


class FakeAPI:
    def __init__(self):
        self.counters, self.marks, self.calls = {IP: 0}, {}, []
        self.fail_mark = False

    def table(self, name, field, values):
        rows = ["# table: %s, type: ipv6, size:102400, used:%d" % (name, len(values))]
        rows += ["0x123: key=%s use=0 exp=100 %s=%d" % (ip, field, value) for ip, value in values.items()]
        return "\n".join(rows)

    def command(self, command):
        self.calls.append(command)
        if command == "show info":
            return "Pid: 123\nVersion: 2.8.0"
        if command == "show table " + ARGS.counter_table:
            return self.table(ARGS.counter_table, "bytes_in_cnt", self.counters)
        if command.startswith("show table " + ARGS.mark_table):
            return self.table(ARGS.mark_table, "gpc0", self.marks)
        if command.startswith("set table "):
            if self.fail_mark:
                return "Permission denied"
            self.marks[command.split()[4]] = 1
            return ""
        if command.startswith("clear table "):
            self.marks.pop(command.split()[4], None)
            return ""
        if command == "show sess":
            return "\n".join([
                "0x1: proto=tcpv4 src=192.0.2.1:5000 fe=reality_in be=bk_trojan_jpe srv=server1",
                "0x2: proto=tcpv4 src=192.0.2.2:5001 fe=reality_in be=bk_trojan_jpe srv=server1",
                "0x3: proto=tcpv4 src=192.0.2.1:5002 fe=reality_in be=bk_trojan_sg srv=server1",
                "0x4: proto=tcpv4 src=192.0.2.1:5003 fe=other be=bk_trojan_jpe srv=server1",
                "0x5: proto=tcpv4 src=192.0.2.1:5004 fe=reality_in be=bk_trojan_jpe_upload srv=upload",
            ])
        if command.startswith("shutdown session "):
            return ""
        raise AssertionError(command)


class EnforcementTests(unittest.TestCase):
    def setUp(self):
        self.ledger = guard.Ledger(":memory:", window=1800, threshold=1000)
        self.api = FakeAPI()
        guard.tick(self.api, self.ledger, ARGS, 0)
        self.api.counters[IP] = 1000

    def tearDown(self):
        self.ledger.close()

    def test_mark_is_confirmed_before_only_matching_sessions_are_disconnected(self):
        guard.tick(self.api, self.ledger, ARGS, 10)
        kills = [call for call in self.api.calls if call.startswith("shutdown")]
        self.assertEqual(kills, ["shutdown session 0x1"])
        set_call = "set table %s key %s data.gpc0 1" % (ARGS.mark_table, IP)
        confirm_call = "show table %s key %s" % (ARGS.mark_table, IP)
        self.assertLess(self.api.calls.index(set_call), self.api.calls.index(confirm_call))
        self.assertLess(self.api.calls.index(confirm_call), self.api.calls.index(kills[0]))

    def test_failed_mark_never_disconnects_and_is_retried_from_persisted_decision(self):
        self.api.fail_mark = True
        with self.assertRaises(RuntimeError):
            guard.tick(self.api, self.ledger, ARGS, 10)
        self.assertFalse(any(call.startswith("shutdown") for call in self.api.calls))
        self.api.fail_mark = False
        guard.tick(self.api, self.ledger, ARGS, 20)
        self.assertEqual(self.api.marks[IP], 1)
        self.assertIn("shutdown session 0x1", self.api.calls)

    def test_mark_is_restored_after_haproxy_restart_and_removed_at_deadline(self):
        guard.tick(self.api, self.ledger, ARGS, 10)
        self.api.marks.clear()
        guard.tick(self.api, self.ledger, ARGS, 20)
        self.assertEqual(self.api.marks[IP], 1)
        guard.tick(self.api, self.ledger, ARGS, 86410)
        self.assertNotIn(IP, self.api.marks)

    def test_download_counter_is_not_used(self):
        output = "# table: uploads, type: ipv6, size:102400, used:1\n" + \
            "0x1: key=::ffff:192.0.2.1 use=1 exp=100 bytes_in_cnt=123 bytes_out_cnt=100000000000"
        self.assertEqual(guard.parse_table(output, "uploads", "bytes_in_cnt"), {IP: 123})

    def test_ipv6_sessions_are_identified_without_confusing_port_with_address(self):
        ip = guard.ip_key("2001:db8::1")
        sessions = "0xab: proto=tcpv6 src=2001:db8::1:12345 fe=reality_in be=bk_trojan_jpe srv=server1"
        self.assertEqual(list(guard.parse_sessions(sessions, ARGS.frontend, ARGS.backend, {ip})), [("0xab", ip)])

    def test_unknown_table_is_rejected(self):
        with self.assertRaises(RuntimeError):
            guard.parse_table("No such table", "uploads", "bytes_in_cnt")


class TLSBackend:
    def __init__(self, label, context):
        self.label, self.context = label, context
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen()
        self.listener.settimeout(0.2)
        self.stopped = threading.Event()
        self.connections = []
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.listener.accept()
            except (OSError, socket.timeout):
                continue
            threading.Thread(target=self.serve, args=(connection,), daemon=True).start()

    def serve(self, connection):
        try:
            with self.context.wrap_socket(connection, server_side=True) as stream:
                self.connections.append(stream)
                stream.sendall(self.label + b"\n")
                while not self.stopped.is_set():
                    data = stream.recv(65536)
                    if not data:
                        return
                    if data == b"DOWNLOAD\n":
                        stream.sendall(b"D" * 1048576)
                    elif data == b"PING\n":
                        stream.sendall(b"PONG\n")
        except (OSError, ssl.SSLError):
            connection.close()

    def close(self):
        self.stopped.set()
        self.listener.close()
        for connection in self.connections:
            connection.close()
        self.thread.join(timeout=1)


@unittest.skipUnless(os.environ.get("HAPROXY_TEST_BINARY"), "set HAPROXY_TEST_BINARY to run local HAProxy / TLS tests")
class TLSIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="jpe-test-", dir="/tmp")
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        certificate, key = root / "cert.pem", root / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=jp-east-stream.ssw-servers.com", "-keyout", str(key), "-out", str(certificate),
        ], check=True, capture_output=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        self.profile_args = {name: guard.arguments(["--profile", name]) for name in PROFILE_SNIS}
        backend_ports = {}
        for name, args in self.profile_args.items():
            normal = TLSBackend(name.encode(), context)
            upload = TLSBackend((name + "-upload").encode(), context)
            self.addCleanup(normal.close)
            self.addCleanup(upload.close)
            backend_ports[args.backend] = normal.port
            backend_ports[args.backend + "_upload"] = upload.port
        # 默认兜底和显式 Naive SG 使用相同节点，但在 HAProxy 中保留不同的后端名。
        backend_ports["bk_naive_sg_fallback"] = backend_ports["bk_naive_sg"]
        other = TLSBackend(b"other", context)
        self.addCleanup(other.close)
        self.clients = []
        self.addCleanup(lambda: [client.close() for client in self.clients])
        ports = set()

        def free_port():
            while True:
                with socket.socket() as probe:
                    probe.bind(("127.0.0.1", 0))
                    port = probe.getsockname()[1]
                if port not in ports:
                    ports.add(port)
                    return port

        self.port, self.socket_path = free_port(), str(root / "admin.sock")
        local_lines, section = [], ""
        for line in (HAPROXY_DIR / "all.cfg").read_text().splitlines():
            stripped = line.strip()
            if line and not line.startswith((" ", "#")):
                section = stripped.split()[-1]
            if stripped.startswith(("log ", "chroot ", "user ", "group ", "errorfile ", "ca-base ", "crt-base ")) or stripped == "daemon":
                continue
            if stripped.startswith("stats socket "):
                line = "    stats socket %s level admin" % self.socket_path
            elif stripped.startswith("bind "):
                if section == "reality_in":
                    line = "    bind 127.0.0.1:%d\n    bind [::1]:%d" % (self.port, self.port)
                else:
                    line = "    bind 127.0.0.1:%d" % free_port()
            elif stripped.startswith("server "):
                port = backend_ports.get(section, other.port)
                line = "    server %s 127.0.0.1:%d" % (stripped.split()[1], port)
            local_lines.append(line)
        config = root / "all-local.cfg"
        config.write_text("\n".join(local_lines) + "\n")
        binary = os.environ["HAPROXY_TEST_BINARY"]
        checked = subprocess.run([binary, "-c", "-f", str(config)], capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        self.process = subprocess.Popen([binary, "-db", "-f", str(config)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.stop_haproxy)
        deadline = time.monotonic() + 5
        while not Path(self.socket_path).exists():
            if self.process.poll() is not None:
                self.fail(self.process.communicate()[1].decode())
            if time.monotonic() > deadline:
                self.fail("HAProxy management socket did not start")
            time.sleep(0.02)
        self.ledgers = {}
        for name, args in self.profile_args.items():
            # 使用 CLI 为此 profile 选择的文件名，验证运行实例的状态相互独立。
            self.ledgers[name] = guard.Ledger(root / args.state_db.name, threshold=131072, hold=60)
            self.addCleanup(self.ledgers[name].close)
            checked = subprocess.run([
                sys.executable, str(HAPROXY_DIR / "jpe_upload_guard.py"),
                "--profile", name, "--socket", self.socket_path, "--check",
            ], capture_output=True, text=True)
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def stop_haproxy(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.communicate(timeout=5)

    def connect(self, expected, host="127.0.0.1", sni="jp-east-stream.ssw-servers.com"):
        raw = socket.create_connection((host, self.port), timeout=3)
        client = self.context.wrap_socket(raw, server_hostname=sni)
        self.clients.append(client)
        self.assertEqual(client.recv(100), expected + b"\n")
        return client

    def tick(self, now):
        with guard.RuntimeAPI(self.socket_path) as api:
            for name, args in self.profile_args.items():
                guard.tick(api, self.ledgers[name], args, now)

    def ping(self, client):
        client.sendall(b"PING\n")
        self.assertEqual(client.recv(100), b"PONG\n")

    def wait_for_counter(self, predicate):
        deadline = time.monotonic() + 7
        while time.monotonic() < deadline:
            with guard.RuntimeAPI(self.socket_path) as api:
                if predicate(api):
                    return
            time.sleep(0.2)
        self.fail("continuous traffic counters did not refresh")

    def test_four_entries_upload_download_isolation_reconnect_and_expiry(self):
        clients = {
            name: (self.connect(name.encode(), sni=sni), self.connect(name.encode(), sni=sni))
            for name, sni in PROFILE_SNIS.items()
        }
        other_sni = self.connect(b"other", sni="hk.sswnat.com")
        fallback = self.connect(b"naive-sg", sni="unmatched.example")
        other_ip = self.connect(b"trojan-jpe", host="::1")
        self.tick(1000)

        # 每个入口下载远大于阈值；兜底上传也超过阈值，均不应触发。
        fallback.sendall(b"U" * 200000)
        for first, _ in clients.values():
            first.sendall(b"DOWNLOAD\n")
            received = bytearray()
            while len(received) < 1048576:
                received.extend(first.recv(65536))

        def download_counted(api):
            output = api.command("show stat reality_in 1 -1")
            rows = list(csv.DictReader(io.StringIO(output[2:])))
            return any(row["svname"] == "FRONTEND" and int(row["bout"]) >= 4 * 1048576 for row in rows)

        self.wait_for_counter(download_counted)
        self.tick(1010)
        with guard.RuntimeAPI(self.socket_path) as api:
            for args in self.profile_args.values():
                self.assertFalse(guard.parse_table(api.command("show table " + args.mark_table), args.mark_table, "gpc0"))
                uploads = guard.parse_table(api.command("show table " + args.counter_table), args.counter_table, "bytes_in_cnt")
                self.assertLess(uploads[guard.ip_key("127.0.0.1")], 131072)

        diverted = {}
        for index, (name, sni) in enumerate(PROFILE_SNIS.items()):
            args = self.profile_args[name]
            first, second = clients[name]
            # 同一入口内两条连接合计超过阈值，其他入口不应被连带分流。
            first.sendall(b"U" * 80000)
            second.sendall(b"U" * 80000)

            def upload_counted(api):
                uploads = guard.parse_table(api.command("show table " + args.counter_table), args.counter_table, "bytes_in_cnt")
                return uploads.get(guard.ip_key("127.0.0.1"), 0) >= 131072

            self.wait_for_counter(upload_counted)
            self.tick(1020 + index * 10)
            self.assertEqual(first.recv(100), b"")
            self.assertEqual(second.recv(100), b"")

            with guard.RuntimeAPI(self.socket_path) as api:
                before = api.command("show table " + args.mark_table)
            diverted[name] = self.connect((name + "-upload").encode(), sni=sni)
            time.sleep(0.05)
            with guard.RuntimeAPI(self.socket_path) as api:
                after = api.command("show table " + args.mark_table)
                for entry, entry_args in self.profile_args.items():
                    marks = guard.parse_table(api.command("show table " + entry_args.mark_table), entry_args.mark_table, "gpc0")
                    if entry in diverted:
                        self.assertEqual(marks, {guard.ip_key("127.0.0.1"): 1})
                    else:
                        self.assertFalse(marks)
            self.assertLess(int(re.search(r"exp=(\d+)", after).group(1)), int(re.search(r"exp=(\d+)", before).group(1)))
            for entry, entry_clients in clients.items():
                if entry in diverted:
                    self.ping(diverted[entry])
                else:
                    for client in entry_clients:
                        self.ping(client)
                    self.connect(entry.encode(), sni=PROFILE_SNIS[entry])
            self.ping(fallback)
            self.ping(other_sni)
            self.ping(other_ip)

        # 固定到期时间不会被专用节点上的活动连接延长。
        self.tick(1060)
        self.tick(1120)
        for name, sni in PROFILE_SNIS.items():
            self.connect(name.encode(), sni=sni)
            self.ping(diverted[name])
        self.ping(fallback)
        self.ping(other_sni)
        self.ping(other_ip)


if __name__ == "__main__":
    unittest.main()
