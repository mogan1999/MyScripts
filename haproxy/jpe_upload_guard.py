#!/usr/bin/env python3
"""按公网 IP 的滚动上传量分流指定 Naive / Trojan 入口；只依赖 Python 标准库。"""

import argparse
import fcntl
import ipaddress
import logging
import os
from pathlib import Path
import re
import socket
import sqlite3
import time


LOG = logging.getLogger("jpe-upload-guard")

# 每个入口使用独立的计数表、标记表和数据库；保留原日本 Trojan 的默认状态文件。
PROFILES = {
    "trojan-jpe": ("bk_jpe_upload_stats", "bk_jpe_upload_marks", "bk_trojan_jpe", "state.sqlite3"),
    "naive-jpe": (
        "bk_naive_jpe_upload_stats", "bk_naive_jpe_upload_marks", "bk_naive_jp_east", "naive-jpe.sqlite3"
    ),
    "trojan-sg": (
        "bk_trojan_sg_upload_stats", "bk_trojan_sg_upload_marks", "bk_trojan_sg", "trojan-sg.sqlite3"
    ),
    "naive-sg": (
        "bk_naive_sg_upload_stats", "bk_naive_sg_upload_marks", "bk_naive_sg", "naive-sg.sqlite3"
    ),
}


def ip_key(value):
    """统一为 IPv6 表的键，IPv4 使用 RFC 4291 映射地址。"""
    address = ipaddress.ip_address(value)
    if address.version == 4:
        address = ipaddress.IPv6Address("::ffff:" + str(address))
    return str(address)


def display_ip(value):
    address = ipaddress.IPv6Address(value)
    return str(address.ipv4_mapped or address)


class RuntimeAPI:
    """每轮采样复用一个 CLI 连接，避免重载时跨进程使用 session 指针。"""

    def __init__(self, path, timeout=10):
        self.path = path
        self.timeout = timeout
        self.sock = None

    def __enter__(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        try:
            self.sock.connect(self.path)
            self.command("prompt")
        except Exception:
            self.sock.close()
            raise
        return self

    def __exit__(self, *args):
        self.sock.close()

    def command(self, command):
        if any(char in command for char in "\r\n;"):
            raise ValueError("Runtime API command must be a single command")
        self.sock.sendall((command + "\n").encode("ascii"))
        chunks = bytearray()
        while not (chunks == b"> " or chunks.endswith(b"\n> ")):
            data = self.sock.recv(65536)
            if not data:
                raise RuntimeError("HAProxy closed the Runtime API connection")
            chunks.extend(data)
        return chunks[:-2].decode("utf-8").strip()


def parse_table(output, name, field):
    if not output.startswith("# table: " + name + ", type: ipv6,"):
        raise RuntimeError("Expected IPv6 stick-table %s: %s" % (name, output[:200]))
    result = {}
    for line in output.splitlines()[1:]:
        values = dict(re.findall(r"(\w+)=([^\s]+)", line))
        if "key" not in values or field not in values:
            raise RuntimeError("Missing %s in stick-table %s" % (field, name))
        result[ip_key(values["key"])] = int(values[field])
    return result


def parse_sessions(output, frontend, backend, ips):
    for line in output.splitlines():
        match = re.match(r"^(0x[0-9a-fA-F]+):", line)
        values = dict(re.findall(r"\b(src|fe|be)=([^\s]+)", line))
        if not match or values.get("fe") != frontend or values.get("be") != backend:
            continue
        source = values.get("src", "").rsplit(":", 1)[0].strip("[]")
        try:
            address = ip_key(source)
        except ValueError:
            continue
        if address in ips:
            yield match.group(1), address


class Ledger:
    """保存计数基线、最近 30 分钟的增量，以及分流的绝对到期时间。"""

    def __init__(self, path, window=1800, threshold=5000000000, hold=86400, interval=10):
        self.window, self.threshold, self.hold, self.interval = window, threshold, hold, interval
        self.db = sqlite3.connect(str(path), timeout=10)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS counters (
                ip TEXT PRIMARY KEY, value INTEGER NOT NULL,
                observed_at REAL NOT NULL, epoch TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS samples (
                ip TEXT NOT NULL, observed_at REAL NOT NULL, bytes INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS samples_time ON samples(observed_at);
            CREATE INDEX IF NOT EXISTS samples_ip ON samples(ip);
            CREATE TABLE IF NOT EXISTS diversions (
                ip TEXT PRIMARY KEY, expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sampling (
                id INTEGER PRIMARY KEY, observed_at REAL NOT NULL
            );
        """)

    def close(self):
        self.db.close()

    def advance(self, counters, epoch, now):
        with self.db:
            holds = dict(self.db.execute("SELECT ip, expires_at FROM diversions"))
            expired = {ip for ip, expiry in holds.items() if expiry <= now}
            active = {ip: expiry for ip, expiry in holds.items() if expiry > now}
            previous = {
                ip: (value, seen, old_epoch)
                for ip, value, seen, old_epoch in self.db.execute("SELECT * FROM counters")
            }
            previous_poll = self.db.execute("SELECT observed_at FROM sampling WHERE id = 1").fetchone()
            recent_poll = previous_poll and 0 <= now - previous_poll[0] <= self.interval * 3
            self.db.execute("DELETE FROM samples WHERE observed_at <= ?", (now - self.window,))
            self.db.execute("DELETE FROM diversions WHERE expires_at <= ?", (now,))
            # 分流期间不累加配额；到期恢复后从新基线开始，避免立刻再次分流。
            self.db.executemany("DELETE FROM samples WHERE ip = ?", [(ip,) for ip in expired])
            increments = []
            for ip, value in counters.items():
                baseline = previous.get(ip)
                if ip not in active and ip not in expired:
                    delta = 0
                    if baseline:
                        old_value, seen, old_epoch = baseline
                        if 0 <= now - seen <= self.interval * 3:
                            delta = value - old_value if old_epoch == epoch and value >= old_value else value
                    elif recent_poll:
                        # 启动后的新 IP 是新建表项，其首次采样前的上传也要计入。
                        delta = value
                    # 长时间停采无法确定字节的发生时间，重新建基线以免误判。
                    if delta:
                        increments.append((ip, now, delta))
            self.db.executemany("INSERT INTO samples VALUES (?, ?, ?)", increments)
            self.db.executemany(
                "INSERT OR REPLACE INTO counters VALUES (?, ?, ?, ?)",
                [(ip, value, now, epoch) for ip, value in counters.items()],
            )
            self.db.execute("DELETE FROM counters WHERE observed_at < ?", (now - self.window,))
            self.db.execute("INSERT OR REPLACE INTO sampling VALUES (1, ?)", (now,))
            created = {}
            for ip, uploaded in self.db.execute(
                "SELECT ip, SUM(bytes) FROM samples GROUP BY ip HAVING SUM(bytes) >= ?",
                (self.threshold,),
            ):
                if ip not in active:
                    active[ip] = now + self.hold
                    created[ip] = uploaded
            self.db.executemany(
                "INSERT INTO diversions VALUES (?, ?)",
                [(ip, active[ip]) for ip in created],
            )
            self.db.executemany("DELETE FROM samples WHERE ip = ?", [(ip,) for ip in created])
        return active, created, expired

    def release(self, ip):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO diversions VALUES (?, 0)", (ip,))
            self.db.execute("DELETE FROM samples WHERE ip = ?", (ip,))
            self.db.execute("DELETE FROM counters WHERE ip = ?", (ip,))


def tick(api, ledger, args, now):
    info = dict(re.findall(r"^(\w+): (.*)$", api.command("show info"), re.MULTILINE))
    if "Pid" not in info:
        raise RuntimeError("Runtime API did not return a HAProxy PID")
    counters = parse_table(api.command("show table " + args.counter_table), args.counter_table, "bytes_in_cnt")
    marks = parse_table(api.command("show table " + args.mark_table), args.mark_table, "gpc0")
    desired, created, expired = ledger.advance(counters, info["Pid"], now)

    for ip in expired:
        LOG.info("restore %s backend=%s after hold expired or manual release", display_ip(ip), args.backend)
    for ip, uploaded in created.items():
        LOG.info("divert %s backend=%s: rolling upload=%d bytes, hold=%ds", display_ip(ip), args.backend, uploaded, ledger.hold)

    # 先持久化决策，再设置并确认标记，最后断开旧连接；任一步失败都会重试。
    for ip, flag in marks.items():
        if flag and ip not in desired:
            response = api.command("clear table %s key %s" % (args.mark_table, ip))
            if response:
                raise RuntimeError(response)
    for ip in desired:
        if marks.get(ip) != 1:
            response = api.command("set table %s key %s data.gpc0 1" % (args.mark_table, ip))
            if response:
                raise RuntimeError(response)
            confirmed = parse_table(
                api.command("show table %s key %s" % (args.mark_table, ip)), args.mark_table, "gpc0"
            )
            if confirmed.get(ip) != 1:
                raise RuntimeError("Could not confirm diversion mark for " + display_ip(ip))
    if desired:
        sessions = list(parse_sessions(api.command("show sess"), args.frontend, args.backend, desired))
        for session, ip in sessions:
            response = api.command("shutdown session " + session)
            if response and "No such session" not in response:
                raise RuntimeError(response)
            if not response:
                LOG.info("disconnect %s session=%s backend=%s", display_ip(ip), session, args.backend)


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, default="trojan-jpe", help="monitored entry (default: trojan-jpe)")
    parser.add_argument("--socket", default="/run/haproxy/admin.sock")
    parser.add_argument("--state-db", type=Path, help="override the profile's independent state database")
    parser.add_argument("--counter-table", help="override the profile's upload counter table")
    parser.add_argument("--mark-table", help="override the profile's diversion mark table")
    parser.add_argument("--frontend", default="reality_in")
    parser.add_argument("--backend", help="override the profile's original backend")
    parser.add_argument("--window", type=float, default=1800, help="rolling window in seconds (30 minutes by default)")
    parser.add_argument("--threshold", type=int, default=5000000000, help="uploaded bytes (5 GB by default)")
    parser.add_argument("--hold", type=float, default=86400, help="diversion duration in seconds")
    parser.add_argument("--interval", type=float, default=10, help="poll interval in seconds")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true", help="read-only Runtime API / table check")
    modes.add_argument("--status", action="store_true", help="show persisted diversion deadlines")
    modes.add_argument("--release", metavar="IP", help="queue release; daemon applies it at the next poll")
    modes.add_argument("--once", action="store_true", help="run one sampling / enforcement cycle")
    args = parser.parse_args(argv)
    counter_table, mark_table, backend, state_file = PROFILES[args.profile]
    args.counter_table = args.counter_table or counter_table
    args.mark_table = args.mark_table or mark_table
    args.backend = args.backend or backend
    args.state_db = args.state_db or Path("/var/lib/haproxy-jpe-upload") / state_file
    if min(args.window, args.threshold, args.hold, args.interval) <= 0 or args.window <= args.interval:
        parser.error("threshold, hold and interval must be positive; window must exceed interval")
    for name in (args.counter_table, args.mark_table, args.frontend, args.backend):
        if not re.fullmatch(r"[A-Za-z0-9_.:/-]+", name):
            parser.error("invalid HAProxy table / proxy name")
    if args.release:
        try:
            args.release = ip_key(args.release)
        except ValueError as exc:
            parser.error(str(exc))
    return args


def main():
    args = arguments()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.check:
        with RuntimeAPI(args.socket) as api:
            parse_table(api.command("show table " + args.counter_table), args.counter_table, "bytes_in_cnt")
            parse_table(api.command("show table " + args.mark_table), args.mark_table, "gpc0")
            print("%s: Runtime API and IPv4/IPv6 upload / diversion tables are ready" % args.profile)
        return 0

    os.umask(0o077)
    args.state_db.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    ledger = Ledger(args.state_db, args.window, args.threshold, args.hold, args.interval)
    try:
        if args.release:
            ledger.release(args.release)
            print("Release queued for %s; applied at the next daemon poll" % display_ip(args.release))
            return 0
        if args.status:
            for ip, expiry in ledger.db.execute("SELECT ip, expires_at FROM diversions ORDER BY expires_at"):
                print("%s remaining_seconds=%d" % (display_ip(ip), max(0, expiry - time.time())))
            return 0
        with args.state_db.with_suffix(".lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("Another monitor is already using this state database")
            LOG.info(
                "monitor started: profile=%s backend=%s window=%ds threshold=%d bytes hold=%ds",
                args.profile, args.backend, args.window, args.threshold, args.hold,
            )
            while True:
                started = time.monotonic()
                try:
                    with RuntimeAPI(args.socket) as api:
                        tick(api, ledger, args, time.time())
                except (OSError, RuntimeError, ValueError) as exc:
                    LOG.error("sampling / enforcement failed: %s", exc)
                    if args.once:
                        return 1
                if args.once:
                    return 0
                time.sleep(max(0, args.interval - (time.monotonic() - started)))
    finally:
        ledger.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(0)
    except (OSError, RuntimeError, sqlite3.Error) as exc:
        LOG.error("%s", exc)
        raise SystemExit(1)
