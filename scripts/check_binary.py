#!/usr/bin/env python3
"""Check the release binary against the size, startup and memory targets (Linux only).

Usage: python3 scripts/check_binary.py <binary>
Exit 1 with one line per failed check. Prints the three measured values always.
"""
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request

MAX_SIZE = 5 * 1024 * 1024  # 5_242_880 bytes
MAX_START_MS = 50.0
MAX_RSS_KB = 15 * 1000  # 15 MB
RUNS = 5
TIMEOUT_S = 5.0


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def spawn(binary: str, port: int, cwd: str) -> subprocess.Popen:
    return subprocess.Popen(
        [binary, "--port", str(port)],
        cwd=cwd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def wait_listening(port: int, proc: subprocess.Popen) -> None:
    deadline = time.monotonic() + TIMEOUT_S
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"binary exited early with code {proc.returncode}")
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.001)
    raise RuntimeError("binary did not listen in time")


def stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def startup_ms(binary: str) -> float:
    samples = []
    for _ in range(RUNS):
        with tempfile.TemporaryDirectory() as tmp:
            port = free_port()
            start = time.perf_counter()
            proc = spawn(binary, port, tmp)
            try:
                wait_listening(port, proc)
                samples.append((time.perf_counter() - start) * 1000)
            finally:
                stop(proc)
    return statistics.median(samples)


def idle_rss_kb(binary: str) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        port = free_port()
        proc = spawn(binary, port, tmp)
        try:
            wait_listening(port, proc)
            url = f"http://127.0.0.1:{port}/_mock/health"
            urllib.request.urlopen(url, timeout=TIMEOUT_S).read()
            time.sleep(2)
            with open(f"/proc/{proc.pid}/status") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1])
            raise RuntimeError("VmRSS not found")
        finally:
            stop(proc)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_binary.py <binary>", file=sys.stderr)
        return 2
    binary = os.path.abspath(sys.argv[1])

    size = os.path.getsize(binary)
    start = startup_ms(binary)
    rss = idle_rss_kb(binary)

    print(f"size: {size} bytes (limit {MAX_SIZE})")
    print(f"startup median of {RUNS}: {start:.1f} ms (limit {MAX_START_MS:.0f})")
    print(f"idle VmRSS: {rss} kB (limit {MAX_RSS_KB})")

    failures = []
    if size > MAX_SIZE:
        failures.append(f"FAIL size: {size} > {MAX_SIZE} bytes")
    if start >= MAX_START_MS:
        failures.append(f"FAIL startup: {start:.1f} ms >= {MAX_START_MS:.0f} ms")
    if rss >= MAX_RSS_KB:
        failures.append(f"FAIL rss: {rss} kB >= {MAX_RSS_KB} kB")
    for line in failures:
        print(line)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
