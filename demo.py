#!/usr/bin/env python3
"""Run the whole reproduction with one command: `python demo.py`

Starts both demonstration receivers, waits for them to accept connections, runs
the cases against them, and shuts them down. Exits non-zero if any case does not
behave as described.
"""

import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).parent
RECEIVERS = [
    ("digest", 8801),
    ("url", 8802),
]
RESOURCE_ORIGIN = "http://127.0.0.1:8899"


def wait_until_listening(port, timeout=15):
    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{port}/.well-known/agent-handoff-spec.json"
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1).read()
            return True
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.2)
    return False


def main():
    processes = []
    try:
        for mode, port in RECEIVERS:
            processes.append(subprocess.Popen(
                [sys.executable, str(HERE / "receiver.py"),
                 "--port", str(port),
                 "--identity-mode", mode,
                 "--resource-origin", RESOURCE_ORIGIN],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ))
        for _, port in RECEIVERS:
            if not wait_until_listening(port):
                print(f"receiver on port {port} did not start", file=sys.stderr)
                return 1

        return subprocess.call([
            sys.executable, str(HERE / "run_cases.py"),
            "--receiver-digest", f"http://127.0.0.1:{RECEIVERS[0][1]}",
            "--receiver-legacy", f"http://127.0.0.1:{RECEIVERS[1][1]}",
        ])
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


if __name__ == "__main__":
    sys.exit(main())
