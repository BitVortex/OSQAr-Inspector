"""Isolated subprocess supervisor for the process-conformance boundary.

The supervisor is intentionally a separate process.  It becomes a Linux child
subreaper so descendants that leave the producer's session are reparented here,
then kills and reaps the complete descendant set before reporting completion.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

_PR_SET_CHILD_SUBREAPER = 36
_READ_CHUNK = 64 * 1024
_CLEANUP_SECONDS = 2.0


def _become_subreaper() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _process_parents() -> dict[int, int]:
    parents: dict[int, int] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            stat_line = (entry / "stat").read_text(encoding="ascii")
            after_name = stat_line.rsplit(")", 1)[1].split()
            parents[int(entry.name)] = int(after_name[1])
        except (FileNotFoundError, IndexError, OSError, ValueError):
            continue
    return parents


def _descendants(root: int) -> set[int]:
    parents = _process_parents()
    found: set[int] = set()
    frontier = {root}
    while frontier:
        children = {
            pid
            for pid, parent in parents.items()
            if parent in frontier and pid not in found and pid != root
        }
        found.update(children)
        frontier = children
    return found


def _reap_available() -> None:
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def _kill_and_reap(root: int, *, include_root: bool) -> bool:
    deadline = time.monotonic() + _CLEANUP_SECONDS
    while True:
        victims = _descendants(root)
        if include_root and Path(f"/proc/{root}").exists():
            victims.add(root)
        for pid in victims:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        _reap_available()
        remaining = _descendants(root)
        if include_root and Path(f"/proc/{root}").exists():
            remaining.add(root)
        if not remaining:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)


def _drain(stream: Any, destination: bytearray, limit: int) -> None:
    while chunk := stream.read(_READ_CHUNK):
        remaining = limit - len(destination)
        if remaining > 0:
            destination.extend(chunk[:remaining])


def _write_report(descriptor: int, report: dict[str, Any]) -> None:
    content = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]


def _failure(kind: str) -> dict[str, Any]:
    return {"kind": kind}


def _run(argv: list[str], timeout: float, console_limit: int) -> dict[str, Any]:
    _become_subreaper()
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=os.environ.copy(),
            start_new_session=True,
        )
    except OSError:
        return _failure("start-error")

    assert process.stdout is not None and process.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    threads = [
        threading.Thread(
            target=_drain, args=(process.stdout, stdout, console_limit), daemon=True
        ),
        threading.Thread(
            target=_drain, args=(process.stderr, stderr, console_limit), daemon=True
        ),
    ]
    for thread in threads:
        thread.start()

    timed_out = False
    try:
        return_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if not _kill_and_reap(process.pid, include_root=True):
            return _failure("cleanup-error")
        try:
            return_code = process.wait(timeout=0.1)
        except (ChildProcessError, subprocess.TimeoutExpired):
            return_code = -signal.SIGKILL

    if not _kill_and_reap(os.getpid(), include_root=False):
        return _failure("cleanup-error")
    for thread in threads:
        thread.join(timeout=1)
    if any(thread.is_alive() for thread in threads):
        return _failure("cleanup-error")
    if timed_out:
        return _failure("timeout")
    return {
        "kind": "completed",
        "returncode": return_code,
        "stderr": base64.b64encode(stderr).decode("ascii"),
        "stdout": base64.b64encode(stdout).decode("ascii"),
    }


def main() -> int:
    if len(sys.argv) < 6 or sys.argv[4] != "--":
        return 2
    descriptor = int(sys.argv[1])
    timeout = float(sys.argv[2])
    console_limit = int(sys.argv[3])
    try:
        report = _run(sys.argv[5:], timeout, console_limit)
    except (OSError, RuntimeError, ValueError):
        report = _failure("supervisor-error")
    try:
        _write_report(descriptor, report)
    finally:
        os.close(descriptor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
