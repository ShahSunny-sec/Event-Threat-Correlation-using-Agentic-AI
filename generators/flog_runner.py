"""Run the open-source `flog` fake log generator (https://github.com/mingrammer/flog).

Requires either:
  - `flog` on PATH (e.g. ``brew tap mingrammer/flog && brew install flog``), or
  - Docker with ``mingrammer/flog`` image pulled.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import List, Literal

FlogFormat = Literal[
    "apache_common",
    "apache_combined",
    "apache_error",
    "rfc3164",
    "rfc5424",
    "json",
]


class FlogNotFoundError(RuntimeError):
    """Neither local `flog` nor Docker is available."""


class FlogRunError(RuntimeError):
    """flog exited with an error."""


def flog_available() -> bool:
    return shutil.which("flog") is not None


def docker_available() -> bool:
    return shutil.which("docker") is not None


def run_flog(
    number: int = 200,
    fmt: str = "apache_common",
    use_docker: bool = False,
) -> str:
    """Generate logs via flog and return stdout text.

    Args:
        number: Line count (-n).
        fmt: flog -f format (see FlogFormat).
        use_docker: If True, run ``docker run mingrammer/flog ...`` (needs network on first pull).
    """
    if number < 1:
        number = 1
    if number > 100_000:
        number = 100_000

    base_cmd: List[str]
    if use_docker:
        if not docker_available():
            raise FlogNotFoundError("Docker not found on PATH.")
        base_cmd = [
            "docker",
            "run",
            "--rm",
            "mingrammer/flog:latest",
            "-n",
            str(number),
            "-f",
            fmt,
            "-t",
            "stdout",
        ]
    elif flog_available():
        base_cmd = ["flog", "-n", str(number), "-f", fmt, "-t", "stdout"]
    else:
        raise FlogNotFoundError(
            "Install flog: https://github.com/mingrammer/flog "
            "(e.g. `brew tap mingrammer/flog && brew install flog`) "
            "or enable Docker and pull mingrammer/flog."
        )

    try:
        proc = subprocess.run(
            base_cmd,
            capture_output=True,
            text=True,
            timeout=min(120, 10 + number // 5000),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise FlogRunError("flog timed out") from exc
    except OSError as exc:
        raise FlogRunError(str(exc)) from exc

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()[:500]
        raise FlogRunError(f"flog exit {proc.returncode}: {err}")

    return proc.stdout or ""
