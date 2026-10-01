"""Async subprocess execution for nmap with timeout management."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 600
MAX_TIMEOUT = 3600


@dataclass
class ScanExecution:
    command: list[str]
    stdout: str
    stderr: str
    return_code: int
    timed_out: bool
    duration_seconds: float


async def execute_nmap(
    command: list[str],
    timeout: int = DEFAULT_TIMEOUT,
) -> ScanExecution:
    """Execute an nmap command as an async subprocess.

    Uses create_subprocess_exec — never shell=True.
    """
    timeout = min(max(timeout, 10), MAX_TIMEOUT)
    start = time.monotonic()

    logger.info("Executing: %s", " ".join(command))

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    timed_out = False
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        timed_out = True
        stdout_bytes = b""
        stderr_bytes = f"Scan timed out after {timeout} seconds".encode()

    duration = time.monotonic() - start

    return ScanExecution(
        command=command,
        stdout=stdout_bytes.decode("utf-8", errors="replace"),
        stderr=stderr_bytes.decode("utf-8", errors="replace"),
        return_code=process.returncode or -1,
        timed_out=timed_out,
        duration_seconds=round(duration, 2),
    )
