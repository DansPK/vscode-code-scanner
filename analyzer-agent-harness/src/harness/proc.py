"""Run external commands without blocking, so they can be cancelled."""

import asyncio
import logging

log = logging.getLogger(__name__)


class CommandError(Exception):
    pass


async def run(args, cwd=None, procs=None, timeout=None, env=None):
    """Run a command and return (returncode, stdout, stderr) as text.
    Running processes are added to `procs` so a cancel can kill them."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, cwd=cwd, env=env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError as e:
        raise CommandError(f"{args[0]} is not installed") from e
    if procs is not None:
        procs.add(proc)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        raise
    finally:
        if procs is not None:
            procs.discard(proc)
    return proc.returncode, out.decode(errors="replace"), err.decode(errors="replace")
