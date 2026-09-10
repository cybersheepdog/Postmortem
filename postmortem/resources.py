"""Runtime resource detection and adaptive worker sizing.

Nothing in postmortem hard-codes a core count or a memory limit. The machine an
investigation runs on varies wildly -- an analyst laptop, a dual-socket forensic
workstation, an isolated VM with two cores -- so every parallel phase asks this
module how wide it may go and gets an answer derived from the hardware actually
present at run time.

Two independent bounds are applied and the smaller wins:

  * a CPU bound, from the logical/physical core count, minus a reservation so
    the parent process and the OS are not starved; and
  * a memory bound, from *currently available* RAM (not total), divided by a
    per-worker footprint estimate, so a 200GB corpus on a 16GB box quietly runs
    narrower instead of dying to the OOM killer half way through.

Every value here is overridable. An explicit ``--workers`` on the command line
is honored as a ceiling request, and the ``POSTMORTEM_*`` environment variables
below override individual pieces, so a strange machine can always be tuned
without a code change.

Environment overrides:
  POSTMORTEM_WORKERS            hard worker count; skips all detection
  POSTMORTEM_MAX_WORKERS        upper clamp on the detected count
  POSTMORTEM_CPU_RESERVE        cores to leave free (default 1)
  POSTMORTEM_MEMORY_FRACTION    fraction of available RAM usable (default 0.7)
  POSTMORTEM_WORKER_MB          per-worker footprint estimate in MB
  POSTMORTEM_LOGICAL_CORES      "0" to size against physical cores only
"""

from __future__ import annotations

import os

import psutil

# Per-worker resident footprint estimates, in bytes. These are deliberately
# generous: under-estimating costs an OOM half way through a multi-hour run,
# while over-estimating only costs some parallelism. Measured against the
# heaviest realistic message (large multipart mail with several attachments).
WORKER_FOOTPRINT = {
    # MIME parse workers hold one message tree plus the record they build.
    "parse": 256 * 1024 * 1024,
    # Extraction workers hold an open libpff handle plus one reconstructed
    # message with its attachment bytes; PST handles are the expensive part.
    "extract": 512 * 1024 * 1024,
    # YARA workers hold the compiled ruleset (a large signature-base compile is
    # hundreds of MB on its own) plus one attachment payload.
    "yara": 768 * 1024 * 1024,
    # QR workers hold a decoded image bitmap, which can be far larger than the
    # encoded attachment that produced it.
    "qr": 384 * 1024 * 1024,
    # Deep enrichment re-parses a candidate message and analyzes its URLs.
    "deep": 384 * 1024 * 1024,
}

DEFAULT_FOOTPRINT = 256 * 1024 * 1024
DEFAULT_MEMORY_FRACTION = 0.7
DEFAULT_CPU_RESERVE = 1


def _env_int(name: str, default=None):
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return int(str(raw).strip())
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return float(str(raw).strip())
    except ValueError:
        return default


def cpu_count(logical=None) -> int:
    """Usable core count, honoring CPU affinity where the OS exposes it.

    A run pinned to a subset of cores (taskset, a cgroup quota, a scheduler
    affinity mask) must size against the cores it may actually use, not against
    every core in the machine.
    """
    if logical is None:
        logical = _env_int("POSTMORTEM_LOGICAL_CORES", 1) != 0

    if logical:
        try:
            # Linux only; the affinity mask is the true usable set.
            return max(1, len(os.sched_getaffinity(0)))
        except (AttributeError, OSError):
            pass

    try:
        detected = psutil.cpu_count(logical=logical)
    except Exception:
        detected = None
    if not detected:
        detected = os.cpu_count() or 1
    return max(1, int(detected))


def available_memory() -> int:
    """Bytes of RAM available right now, without counting swap.

    ``available`` rather than ``free``: it accounts for reclaimable page cache,
    which on a box that has just read hundreds of GB of PST is most of what
    ``free`` would otherwise report as used.
    """
    try:
        return int(psutil.virtual_memory().available)
    except Exception:
        # Never let resource detection be the thing that kills a run.
        return 2 * 1024 * 1024 * 1024


def total_memory() -> int:
    try:
        return int(psutil.virtual_memory().total)
    except Exception:
        return 2 * 1024 * 1024 * 1024


def process_rss(pid=None) -> int:
    """Resident set size of this process (or `pid`), in bytes."""
    try:
        return int(psutil.Process(pid).memory_info().rss)
    except Exception:
        return 0


def memory_pressure() -> float:
    """Fraction of total RAM currently in use, 0.0-1.0.

    Used by the streaming phases to decide when to flush accumulated records to
    SQLite rather than hold them.
    """
    try:
        return float(psutil.virtual_memory().percent) / 100.0
    except Exception:
        return 0.0


def plan_workers(phase, requested=None, footprint=None, minimum=1):
    """Decide how many workers `phase` may use on this machine, with a reason.

    Returns ``(workers, explanation)``. The explanation is printed so an
    analyst reading a run log can see why a 24-thread box only used six
    workers, rather than assuming the tool is broken.
    """
    forced = _env_int("POSTMORTEM_WORKERS")
    if forced and forced > 0:
        return max(1, forced), "POSTMORTEM_WORKERS=%d" % forced

    cores = cpu_count()
    reserve = max(0, _env_int("POSTMORTEM_CPU_RESERVE", DEFAULT_CPU_RESERVE) or 0)
    cpu_bound = max(minimum, cores - reserve)

    if footprint is None:
        override_mb = _env_int("POSTMORTEM_WORKER_MB")
        if override_mb and override_mb > 0:
            footprint = override_mb * 1024 * 1024
        else:
            footprint = WORKER_FOOTPRINT.get(phase, DEFAULT_FOOTPRINT)

    fraction = _env_float("POSTMORTEM_MEMORY_FRACTION", DEFAULT_MEMORY_FRACTION)
    fraction = min(max(fraction, 0.05), 0.95)
    usable = int(available_memory() * fraction)
    mem_bound = max(minimum, usable // max(footprint, 1))

    # Track which constraint actually binds, so the printed reason names the
    # thing an operator would have to change to get more parallelism.
    constraints = [
        (cpu_bound, "cpu-bound: %d cores - %d reserved" % (cores, reserve)),
        (
            mem_bound,
            "memory-bound: %.1fGB available x %d%% / %dMB per worker"
            % (available_memory() / 1e9, int(fraction * 100), footprint / 1e6),
        ),
    ]
    if requested and requested > 0:
        constraints.append((requested, "requested %d" % requested))

    clamp = _env_int("POSTMORTEM_MAX_WORKERS")
    if clamp and clamp > 0:
        constraints.append((clamp, "POSTMORTEM_MAX_WORKERS=%d" % clamp))

    limit, why = min(constraints, key=lambda item: item[0])
    workers = max(minimum, int(limit))
    if workers != limit:
        why = "%s (raised to floor of %d)" % (why, minimum)

    return workers, why


def describe_host() -> str:
    """One-line hardware summary for the run log and the report manifest."""
    physical = cpu_count(logical=False)
    logical = cpu_count(logical=True)
    mem = psutil.virtual_memory()
    return (
        "%d physical / %d logical cores, %.0fGB RAM (%.0fGB available)"
        % (physical, logical, mem.total / 1e9, mem.available / 1e9)
    )
