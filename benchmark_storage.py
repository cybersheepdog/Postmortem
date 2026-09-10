"""Measure what this machine's storage and CPU can actually do, and project a
postmortem run over a large container corpus from it.

Standalone and stdlib-only (psutil is used if present, skipped if not), so it
can be dropped onto an analysis box and run without installing anything.

Why this exists: on a corpus measured in hundreds of gigabytes the run time is
not dominated by reading the PSTs. It is dominated by writing, and then
re-reading, one small .eml file per message. Sequential throughput barely
predicts that; small-file rate does. The parallel section matters just as much
-- if small-file writes do not scale with concurrency on this storage, extra
extraction workers only add contention, and the tool should be told to run
narrower.

Usage:
    python benchmark_storage.py --path "D:\\path\\to\\workdir"
    python benchmark_storage.py --path . --containers "D:\\mail\\psts"

Everything it writes goes in a temporary subdirectory under --path and is
deleted afterwards. It needs roughly 1GB free there while running.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import statistics
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SEQ_FILE_MB = 512
SMALL_FILE_COUNT = 3000
SMALL_FILE_KB = 12  # close to a typical plain-text .eml


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def human(n: float, unit: str = "B") -> str:
    for suffix in ("", "K", "M", "G", "T"):
        if abs(n) < 1024:
            return f"{n:,.1f}{suffix}{unit}"
        n /= 1024
    return f"{n:,.1f}P{unit}"


def duration(seconds: float) -> str:
    seconds = max(seconds, 0)
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.1f} min"
    return f"{seconds / 3600:.1f} hours"


def describe_host() -> None:
    print("HOST")
    print(f"  platform      : {platform.platform()}")
    print(f"  python        : {sys.version.split()[0]}")
    logical = os.cpu_count() or 0
    print(f"  logical cores : {logical}")
    try:
        import psutil
        vm = psutil.virtual_memory()
        print(f"  physical cores: {psutil.cpu_count(logical=False)}")
        print(f"  RAM           : {human(vm.total)} total, "
              f"{human(vm.available)} available")
    except Exception:
        print("  RAM           : (install psutil for memory detail)")
    print()


def describe_volume(path: Path) -> None:
    total, used, free = shutil.disk_usage(path)
    print("TARGET VOLUME")
    print(f"  path          : {path}")
    print(f"  capacity      : {human(total)} total, {human(free)} free")
    print()
    if free < 2 * 1024 ** 3:
        print("  [!] Less than 2GB free here; the benchmark needs about 1GB.\n")


# ---------------------------------------------------------------------------
# measurements
# ---------------------------------------------------------------------------
def measure_sequential(workdir: Path) -> dict:
    """Large-file write then read. Sets the ceiling for bulk container reads."""
    target = workdir / "sequential.bin"
    block = os.urandom(1024 * 1024)

    start = time.perf_counter()
    with target.open("wb") as fh:
        for _ in range(SEQ_FILE_MB):
            fh.write(block)
        fh.flush()
        os.fsync(fh.fileno())
    write_s = time.perf_counter() - start

    # Best effort at defeating the page cache so the read is not free. On
    # Windows there is no drop_caches, so treat the read figure as an upper
    # bound rather than a cold-cache number.
    try:
        with open("/proc/sys/vm/drop_caches", "w") as fh:
            fh.write("3")
    except Exception:
        pass

    start = time.perf_counter()
    read_bytes = 0
    with target.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            read_bytes += len(chunk)
    read_s = time.perf_counter() - start

    target.unlink(missing_ok=True)
    mb = SEQ_FILE_MB
    return {
        "write_mb_s": mb / write_s if write_s else 0,
        "read_mb_s": mb / read_s if read_s else 0,
    }


def _write_batch(args) -> float:
    directory, start_index, count, payload = args
    directory.mkdir(parents=True, exist_ok=True)
    begin = time.perf_counter()
    for i in range(start_index, start_index + count):
        (directory / f"{i:06d}.eml").write_bytes(payload)
    return time.perf_counter() - begin


def measure_small_files(workdir: Path, threads: int) -> dict:
    """Create, walk, read and delete many small files.

    This is the operation extraction actually performs, millions of times.
    """
    payload = os.urandom(SMALL_FILE_KB * 1024)
    root = workdir / f"small_{threads}"
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True, exist_ok=True)

    per_thread = SMALL_FILE_COUNT // threads
    jobs = [
        (root / f"t{t}", t * per_thread, per_thread, payload)
        for t in range(threads)
    ]
    written = per_thread * threads

    start = time.perf_counter()
    if threads == 1:
        _write_batch(jobs[0])
    else:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            list(pool.map(_write_batch, jobs))
    write_s = time.perf_counter() - start

    # Directory walk: the discovery phase does exactly this over the whole
    # staging tree before any parsing starts.
    start = time.perf_counter()
    found = 0
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames:
            if name.endswith(".eml"):
                found += 1
    walk_s = time.perf_counter() - start

    # Read them back: the parse pass, and every attachment-scan pass, does
    # this. Read at the same concurrency as the write test -- a per-open cost
    # (an on-access scanner, or high per-IO latency) looks completely
    # different from a bandwidth limit once you add threads, and that
    # difference decides whether more workers help or do nothing.
    paths = list(root.rglob("*.eml"))
    chunk = max(1, len(paths) // threads)
    batches = [paths[i:i + chunk] for i in range(0, len(paths), chunk)]

    def read_batch(batch):
        for item in batch:
            item.read_bytes()

    start = time.perf_counter()
    if threads == 1:
        read_batch(paths)
    else:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            list(pool.map(read_batch, batches))
    read_s = time.perf_counter() - start

    start = time.perf_counter()
    shutil.rmtree(root, ignore_errors=True)
    delete_s = time.perf_counter() - start

    return {
        "threads": threads,
        "files": written,
        "write_files_s": written / write_s if write_s else 0,
        "write_mb_s": (written * SMALL_FILE_KB / 1024) / write_s if write_s else 0,
        "walk_files_s": found / walk_s if walk_s else 0,
        "read_files_s": len(paths) / read_s if read_s else 0,
        "delete_files_s": written / delete_s if delete_s else 0,
    }


def measure_cpu() -> float:
    """A rough single-core score, as a stand-in for MIME parsing throughput."""
    import email.message
    from email import policy
    from email.parser import BytesParser

    msg = email.message.EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Benchmark message"
    msg["Date"] = "Mon, 1 Sep 2025 10:00:00 +0000"
    msg.set_content("Body text with a link http://example.com/path " * 40)
    raw = msg.as_bytes()

    parser = BytesParser(policy=policy.default)
    start = time.perf_counter()
    iterations = 2000
    for _ in range(iterations):
        import io
        parsed = parser.parse(io.BytesIO(raw))
        parsed.get("Subject")
    elapsed = time.perf_counter() - start
    return iterations / elapsed if elapsed else 0


# ---------------------------------------------------------------------------
# projection
# ---------------------------------------------------------------------------
def survey_containers(path: Path) -> dict:
    total = 0
    counts = {}
    for p in path.rglob("*"):
        if p.is_file() and p.suffix.lower() in (".pst", ".ost", ".mbox"):
            try:
                total += p.stat().st_size
            except OSError:
                continue
            counts[p.suffix.lower()] = counts.get(p.suffix.lower(), 0) + 1
    return {"bytes": total, "counts": counts}


def project(corpus_bytes: int, avg_message_kb: float, small: dict,
            seq: dict, parse_per_s: float, cores: int) -> None:
    if not corpus_bytes:
        return
    messages = corpus_bytes / (avg_message_kb * 1024)

    print("PROJECTION")
    print(f"  corpus            : {human(corpus_bytes)}")
    print(f"  assumed avg msg   : {avg_message_kb:.0f}KB "
          f"-> ~{messages:,.0f} messages")
    print()

    read_s = corpus_bytes / (seq["read_mb_s"] * 1024 ** 2) if seq["read_mb_s"] else 0
    write_s = messages / small["write_files_s"] if small["write_files_s"] else 0
    walk_s = messages / small["walk_files_s"] if small["walk_files_s"] else 0
    reread_s = messages / small["read_files_s"] if small["read_files_s"] else 0
    parse_s = messages / (parse_per_s * max(cores - 1, 1))

    print("  extraction")
    print(f"    read containers : {duration(read_s)}")
    print(f"    write .eml      : {duration(write_s)}  <-- usually dominates")
    print("  analysis")
    print(f"    directory walk  : {duration(walk_s)}")
    print(f"    read + parse    : {duration(max(reread_s, parse_s))} "
          f"(io {duration(reread_s)} vs cpu {duration(parse_s)})")
    print()
    print(f"  rough total       : {duration(read_s + write_s + walk_s + max(reread_s, parse_s))}")
    print()
    print("  These are order-of-magnitude figures from a short sample, not a")
    print("  promise. Attachment-heavy mail moves the average message size a")
    print("  long way, and that assumption drives everything above.")
    print()


def verdict(scaling: list, parse_per_s: float, cores: int,
            seq_read_mb_s: float = 0.0) -> None:
    print("WHAT THIS MEANS")
    if len(scaling) < 2:
        return
    base = scaling[0]
    best = max(scaling, key=lambda s: s["write_files_s"])
    ratio = best["write_files_s"] / base["write_files_s"] if base["write_files_s"] else 1

    print(f"  small-file writes: {base['write_files_s']:,.0f}/s at 1 thread, "
          f"{best['write_files_s']:,.0f}/s at {best['threads']} "
          f"({ratio:.1f}x)")
    if ratio < 1.3:
        print("  -> Storage does not reward concurrent writes. Extraction is")
        print("     IO-bound here: keep extraction workers low (2-4) and set")
        print("     POSTMORTEM_MAX_WORKERS accordingly. Extra workers will add")
        print("     contention without adding throughput.")
    elif ratio < 2.5:
        print("  -> Storage rewards concurrency modestly. Extraction workers in")
        print(f"     the {best['threads']} range look right; past that the")
        print("     returns flatten.")
    else:
        print("  -> Storage scales well with concurrency. Let extraction use the")
        print("     detected worker count; CPU will be the limit, not the disk.")
    print()
    print(f"  single-core parse: {parse_per_s:,.0f} messages/s "
          f"-> ~{parse_per_s * max(cores - 1, 1):,.0f}/s across {max(cores - 1, 1)} workers")
    print()

    best_read = max(scaling, key=lambda s: s["read_files_s"])
    seq_ratio = (seq_read_mb_s * 1024) / (best_read["read_files_s"] * SMALL_FILE_KB / 1024) \
        if best_read["read_files_s"] else 0
    print(f"  small-file reads : {base['read_files_s']:,.0f}/s at 1 thread, "
          f"{best_read['read_files_s']:,.0f}/s at {best_read['threads']}")
    if best_read["read_files_s"] < 500:
        print("  -> This is far below what the sequential figure implies. Fast")
        print("     directory walks with slow content reads points at a")
        print("     per-open cost rather than the disk: on-access antivirus or")
        print("     an EDR agent scanning every file as it is opened.")
        print("     Try excluding the container and staging directories from")
        print("     real-time scanning and re-running this benchmark. That is")
        print("     usually worth more than any amount of tuning.")
    print()


# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Measure storage and CPU, and project a postmortem run.")
    ap.add_argument("--path", default=".",
                    help="Directory to benchmark. Use the volume the .eml "
                         "staging directory will live on (default: cwd).")
    ap.add_argument("--containers",
                    help="Directory holding the PST/OST/MBOX files, to size "
                         "the projection from the real corpus.")
    ap.add_argument("--corpus-gb", type=float,
                    help="Corpus size in GB, if --containers is not reachable.")
    ap.add_argument("--avg-message-kb", type=float, default=100.0,
                    help="Assumed average message size (default: 100).")
    ap.add_argument("--threads", default="1,2,4,8",
                    help="Thread counts for the small-file scaling test.")
    args = ap.parse_args()

    path = Path(args.path).expanduser().resolve()
    if not path.is_dir():
        print(f"Not a directory: {path}", file=sys.stderr)
        return 1

    print("=" * 72)
    print("postmortem storage benchmark")
    print("=" * 72)
    print()
    describe_host()
    describe_volume(path)

    workdir = Path(tempfile.mkdtemp(prefix="pm_bench_", dir=path))
    cores = os.cpu_count() or 1
    try:
        print("SEQUENTIAL (bulk container reads)")
        seq = measure_sequential(workdir)
        print(f"  write         : {seq['write_mb_s']:,.0f} MB/s")
        print(f"  read          : {seq['read_mb_s']:,.0f} MB/s "
              "(page cache may inflate this)")
        print()

        print(f"SMALL FILES ({SMALL_FILE_KB}KB each -- this is what extraction does)")
        scaling = []
        for spec in args.threads.split(","):
            spec = spec.strip()
            if not spec.isdigit():
                continue
            n = int(spec)
            if n > cores * 2:
                continue
            result = measure_small_files(workdir, n)
            scaling.append(result)
            print(f"  {n:>2} thread(s)  : "
                  f"write {result['write_files_s']:>8,.0f} files/s "
                  f"({result['write_mb_s']:>6,.1f} MB/s) | "
                  f"walk {result['walk_files_s']:>9,.0f}/s | "
                  f"read {result['read_files_s']:>8,.0f}/s | "
                  f"delete {result['delete_files_s']:>8,.0f}/s")
        print()

        print("CPU (MIME parsing, single core)")
        parse_per_s = measure_cpu()
        print(f"  parse rate    : {parse_per_s:,.0f} messages/s")
        print()

        corpus_bytes = 0
        if args.containers:
            survey = survey_containers(Path(args.containers).expanduser())
            corpus_bytes = survey["bytes"]
            if corpus_bytes:
                kinds = ", ".join(f"{v} x {k}" for k, v in sorted(survey["counts"].items()))
                print(f"CORPUS: {human(corpus_bytes)} ({kinds})\n")
            else:
                print(f"CORPUS: no containers found under {args.containers}\n")
        if not corpus_bytes and args.corpus_gb:
            corpus_bytes = int(args.corpus_gb * 1024 ** 3)

        best = max(scaling, key=lambda s: s["write_files_s"]) if scaling else None
        if best and corpus_bytes:
            project(corpus_bytes, args.avg_message_kb, best, seq,
                    parse_per_s, cores)
        verdict(scaling, parse_per_s, cores, seq['read_mb_s'])
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
        print(f"(cleaned up {workdir})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
