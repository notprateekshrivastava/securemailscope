#!/usr/bin/env python3
"""Build large captures for scale testing and demos, from our own lab captures.

What this produces
------------------
A single capture containing the lab scenarios repeated many times, with the timestamps of
each repetition shifted so the result reads as one long recording rather than fifteen
overlapping ones. It is used to answer the questions a judge will ask about scale:

    how long does a 15 MB capture take?          (measured: see docs\\SCALE_AND_ML.md)
    how many sessions can one file hold?
    does the report still render at that size?

    python tools\\make_stress_capture.py --repeat 20  --out samples\\stress\\medium.pcapng
    python tools\\make_stress_capture.py --repeat 200 --out samples\\stress\\large.pcapng

What this is NOT
----------------
This data is synthetic in the strict sense: it adds no new *information*. The same fifteen
conversations appear over and over, so it is a load test, not new coverage.

**Do not train on these files.** Analysing them and feeding the model the result would
duplicate the same sessions hundreds of times, which is the opposite of the diversity that
was measured to be the thing that improves the model (see docs\\TRAINING_PLAYBOOK.md
section 1: four times the rows changed nothing, six new captures moved the result). The
training loader reads `samples\\` and `samples\\lab\\`, so writing stress captures into
`samples\\stress\\` keeps them out of training by default - and this tool refuses to write
into `samples\\lab\\` for that reason.

Requirements: `editcap` and `mergecap`, which ship with Wireshark alongside `tshark`. The
tool looks for them next to `tshark` first, which is where the Windows installer puts them.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.analysis.tshark import tshark_binary  # noqa: E402

DEFAULT_SOURCES = PROJECT_ROOT / "samples" / "lab"
STRESS_DIR = PROJECT_ROOT / "samples" / "stress"


def find_sibling(name: str) -> str | None:
    """Locate editcap/mergecap, preferring the copy next to tshark.

    On Windows the Wireshark installer adds its program folder to PATH, so a bare name
    works, but a portable or zip install may not. Looking next to the known tshark binary
    first makes the toolkit work in both layouts.
    """
    try:
        beside = Path(tshark_binary()).with_name(name)
        if beside.exists():
            return str(beside)
    except Exception:
        pass
    found = shutil.which(name)
    return found


def run(command: list[str]) -> None:
    done = subprocess.run(command, capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError(f"{command[0]} failed: {done.stderr.strip()[-300:]}")


def build(out_path: Path, sources: list[Path], repeat: int, shift: int) -> dict[str, object]:
    editcap = find_sibling("editcap")
    mergecap = find_sibling("mergecap")
    if not editcap or not mergecap:
        raise RuntimeError(
            "editcap and mergecap are required and were not found. They ship with Wireshark, "
            "in the same folder as tshark. Install Wireshark, or add its program folder to PATH."
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    pieces: list[Path] = []
    with tempfile.TemporaryDirectory(prefix="sms-stress-") as tmp:
        staging = Path(tmp)
        # One pass over the source set first, so each repetition is a single file. Shifting
        # 15 files 200 times would spawn 3,000 processes; this way it spawns 401, which
        # matters on Windows where process start-up is the slow part.
        combined = staging / "source-set.pcapng"
        run([mergecap, "-w", str(combined), *[str(source) for source in sources]])

        for round_index in range(repeat):
            # A distinct file per repetition: mergecap treats two identical paths as one
            # input and silently drops the duplicate.
            destination = staging / f"round-{round_index:04d}.pcapng"
            run([editcap, "-t", str(round_index * shift), str(combined), str(destination)])
            pieces.append(destination)
        run([mergecap, "-w", str(out_path), *[str(piece) for piece in pieces]])

    return {
        "captures_merged": len(pieces) * len(sources),
        "bytes": out_path.stat().st_size,
    }


def describe(out_path: Path) -> None:
    """Report what was actually written, using TShark rather than our own assumptions."""
    packets = subprocess.run(
        [tshark_binary(), "-n", "-r", str(out_path), "-T", "fields", "-e", "frame.number"],
        capture_output=True,
        text=True,
    )
    packet_count = len([line for line in packets.stdout.splitlines() if line.strip()])

    sys.path.insert(0, str(PROJECT_ROOT))
    from app.analysis.assessment import apply_policy_assessment, build_summary
    from app.analysis.tshark import analyze_pcap

    import time

    started = time.perf_counter()
    # apply_policy_assessment is what turns parsed evidence into findings. Without it the
    # summary of a capture full of TLS 1.0 and weak certificates reads "LOW, 0 findings" -
    # a false all-clear printed by the tool that measures such things.
    sessions = [apply_policy_assessment(session) for session in analyze_pcap(out_path)]
    elapsed = time.perf_counter() - started
    summary = build_summary(sessions)

    print(f"  file            : {out_path}")
    print(f"  size            : {out_path.stat().st_size / 1_048_576:.2f} MB ({packet_count} packets)")
    print(f"  email sessions  : {len(sessions)}")
    print(f"  parse time      : {elapsed:.2f} s  ({len(sessions) / elapsed:.0f} sessions/second)")
    print(f"  worst class     : {summary.overall_risk_class}  posture {summary.overall_posture_score}/100")
    print(f"  findings        : {summary.total_findings}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="capture to write")
    parser.add_argument("--repeat", type=int, default=20, help="how many times to repeat the set")
    parser.add_argument(
        "--sources",
        default=str(DEFAULT_SOURCES),
        help="folder or glob of captures to repeat (default: samples/lab)",
    )
    parser.add_argument(
        "--shift",
        type=int,
        default=120,
        help="seconds added per repetition, so the file reads as one long recording",
    )
    args = parser.parse_args(argv)

    out_path = Path(args.out)
    if out_path.suffix not in {".pcapng", ".pcap", ".cap"}:
        print("--out must end in .pcapng, .pcap or .cap")
        return 2

    # Guard: enlarging the training set by duplication is the one thing this tool must not
    # be used for, and samples/lab is what the trainer reads.
    try:
        out_path.resolve().relative_to((PROJECT_ROOT / "samples" / "lab").resolve())
    except ValueError:
        pass
    else:
        print("Refusing to write into samples\\lab: the trainer reads that folder.")
        print("Stress captures belong in samples\\stress\\ and are not training data.")
        return 2

    sources_dir = Path(args.sources)
    if sources_dir.is_dir():
        sources = sorted(sources_dir.glob("*.pcapng")) + sorted(sources_dir.glob("*.pcap"))
    else:
        sources = sorted(PROJECT_ROOT.glob(args.sources))
    if not sources:
        print(f"No captures found in {args.sources}")
        return 2
    if args.repeat < 1:
        print("--repeat must be at least 1")
        return 2

    print(f"Merging {len(sources)} capture(s) x {args.repeat} = {len(sources) * args.repeat} inputs")
    info = build(out_path, sources, args.repeat, args.shift)
    print(f"Wrote {info['bytes'] / 1_048_576:.2f} MB from {info['captures_merged']} inputs")
    describe(out_path)
    print()
    print("This file is for scale testing and demos. Do NOT train on it: it repeats the")
    print("same conversations, and duplicated rows were measured to add nothing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
