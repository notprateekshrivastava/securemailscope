"""Build a single offline HTML file of the dashboard with the stored analyses embedded.

Why this exists
---------------
The live dashboard needs a running API. Two situations where that is inconvenient:

* You want screenshots for the slide deck, or a judge wants to open the dashboard
  on a laptop with nothing installed.
* You want to hand over one file that shows the real results without giving anyone
  the capture data or a server to run.

The file produced here contains the same interface as ``/dashboard``, with the
results of the analyses stored in ``data\\analyses\\`` embedded as JSON. It has no
external references, so it opens from a USB stick with no network at all.

Usage
-----
    python tools\\build_dashboard_snapshot.py
    python tools\\build_dashboard_snapshot.py --output reports\\dashboard_snapshot.html
    python tools\\build_dashboard_snapshot.py --stale-only        # tiny file, old results only
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.dashboard import render_dashboard  # noqa: E402
from app.version import ANALYZER_VERSION  # noqa: E402


def load_analyses(directory: Path, include_stale: bool = False) -> list[dict]:
    """Read the stored analyses, newest first, skipping ones from older builds."""
    results: list[dict] = []
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not include_stale and data.get("analyzer_version") != ANALYZER_VERSION:
            continue
        results.append(data)
    results.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)
    return results


def build(output: Path, directory: Path, include_stale: bool = False, health: dict | None = None) -> tuple[Path, int]:
    analyses = load_analyses(directory, include_stale=include_stale)
    snapshot = {
        "generated_at": __import__("datetime").datetime.now().astimezone().isoformat(timespec="seconds"),
        "analyzer_version": ANALYZER_VERSION,
        "health": health or {"status": "snapshot", "version": ANALYZER_VERSION,
                             "ml_model_status": "see models/model_metadata.json"},
        "analyses": analyses,
    }
    page = render_dashboard()
    injection = (
        "<script>window.__SECUREMAILSCOPE_SNAPSHOT__ = "
        + json.dumps(snapshot, ensure_ascii=False).replace("</", "<\\/")
        + ";</script>\n"
    )
    # Inject before the dashboard script so the data exists when the page runs.
    marker = "<script>\n(function () {"
    if marker not in page:
        raise RuntimeError("dashboard script marker not found - update the injection point")
    page = page.replace(marker, injection + marker, 1)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(page, encoding="utf-8")
    return output, len(analyses)


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline dashboard snapshot with embedded results")
    parser.add_argument("--data-dir", default=str(PROJECT_ROOT / "data" / "analyses"))
    parser.add_argument("--output", default=str(PROJECT_ROOT / "reports" / "dashboard_snapshot.html"))
    parser.add_argument("--stale-only", action="store_true",
                        help="include results from older analyzer versions too (not recommended)")
    args = parser.parse_args()

    output, count = build(Path(args.output), Path(args.data_dir), include_stale=args.stale_only)
    size_kb = output.stat().st_size / 1024
    print(f"Wrote {output}")
    print(f"Analyses embedded: {count} (analyzer version {ANALYZER_VERSION})")
    print(f"Size: {size_kb:.0f} KB - one file, no server and no network needed")
    if count == 0:
        print("Note: no stored analyses matched. Run restart_and_test.ps1 first to create some.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
