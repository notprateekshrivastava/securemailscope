"""Assemble a publishable dataset release: captures, feature tables and a datasheet.

Why this exists
---------------
"Can we use Kaggle?" has two useful halves, and only one of them is about training:

1. **Using** data. Public labelled mail-TLS-posture data does not exist to use. The
   captures we need are not downloadable; they have to be produced. So the honest
   use of an external corpus is scale and robustness testing, not labels.
2. **Publishing** data. We can contribute one, and it is ours to publish: captures
   we generated ourselves on loopback with known, deliberately varied configurations,
   plus the session feature table extracted from them. That is a legitimate artefact
   with a clear provenance story and no third-party content.

This script produces that release in one folder:

    dist\\dataset_v1\\
        README.md                 what this is, in plain language
        DATASHEET.md              datasheet-for-datasets style documentation
        captures\\                 one .pcapng per scenario
        session_features.csv      one row per session, 26 features + labels
        captures.csv              one row per capture
        dataset_metadata.json     versions, counts, hashes, generation parameters

Nothing here contains a capture from the organisation, an email address, an IP
address outside loopback, or any message body.

Usage
-----
    python tools\\make_dataset_release.py
    python tools\\make_dataset_release.py --out dist\\dataset_v1 --scenarios 3
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.version import ANALYZER_VERSION  # noqa: E402

DATASHEET = """# Datasheet: SecureMailScope mail-TLS posture corpus

Following the "Datasheets for Datasets" structure, so a reader can judge whether this
data is appropriate for their use before downloading it.

## Motivation

Why was the dataset created?
: To make mail encryption posture machine-analysable. Public captures of mail traffic
  exist, but they do not come with labels describing the security configuration that
  was in effect, so a model cannot learn from them. We generated mail sessions with
  deliberately varied, known configurations and captured them, which gives every
  session a ground-truth description of how it was configured.

Who created it and who funded it?
: The SecureMailScope team, for the Smart India Hackathon problem statement on passive
  mail security posture assessment. No external funding.

## Composition

What do the instances represent?
: One instance is one email session (SMTP, IMAP or POP3 including their TLS variants)
  between a client and a server on the loopback interface. Each instance is described
  by 26 numeric features extracted by a passive parser, plus the risk class assigned
  by an explainable rule engine.

How many instances are there?
: See `dataset_metadata.json` for the exact counts of captures and sessions in this
  release. Every capture here was produced by the toolkit in this repository.

What data does each instance contain?
: Traffic metadata only. Session timing, packet and byte counts, protocol, the
  negated TLS version and cipher suite, key exchange and forward secrecy, STARTTLS or
  STLS negotiation outcome, X.509 certificate properties and validation results, and
  the resulting findings. `session_features.csv` also lists which rule findings fired.

Is it complete?
: It is complete for the scenarios listed below and nothing else. It does not cover
  real-world traffic mixes, other protocols, or mail servers we did not configure.

What is deliberately absent?
: Message bodies, credentials, and personal data. The captures contain no email
  content: the toolkit sends fixed protocol commands and no message text. All
  addresses are loopback (127.0.0.1) and the certificates are self-signed
  certificates generated for the test, with names such as `mail.lab.test`.

Does it contain confidential data?
: No. Nothing in this release was captured from a real network, a real mail server or
  an organisation's infrastructure.

## Collection process

How was the data acquired?
: A mock mail server and client were run on loopback with a chosen TLS or STARTTLS
  configuration, and the session was captured with TShark on the loopback interface.
  The exact commands are in `tools\\lab_capture_toolkit.py`.

Who collected it and how were they compensated?
: The team, as part of the project. The toolkit is deterministic and re-runnable.

Over what timeframe?
: Generated on the date recorded in `dataset_metadata.json`. Each release is
  reproducible from the toolkit.

Were ethical review processes conducted?
: Not applicable: loopback only, no third-party or personal data, no real traffic.

## Preprocessing and labelling

Was the raw data processed?
: Yes. The raw captures are included unmodified; the feature table is derived from
  them by the parser in `app/analysis/tshark.py`.

How were labels assigned?
: **Weak supervision.** Labels are the output of the explainable rule engine, not a
  human judgement and not a ground-truth security assessment. This is the single most
  important limitation: a model trained on this data learns to imitate our rules, so
  it should be used for triage and anomaly ranking, never as the final verdict.

Are the labels validated?
: The rules were checked against known-configuration captures: each capture's intended
  configuration is compared with the findings that fired, and a mismatch is reported
  as a failure. See `samples\\lab\\EXPECTED_RESULTS.md`.

## Uses

What is it useful for?
: Reproducing and stress-testing passive mail-TLS posture analysis; training and
  evaluating triage models; teaching how mail STARTTLS and TLS configuration appears
  on the wire; regression testing a parser.

What should it not be used for?
: Measuring real-world attack rates. Treating the rule-engine label as an expert
  security assessment. Comparing organisations. Any claim about a specific network.

## Distribution and maintenance

How is it distributed?
: Publicly, with the repository, under the MIT licence. Captures are `.pcapng` files
  readable in Wireshark.

Will it be updated?
: Yes, when the toolkit gains scenarios. The version is in `dataset_metadata.json`.

## Citation

    SecureMailScope mail-TLS posture corpus, version {version}
    Generated with SecureMailScope {analyzer_version}
"""

README = """# SecureMailScope mail-TLS posture corpus

Email sessions captured on loopback with deliberately varied TLS and STARTTLS
configurations, together with a feature table extracted from them by a passive
parser.

## Why this dataset exists

If you want a model that can judge how well an email session is encrypted, you need
examples where you know the true configuration. Real captures rarely come with that.
So we configured mail servers on purpose - old TLS versions, static RSA, CBC, NULL
ciphers, weak keys, expired certificates, rejected STARTTLS, cleartext logins - and
captured what happened on the wire.

## Files

| File | Contents |
|---|---|
| `captures/` | One `.pcapng` per scenario, readable in Wireshark |
| `session_features.csv` | One row per email session: 26 numeric features plus the risk class from the rule engine |
| `captures.csv` | One row per capture: session counts, findings by severity, posture score |
| `dataset_metadata.json` | Versions, counts, generation parameters and file hashes |
| `DATASHEET.md` | What this data is, how it was made, and what it must not be used for |

## Read this before training on it

The labels are **weak supervision**: they are the output of an explainable rule
engine, not a human security assessment. A model trained here learns to imitate our
rules. That is useful for triage and for ranking sessions - it is not a substitute
for the rules themselves and it is not a measurement of the real world.

## Privacy

No message bodies, no credentials, no real network traffic, no third-party data. All
traffic is loopback with self-signed test certificates. See `DATASHEET.md`.

## Reproduce it

```powershell
python tools\\lab_capture_toolkit.py certs
python tools\\lab_capture_toolkit.py capture
python -m app.cli batch samples --out data\\batch
python tools\\make_dataset_release.py
```
"""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a publishable dataset release")
    parser.add_argument("--out", default=str(PROJECT_ROOT / "dist" / "dataset_v1"))
    parser.add_argument("--captures", default=str(PROJECT_ROOT / "samples"))
    parser.add_argument("--batch", default=str(PROJECT_ROOT / "data" / "batch"))
    parser.add_argument("--version", default="1.0")
    parser.add_argument(
        "--include-third-party",
        action="store_true",
        help="also copy captures we do not own into a clearly labelled folder (never publish those as the dataset)",
    )
    args = parser.parse_args(argv)

    out = Path(args.out)
    captures_dir = out / "captures"
    if out.exists():
        shutil.rmtree(out)
    captures_dir.mkdir(parents=True, exist_ok=True)

    source_dir = Path(args.captures)
    # Captures produced by our own toolkit live under samples\lab. Anything else in
    # the samples tree was written by someone else and is not ours to redistribute.
    lab_dir = source_dir / "lab"
    search_dirs = [lab_dir] if lab_dir.exists() else [source_dir]

    copied: list[dict[str, object]] = []
    excluded: list[str] = []
    for search in search_dirs:
        for path in sorted(search.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in {".pcapng", ".pcap", ".cap"}:
                continue
            target = captures_dir / path.name
            shutil.copy2(path, target)
            copied.append({"file": path.name, "bytes": target.stat().st_size, "sha256": sha256(target)})

    if args.include_third_party:
        third = out / "third_party_captures"
        third.mkdir(exist_ok=True)
        for path in sorted(source_dir.glob("*")):
            if path.is_file() and path.suffix.lower() in {".pcapng", ".pcap", ".cap"}:
                shutil.copy2(path, third / path.name)
        for path in sorted(source_dir.rglob("*")):
            if path.is_file() and path.suffix.lower() in {".pcapng", ".pcap", ".cap"} and "lab" not in path.parts:
                if path.parent == source_dir:
                    continue
                shutil.copy2(path, third / path.name)
        third_note = third / "SOURCE.md"
        third_note.write_text(
            "# Third-party captures (not ours)\n\n"
            "These files were downloaded from public sources and are **not** part of our\n"
            "dataset. They are included only to make the local reproduction path complete.\n"
            "Do not publish them as our data; each remains the property of its author.\n\n"
            "| File | Source |\n|---|---|\n"
            "| `smtp-ssl.pcapng`, `imap-ssl.pcapng`, `pop-ssl.pcapng` | https://github.com/Lekensteyn/wireshark-notes (tls/) |\n"
            "| `The-Ultimate-PCAP.pcapng` | https://weberblog.net/the-ultimate-pcap/ |\n",
            encoding="utf-8",
        )
        excluded = ["third_party_captures/ is quarantined and clearly labelled, not part of the dataset"]

    if not copied:
        print(f"No captures found under {lab_dir}. Generate them first:")
        print("  python tools\\lab_capture_toolkit.py capture")
        return 2

    batch = Path(args.batch)
    features_src = batch / "session_features.csv"
    summary_src = batch / "captures.csv"
    if not features_src.exists():
        print(f"No feature table at {features_src}")
        print("Run this first:  python -m app.cli batch samples --out data\\batch")
        return 2

    # The feature table must describe exactly the captures that ship with it. Copying
    # it whole would leave rows from captures that are not in captures/ (including
    # third-party ones), which a reviewer would rightly flag as inconsistent.
    included = {str(item["file"]) for item in copied}
    all_rows = list(csv.DictReader(features_src.open(encoding="utf-8")))
    rows = [row for row in all_rows if row.get("capture") in included]
    dropped = len(all_rows) - len(rows)

    if rows:
        fieldnames = list(all_rows[0].keys())
        with (out / "session_features.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
    else:
        (out / "session_features.csv").write_text("", encoding="utf-8")

    if summary_src.exists():
        summary_rows = [
            row for row in csv.DictReader(summary_src.open(encoding="utf-8"))
            if row.get("capture") in included
        ]
        if summary_rows:
            with (out / "captures.csv").open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(summary_rows[0].keys()))
                writer.writeheader()
                writer.writerows(summary_rows)
    labels: dict[str, int] = {}
    for row in rows:
        labels[row.get("risk_label", "?")] = labels.get(row.get("risk_label", "?"), 0) + 1

    metadata = {
        "dataset": "SecureMailScope mail-TLS posture corpus",
        "dataset_version": args.version,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "analyzer_version": ANALYZER_VERSION,
        "captures": len(copied),
        "sessions": len(rows),
        "feature_rows_dropped_from_other_captures": dropped,
        "label_source": "explainable rule engine (weak supervision, not human ground truth)",
        "label_distribution": labels,
        "privacy": "loopback traffic only; no message bodies; no credentials; self-signed test certificates",
        "licence": "MIT",
        "provenance": "every file under captures/ was generated by tools\\lab_capture_toolkit.py on this machine",
        "third_party_excluded": excluded or None,
        "capture_files": copied,
        "reproduce": [
            "python tools\\lab_capture_toolkit.py certs",
            "python tools\\lab_capture_toolkit.py capture",
            "python -m app.cli batch samples --out data\\batch",
            "python tools\\make_dataset_release.py",
        ],
    }
    (out / "dataset_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (out / "README.md").write_text(README, encoding="utf-8")
    (out / "DATASHEET.md").write_text(
        DATASHEET.format(version=args.version, analyzer_version=ANALYZER_VERSION), encoding="utf-8"
    )

    total_bytes = sum(int(item["bytes"]) for item in copied)
    print(f"Dataset release written to {out}")
    print(f"  captures           : {len(copied)} ({total_bytes / 1024:.0f} KB)")
    print(f"  sessions           : {len(rows)}" + (f"  ({dropped} row(s) dropped: captures not in this release)" if dropped else ""))
    print(f"  label distribution : {labels}")
    print(f"  files              : README.md, DATASHEET.md, dataset_metadata.json, "
          f"session_features.csv" + (", captures.csv" if summary_src.exists() else ""))
    print()
    print("Uploading to Kaggle:")
    print("  pip install kaggle")
    print(f"  kaggle datasets create -p {out} --dir-mode zip")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
