"""Analyzer identity and version.

Why this file exists
--------------------
Every stored analysis records the version of the analyzer that produced it. That
matters for two reasons:

1. Traceability. A report has to say which build produced it, otherwise nobody can
   tell whether a result was made before or after a parser fix.
2. Hygiene. Analyses produced by an older build stay on disk, and a result made
   before a fix can look wrong next to a correct one (for example a session count
   from before the mail-only traffic filter was added). ``scripts\\clear_analyses.ps1``
   compares the stored version with ``ANALYZER_VERSION`` and can remove the old
   ones instead of exporting them.

Bump ``ANALYZER_VERSION`` whenever a change alters analysis output: the parser,
the rules, the scoring, the feature set or the report layout.
"""

from __future__ import annotations

ANALYZER_NAME = "SecureMailScope"
ANALYZER_VERSION = "1.0.0"

# Human-readable note shown next to the version so a stored result explains itself.
ANALYZER_VERSION_NOTE = "mail-only session filter, evidence-qualified TLS and certificate rules"
