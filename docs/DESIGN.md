# Design notes: why the dashboard and the reports look the way they do

The analysis was finished first, so the interface had one job: make the evidence readable in
the ten seconds a judge or an analyst actually spends on it, without hiding anything. This
file records the decisions, and the two layout bugs that were fixed, so the reasoning survives
the next person who touches the CSS.

---

## The dashboard

**One verdict first, detail behind tabs.** The top band answers three questions in one line:
how bad is this capture (posture ring + worst-session class), how much was looked at (sessions,
upgrades, findings), and how complete the evidence is. Everything else lives in four tabs -
Overview, Findings, Sessions, Actions - so a capture with 70 findings is a tab, not a
kilometre of scrolling.

**The list says what the number means.** Each stored analysis is one card with its class,
posture, session count and provenance. Three states are deliberately distinct, because
conflating them would be a false all-clear:

| State | Shown as | Why |
|---|---|---|
| Sessions scored | Class pill + posture score | The normal case |
| Encrypted, protocol unprovable | `UNCLASSIFIED` + what was seen | Implicit TLS on an unknown port hides the protocol. Reporting a posture would claim something that was never established |
| Nothing to score | `NO MAIL SESSIONS` | An empty, truncated or non-mail capture is not a low-risk capture |

**The ML column is marked as a hint, not an answer.** Where the triage class disagrees with the
rule class, the cell shows a warning sign and a tooltip. It is never silently picked as the
result, and the finding stays the evidence.

**Filters instead of more pages.** One input filters both the findings and the sessions, so the
common question - "what happened on the IMAP sessions on port 143?" - is typing, not scrolling.

**The ring, the bars, the colour.** Posture is one number in one ring; the severity
distribution is a short bar chart with a one-line explanation per band, because a judge who
does not know what MEDIUM means should not have to ask. Colour is used only for severity and
state; nothing else competes for attention.

**Nothing loads from the internet.** No CDN, no web font, no icon package. A capture from an
organisation must never cause a request to a third party, and the page has to work on a machine
with no network. It is one HTML file with inline CSS and vanilla JavaScript, served by the
backend itself, calling the same public API a separate frontend would call - so a React/Vue
frontend can replace it without touching the backend.

**It was tested as a deliverable.** Twelve tests cover it: served as HTML, no external
references, the documented endpoints, the three empty-capture states, the unprovable-protocol
explanation, the session-row cap, and - new - that the inline JavaScript **parses**. That last
one exists because a syntax error in the inline script still returns HTTP 200 and still passes
every string-based test: it only breaks in a browser. One such error reached a screenshot
before this test existed.

---

## The PDF report (the two bugs, and the redesign)

**Bug 1: the columns overlapped.** The finding table passed plain strings and a fixed
`colWidths` to ReportLab. A plain string cannot wrap, so a long evidence line overflowed into
the next column and the recommendation ran off the page edge - which is exactly what the
submission screenshot showed.

**Bug 2: the table could be wider than the page.** The widths were fixed millimetre values that
happened to fit A4 landscape. Any page-size or margin change would have pushed the last column
off the paper.

Both are fixed the same way: **every cell is a `Paragraph`**, which wraps, and **the column
widths are derived from the frame width**, so the table can never exceed it.

**The document now reads in order of importance:**

1. Title, source file, provenance, SHA-256, risk and posture.
2. A metric strip: posture, risk, sessions, upgrades, findings, evidence completeness.
3. Finding severity, with one line per band explaining what it means, next to the capture facts
   (protocols, TLS versions, cipher suites).
4. Prioritised findings, each with severity, title, description, evidence and the fix.
5. Sessions, highest risk first, in a one-line-per-row table.
6. Recommended actions, numbered.
7. A closing statement of what the report does **not** claim.

**Honesty is part of the design.** The cap on findings (40 in the PDF, 60 in the session table)
is printed in the document with a pointer to the complete HTML and JSON exports, because a
reviewer comparing formats must be able to tell a stated limit from a bug. The footer of every
page carries "no email content was read or decrypted", and the closing section states that
missing evidence is reported as UNKNOWN rather than as a weakness.

---

## Design tokens

Both the dashboard and the HTML report use one palette and one spacing scale, so the two look
like the same product:

| Token | Value | Used for |
|---|---|---|
| Background | `#0b1220` / `#121c2d` | Page, panel (dark UI) |
| Ink / body | `#0b1f33` / `#1f2a37` | Headings, text (reports) |
| Accent | `#1d4ed8` (report) · `#4f8cff` (dashboard) | Links, buttons, focus |
| CRITICAL | `#b42318` (print) · `#ff5c5c` (screen) | Severity |
| HIGH | `#c2410c` · `#ff9a4d` | Severity |
| MEDIUM | `#a16207` · `#f5c451` | Severity |
| LOW | `#15803d` · `#46d39a` | Severity |
| INFO | `#64748b` · `#8194ad` | Context, unobserved evidence |

Print and screen use different shades on purpose: a saturated red that reads as "alarm" on a
dark screen is hard to print legibly on white paper.

---

## Files

| File | Role |
|---|---|
| `app/dashboard.py` | The dashboard: one HTML file, inline CSS and JavaScript |
| `app/reports.py` | JSON, HTML and PDF renderers, sharing one palette |
| `tools/build_dashboard_snapshot.py` | Single-file offline dashboard with the analyses embedded |
| `docs/screenshots/` | Generated screenshots, sample reports and the offline snapshot |
| `tests/test_dashboard.py` | 12 tests, including the JavaScript parse check |

Regeneration commands are in `docs\screenshots\README.md`.
