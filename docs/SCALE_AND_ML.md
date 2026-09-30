# Scale, and the honest ML numbers

This document records what the machine learning layer actually does, what was
measured, and what it must not be used to claim. Every number here was produced by
running the code in this repository; the commands are given so anyone can repeat them.

---

## 1. Heavy data processing: what "scale" means here

A bigger model was never the bottleneck. Two things were: **throughput** (many
captures at once) and **labelled data** (only so many sessions have known
configurations). The batch analyser addresses the first, and it is also the tool that
addresses the second, because the rule engine can label any capture it can parse.

### What was added

| Piece | What it does |
|---|---|
| `app/analysis/batch.py` | Analyses a whole directory tree in parallel. One process per capture (TShark is a separate OS process, so processes - not threads - are what give real parallelism), a bounded number of workers, results written as JSON Lines the moment each capture finishes so a crash never loses completed work, plus a flat CSV summary |
| `app/cli.py` | `batch`, `export`, `doctor` and `verify` subcommands, so the whole pipeline can be scripted or run in CI |
| `session_features.csv` | One row per session: 26 numeric features plus the rule label, ML label, risk score and finding codes. This is the training set and the analysis table in one artefact |

### Measured

```powershell
python -m app.cli batch samples --out data\batch --workers 2
```

```
captures            : 13 analysed, 0 failed
sessions            : 63
session feature rows: 63
wall clock          : 6.6s        (2 CPU cores)
```

Every capture in this repository, including a 14.88 MB mixed-protocol capture, is
parsed in a few seconds. The per-capture record is a summary plus one row per session,
not the full nested document - the earlier attempt to serialise everything produced a
141 MB JSON for that one capture, which is why the flat schema exists.

### Measured with the generated stress captures

`tools/make_stress_capture.py` builds large files by repeating the fifteen lab captures
with time-shifted timestamps, so their size is adjustable on any machine:

```powershell
python tools\make_stress_capture.py --repeat 20  --out samples\stress\medium.pcapng
python tools\make_stress_capture.py --repeat 200 --out samples\stress\large.pcapng
```

| File | Size | Sessions | Findings | CLI parse | API upload (synchronous) | Analysis JSON the browser fetches |
|---|---|---|---|---|---|---|
| `medium.pcapng` | 1.49 MB | 300 | 560 | **11 s** | **24 s** | 1.4 MB |
| `large.pcapng` | 14.72 MB | 3000 | 5600 | **105 s** | **236 s** | **13.0 MB** |
| `The-Ultimate-PCAP.pcapng` (third party, mixed protocols) | 14.88 MB | 51 | 60 | ~3.5 s | 5.3 s | - |

Reports for the 3,000-session capture: JSON 17.9 MB in 0.6 s, HTML 1.4 MB in 0.3 s,
PDF 7 KB in 0.6 s. The PDF lists the 40 most severe findings and now **states that it is
showing 40 of 5,600** - a silent cap would look like a report that lost evidence.

Two things this measurement changed in the product:

* **The list endpoint was downloading everything.** `GET /api/v1/analyses` returned
  16.6 MB for eight stored analyses, because each item carried every session. It now
  accepts `?summary_only=true` (0.01 MB, same summary) and the dashboard uses it; the full
  record is fetched only for the capture that was opened. Any new frontend must do the same -
  see `FRONTEND_API.md`.
* **The dashboard table is capped** at the 200 highest-risk sessions with a visible note
  about the rest, instead of rendering 3,000 rows.

**Say this:** "A single capture with 3,000 mail sessions and 5,600 findings is parsed in
under two minutes, and the batch path does 24 captures in parallel." 

**Do not say this:** "It handles any volume." Throughput is about 28 sessions per second on
two cores, and the synchronous upload call blocks for the whole analysis, so a
multi-gigabyte capture needs the batch path and patience.

The stress captures are load tests, **not training data**: they repeat the same fifteen
conversations, and duplicated rows were measured to add nothing to the model. The tool
refuses to write into `samples\lab` for that reason, and the trainer does not read
`samples\stress`.

### Scaling further

* More workers: `--workers 8` on an 8-core machine. The work is CPU-bound inside
  TShark, so this scales close to linearly until the disk becomes the limit.
* More captures: the batch walker takes any directory tree, so a corpus of thousands
  of files is the same command.
* Resume: `--resume` skips captures already present in `captures.jsonl`.

---

## 2. The ML layer: what it is, and what it is not

* **Risk classifier** - Random Forest over 26 numeric session features.
* **Anomaly detector** - Isolation Forest, trained on the secure-looking portion of
  the synthetic rows.
* **Labels** - the explainable rule engine's verdict for each session. This is
  **weak supervision**: the model learns to imitate rules, it does not learn a
  security truth.
* **Role** - triage and ranking. The findings, not the model, are the evidence.

### In-sample and holdout - both published, as required

The dataset is small, so the in-sample score alone proves nothing and the holdout score alone
can look thin. Both are therefore published here, printed by every training run, and written
into `models\model_metadata.json` so they travel with the model instead of living in a slide.

| Measurement | What it means | Value |
|---|---|---|
| **In-sample (`capture_calibration`)** | Rule agreement on real captures **that were used in training** - a consistency check, not evidence | **90/90** |
| **Holdout (`capture_holdout`)** | **Leave-one-capture-out: a whole capture is held out, so no session from it helped training** | **82/90 = 91.1%** |
| **Transfer (`synthetic_transfer`)** | **Trained on synthetic rows only, tested on real captures - not one real session seen** | **78/90 = 86.7%** |
| Synthetic validation accuracy | Held-out 20% of the synthetic scenario rows - measures the generator, not reality | 0.983 |

Quote the holdout and the transfer numbers. The 90/90 in-sample figure is a consistency
check: those rows trained the model.

**How the 90 rows are made up (so the size is auditable):** 15 hand-written lab captures,
42 systematic sweep captures (21 of which contain sessions), and 4 third-party captures
(3 Wireshark fixtures plus one aggregate capture). 61 files scanned, 40 with mail sessions.

---

### Is the number good? The baseline, and why not 95%

| Measure | Value | How it is computed |
|---|---|---|
| **Majority-class baseline** | 44/90 = **48.9%** | always predict MEDIUM; what a useless model scores |
| Holdout on the curated set only | 61/69 = 88.4% | the 19 hand-written/third-party captures, unchanged by the sweep |

**+42.2 points over the trivial baseline**, and the two confidence intervals do not overlap:

| | Accuracy | 95% CI |
|---|---|---|
| Our model | 91.1% | **[85.2%, 97.0%]** |
| Majority-class baseline | 48.9% | [38.6%, 59.2%] |

### Where the 91.1% comes from, honestly decomposed

The systematic sweep added 21 training sessions whose **siblings remain in training** (same
TLS profile, different protocol or port), so they are easier to classify than a truly unseen
capture. Decomposed:

| Test set | Rows | Correct | Note |
|---|---|---|---|
| Sweep captures (systematic combinations) | 21 | 21 | near-twins of each other - the least demanding rows |
| Curated + third-party captures | 69 | 61 | the number to compare against the previous 60/69 |

So the honest reading is: **the sweep improved our own curated set from 60/69 to 61/69
(+1.4 points) and raised the headline from 87.0% to 91.1%**, most of the difference being a
measurement effect rather than new skill. Both numbers are published because a reviewer
comparing the two would otherwise think the jump was hidden. What the sweep genuinely bought
is **class balance** (CRITICAL 13% -> 23% of rows), one fixed error
(`smtp-starttls-secure` is no longer called CRITICAL), and 3x more evidence that the model
works on combinations nobody hand-picked.

### "Why 91% and not 95%?"

Because at this sample size the question is not meaningful yet, and saying so is stronger
than chasing the number:

* **One row is worth 1.1 points.** With 90 rows, a 95% claim allows at most 4 misses; we have
  8. Two of our eight misses are the same boundary judgement repeated on one capture.
* **95% is inside our confidence interval.** Our result is 91.1% ± 5.9 points, so 95% is
  statistically compatible with what we measured. The honest statement is "91%, and the
  uncertainty is about six points", not "we are 91% and not 95%".
* **Reaching ±3 points of certainty needs roughly 350 rows; ±2 points needs about 780.** We
  have 90. Tuning the classifier until the number reads 95% on 90 rows would be fitting the
  test set, and it would not survive a single new capture.
* **The ceiling is partly the rules.** The model is trained on rule-engine labels (weak
  supervision), so it imitates the rules rather than outperforming them. Where the two
  disagree, the rule engine is the evidence; the model is a triage layer. A model that
  scored 100% here would only prove it had memorised the rules.

**The right way to answer a judge who asks "why not 95%?":**

> "Because 90 sessions is not enough to distinguish 91% from 95% - our confidence interval is
> about six points wide, and one row moves the number by more than a point. What we can say
> is that we are 42 points above a majority-class guess, that the intervals do not overlap,
> and that eight of our nine errors warn too much rather than too little. The lever is more
> captures, not more tuning: four times the training rows changed nothing, while six more
> diverse captures moved the number."

### The one error that goes the wrong way

| Capture | Rows | Rules say | Model said | Direction |
|---|---|---|---|---|
| `The-Ultimate-PCAP.pcapng` (7 rows) | 51 | LOW | MEDIUM | over-warns |
| `imap-cleartext-login.pcapng` (1 row) | 1 | CRITICAL | HIGH | **under-warns - disclose this one first** |
| `smtp-starttls-secure.pcapng` | 1 | LOW | CRITICAL | over-warns *(fixed by the sweep)* |

**What this number is not.** It is agreement with our own rule engine, not accuracy against
human-labelled ground truth. No capture in this project has been labelled by a human analyst,
and we do not claim otherwise. The claim it supports is: *on captures it has never seen, the
triage layer reaches the same conclusion as the evidence-based rules about nine times in ten,
almost always erring towards caution, and never replacing the rules.*

---

## 3. Two real defects found by measuring instead of assuming

### 3.1 The labeller scored "not observed" as "weak"

The synthetic scenario generator's labeller added the weak-cipher penalty whenever
`cipher_strength_score <= 20`. A plaintext session has no cipher at all, so its score
is 0, which tripped the penalty. Certificate penalties had the same shape: a session
where the certificate was never on the wire scored the same as one with an expired
1024-bit certificate.

This is the exact mistake the problem statement warns against - missing evidence
treated as evidence of weakness - and it was inside the training data. Measured
effect on a real, unseen capture (`The-Ultimate-PCAP.pcapng`, 51 sessions):

| | sessions the model got right |
|---|---|
| Before the fix | 3/51 |
| After the fix | 44/51 |

All 35 sessions that were being escalated from MEDIUM to CRITICAL became correct.
The rule engine was right the whole time; only the synthetic labels were wrong.

### 3.2 The training recipe was memorising instead of learning

`capture_repeat` controls how often each real capture row is repeated in the training
set. It was 60. Measured leave-one-capture-out accuracy for each setting:

Measured at the time, on the 63 rows that existed then:

| Capture rows repeated | Honest holdout accuracy |
|---|---|
| none (synthetic only) | 53/63 = 84.1% |
| x1 | 55/63 = 87.3% |
| **x2 (new default)** | **55/63 = 87.3%** |
| x3 | 60/69 = 87.0% |
| x6 | 60/69 = 87.0% |
| x12 | 20/63 = 31.7% |
| x60 (old default) | 18/63 = 28.6% |

Repeating the sessions dozens of times made the model memorise them and misread any capture
it had not seen. The default is now `2`, and the measured table is kept next to the parameter
in `app/ml/train.py` so nobody raises it again by accident. (Those figures are from the
63-row dataset of that round; the current 90-row figures are at the top of this document.)

Together, the two fixes took honest generalisation from **14.3% to 87.0%** on that dataset.

---

## 3.3 A capture on an unfamiliar port used to produce an empty report

This one was found by asking the question the submission will be judged on: *"the model is
trained on a handful of files - does it work on a file you did not make?"* The answer was
measured, not guessed, and the first measurement was wrong in a way worth recording.

**The false start.** Twelve captures were generated on alternate ports and the analyzer
appeared to behave. It had not. Every one of those captures was two packets long - a SYN
and a refusal. The mock servers could not bind ports 25, 143, 110, 465, 993 or 995,
because those are privileged on Linux and macOS (they are not on Windows, which is why the
same toolkit had always worked on the development machine). The capture files were still
written, still non-empty, and still reported as captures. Every conclusion drawn from them
was worthless.

Two fixes came out of that:

* The toolkit now checks the socket error and **counts packets that carry payload**
  before accepting a capture. A file that holds only a handshake, or a refusal, is deleted
  and reported as a failure. Size is not evidence: a two-packet refusal is not an empty
  file.
* Variant captures are now only produced on ports that are *semantically valid for the
  scenario*: STARTTLS and STLS on 25, 587, 143, 110, 2525, 8143, 8110; implicit TLS on
  465, 993, 995, 9465, 9993, 9995. Capturing a STARTTLS conversation on 465 produces a
  file whose contents contradict its own name.

**The real defect, once the test was honest.** With 11 genuine captures in hand, the
analyzer found **one session in six of them and nothing at all in the other five**. Mail
protocol identification was port-based in three independent places:

1. the display filter that keeps packets (`tcp.port in {25,110,143,465,587,993,995}`),
2. TShark's own dissector, which only dissects a protocol on ports it knows,
3. the internal fallback table `EMAIL_PORT_PROTOCOL`.

A mail service running on 8143, 2525 or 8110 was therefore invisible: not misclassified,
not flagged - *absent*. For a tool whose job is to accept a capture from an outside
organisation, that was the most serious defect found so far.

**The fix.** Protocol identification now falls back to what the client and server actually
say. If a first analysis finds no session, the capture is searched for the protocols' own
vocabulary, and when it is found TShark is told to dissect those ports and the analysis is
repeated. Two details matter:

* This is **content-based identification, not decoding**. Only the protocol's own commands
  and greetings are read - `EHLO`, `* OK`, `+OK`, `AUTH PLAIN`, `STLS`. No message body and
  no credential is read or stored, and the vocabulary is only used to choose which
  dissector to apply. Everything after that is TShark's own parsing, exactly as before.
* The greeting direction decides which port is the server: every mail protocol opens with
  the server speaking first. Guessing from port numbers alone would risk naming the
  client's ephemeral port as the server.

**Measured result on the same 11 captures** (`python tools/capability_test.py`):

| Before | After |
|---|---|
| 1 session found in 6 captures, 0 sessions in 5 | 6 captures analysed with all expected findings |
| Nothing reported for a mail service on 8143, 2525 or 8110 | Correct sessions, correct findings, correct ports |
| Rules vs ML: not measurable (no sessions) | Rules vs ML agree 6/6 sessions |

The full table, with the command that produced it, is in `docs/CAPABILITY_TEST.md`.

That report also records when the training-range column can be quoted, because it is
easy to make it say nothing: if the unseen captures are analysed and the model is then
retrained, those sessions become training rows and every one of them reads as *inside*
the range. Train first, then measure. The column is a warning system, not a score: a
session inside the range means the model is not obviously out of its depth, not that
its class is correct.

## 3.4 The held-out test set, and the two defects it found immediately

Everything above measures the model on captures that already existed. This section is about
the opposite: a set built **after** training, on purpose, to be wrong about.

`testset/` holds captures generated for measurement only. It sits outside `samples/`, and
`app/ml/train.py` does not read it - a test set that leaks into training measures nothing. It
exists on the axis the training captures never covered: the **upgrade paths on the cleartext
ports**. Before this round there was one SMTP STARTTLS capture and one refused IMAP one in the
whole project; POP3 STLS did not appear in any capture we had ever generated.

| Test set | Files | Sessions | Distinct situations |
|---|---|---|---|
| `testset/captures` - one file per situation | 24 | 24 | 24 |
| `testset/field` - mixed protocols and port families | 2 | 52 | 26 |
| `testset/large` - one field file repeated with timestamps shifted | 1 | 1,040 | 26 |
| **Total** | **27** | **1,116** | **50 distinct situations** |

Every expectation is declared in `ground_truth.json` **before** the capture runs, from the
server configuration the generator used, and the scorer only reads that file. Nothing can be
adjusted after seeing a result. `python tools/score_testset.py --dir testset` re-measures it,
and `scripts/run_testset.ps1` does the same on Windows.

**What the first scoring run found.** The analyzer reconstructed 1,095 of 1,116 sessions -
five of twenty-six in one file, and every session in the others. Two defects, both invisible
until a capture mixed standard and unusual ports:

1. **The vocabulary fallback only ran when the first pass found nothing.** A capture with mail
   on 587 and mail on 2525 therefore returned only the 587 sessions, and the report looked
   complete. Real traffic mixes ports, so this was the common case and not the edge case.
   Fixed by always running the vocabulary pass and merging the two by stream and address pair
   (`app/analysis/tshark.py`), with `tests/test_unknown_ports.py` extended to lock it down.
2. **Port discovery returned only the first protocol it met.** `discover_mail_ports` collected
   every unusual port that greeted a client and then returned after the first match, so a
   capture with mail on 2525 *and* 8143 *and* 8110 only ever had one of them dissected. Fixed;
   a test now feeds it two greeted ports and requires both back.

A third item looked like a defect and was not: on the upgrade path the certificate hostname
could not be evaluated, because the generated client did not send SNI when it upgraded. Real
clients do. The generator now sends it, so `CERTIFICATE_HOSTNAME_MISMATCH` is raised on
STARTTLS/STLS sessions exactly as it is under implicit TLS. The analyzer had been right to say
nothing with no SNI to compare against - the capture was deficient, not the analysis.

**The measured result after those three fixes** (`testset/RESULTS.md`):

| Check | All 1,116 sessions | 76 non-repeated sessions |
|---|---|---|
| Session reconstructed | 1,116/1,116 | 76/76 |
| Declared findings all reported | 1,116/1,116 | 76/76 |
| No finding invented for evidence that was absent | 1,116/1,116 | 76/76 |
| TLS version, cipher, certificate visibility and forward secrecy as configured | 1,116/1,116 | 76/76 |
| Risk class inside the declared band | 1,116/1,116 | 76/76 |
| **ML class agrees with the rule engine** | **1,073/1,116 = 96.1%** | - |

Two rows deserve pointing at:

* **No finding invented** is not a formality. It is the check that a cleartext session is not
  scored for a weak cipher or an expired certificate it never had, and that a TLS 1.3 session
  whose certificate is encrypted is reported as *not observable* rather than as missing. That
  rule was built into the analyzer earlier; this is the first time it has been tested from the
  outside, on captures generated after the fact.
* **Every ML disagreement is one situation.** All 43 of them are `imap_cleartext_login` - the
  IMAP session where the password is sent before the STARTTLS upgrade. The rules call it
  CRITICAL, the triage layer says HIGH. It is the same under-warning the training holdout
  showed, it is disclosed rather than smoothed over, and it does not hide anything from a
  reader: the report shows the rule class and the ML class side by side, and the
  `PLAINTEXT_AUTHENTICATION` finding is CRITICAL in both the JSON and the PDF.

### The same test set, two models: what the ML row actually depends on

The scoreboard above was produced with the current model (90 capture rows). The same test
set, the same analyzer and the same captures were then scored with the model from before the
coverage sweep existed (69 capture rows). Nothing else changed:

| Model in use | Rule checks | ML agreement with the rules | Disagreements |
|---|---|---|---|
| 90 rows (includes `samples/sweep`) | **100% on every check** | **1,073/1,116 = 96.1%** | 43 |
| 69 rows (no `samples/sweep`) | **100% on every check** | **987/1,116 = 88.4%** | 129 |

The difference is not noise and it is not a regression - it is measurable, and it says
something precise about what the sweep bought:

| Disagreement | Out-of-date model | Current model |
|---|---|---|
| `imap_cleartext_login` - rules CRITICAL, ML HIGH (the known under-warning) | 43 sessions | 43 sessions |
| **static-RSA sessions - rules MEDIUM, ML CRITICAL** | **86 sessions** | **0 sessions** |

The old model had never seen a static-RSA session, because no capture before the sweep used
that profile, so it treated "no forward secrecy" as a critical problem and over-warned on
86 sessions. The sweep added `static-rsa` coverage on all three protocols and both port
families, and the over-warning disappeared. **That is the clearest measured justification for
the sweep in the whole project:** on held-out captures, it removed a systematic false alarm
across 86 sessions, and it did not cost anything - the under-warning count stayed at 43.

Two things follow, and both are worth saying to a judge:

* **The rule-based results do not depend on the model at all.** Every check except ML
  agreement read 100% under both models. The evidence layer is deterministic; only the triage
  layer moves. A weaker model cannot make a finding disappear.
* **An out-of-date model produces a plausible-looking number with no symptom.** It looked
  exactly like a real measurement of a real limitation. The scorer now refuses to let that
  pass silently: if any capture it should have learned from is newer than the model file, it
  prints a MODEL WARNING, writes the same warning into `RESULTS.md`, and explains what the
  figure would have been. Compare the model's row count against the captures present before
  quoting ML agreement.

**What this does not prove.** The test set is synthetic and self-generated; it is not human
analyst ground truth, and the model is trained on rule labels, so agreement with the rules is
what is measured. It cannot show that the analyzer works on traffic from a network it has
never seen - only a capture from the organisation could. What it can show is that declared
weaknesses are still detected, and declared-absent evidence is still not turned into a
finding, on captures built after the model was trained, at a scale of a thousand sessions.

### The limit that remains, stated plainly

Five captures are still reported as *unclassified*, and this is a property of passive
analysis rather than a bug: they are **implicit TLS on an unrecognised port** (9993, 9465).
(A capture that mixes standard and unusual ports is no longer in this category - that was a
defect, and section 3.4 records it and the fix.)
There, the client sends a TLS ClientHello as the first byte of the conversation, so there
is no vocabulary to read anywhere in the file, and a port number is a convention rather
than evidence. The analyzer reports what it can see instead of guessing:

```
port 9993, TLS 1.0 (from SERVER_HELLO_LEGACY), client asked for mail.lab.test, certificate visible
```

It names the port, the negotiated TLS version taken from the server's own hello, the SNI
the client asked for, and whether the certificate was observable - and it says the protocol
inside cannot be proven. It does **not** claim "this is IMAPS". A STARTTLS or STLS
conversation has no such limit, because the upgrade is negotiated in cleartext first.

**Say this:** "A capture on a non-standard port is analysed on its content. If the traffic
is encrypted end to end and the port is unknown, the tool tells you it saw encrypted
traffic it could not name, rather than reporting nothing."

**Do not say this:** "It identifies any encrypted mail stream." It identifies encrypted
streams and describes them; naming the protocol inside one is not always possible from a
capture alone.

---

## 4. What is still honest to say, and what is not

**Say this:**

* "The model reaches 91.1% agreement with the rule engine on captures it has never
  seen, measured leave-one-capture-out - 61/69 on the hand-curated captures alone."
* "It is trained on a scenario generator plus rule-labelled sessions, so it imitates
  our rules. It ranks and triages; the findings are the evidence."
* "40 captures and 90 sessions is still a small sample, and the interval is roughly six
  points wide. That is why both the in-sample and the holdout figures are published with
  the model, and why we do not claim 95%."

**Do not say this:**

* "90/90 accuracy." It is in-sample agreement on the rows that trained the model.
* "The model detects attacks." It classifies posture, from passive evidence.
* "The model generalises to any mail traffic." Of the 40 captures it has seen, 15 are
  hand-written and 42 are generated by our own toolkit on loopback.
* Any number about real-world attack rates: nothing here measures that.

---

## 5. What actually improves the model: measured

Two ideas were tested against each other, same code, same seed, same evaluation
(leave-one-capture-out, which holds a whole capture out so no session from it helped
training).

**Idea A - more training rows.** 5,000 synthetic rows versus 20,000:

| Synthetic rows | Synthetic accuracy | Capture holdout | Transfer |
|---|---|---|---|
| 5,000 | 0.983 | **53/63** | 53/63 |
| 20,000 | 0.9965 | **53/63** | 53/63 |

Four times the data, no change at all. The synthetic accuracy improved from 0.983 to
0.9965, which is exactly the trap: it measures how well the model memorised its own
generator, not how it behaves on real captures.

```powershell
python -c "from app.ml.train import train_models; train_models(rows=20000)"
```

**Idea C - fill the matrix instead of hand-picking captures.** The lab set teaches fifteen
hand-written situations. `tools\lab_capture_toolkit.py sweep` captures the **whole matrix**
instead: every protocol (SMTP/IMAP/POP3) against every port family (standard and high)
against every TLS profile (modern, TLS 1.3, static RSA, TLS 1.0, NULL cipher, CBC, weak
certificate) - **42 captures**, including a `static-rsa` profile no hand-written capture used.

```powershell
python tools\lab_capture_toolkit.py sweep          # ~100 s, writes samples\sweep
python -m app.ml.train                            # scans samples, samples\lab, samples\sweep
```

Result: training rows 69 -> **90**, captures with sessions 19 -> **40**, class balance
improved (CRITICAL 13% -> 23% of rows), and the reported holdout rose 87.0% -> **91.1%**.
Most of that headline gain is a measurement effect, decomposed honestly in section 2: the
curated-set figure is **61/69**, up one row. One real error was fixed either way
(`smtp-starttls-secure` is no longer called CRITICAL).

21 of the 42 sweep captures sit on high ports where implicit TLS hides every protocol word.
They are reported as UNCLASSIFIED by design and contribute no training rows; their verified
results are in `samples\sweep\SWEEP_RESULTS.md`.

**Idea B - more different captures.** Six new scenarios were added, each a (protocol, port,
profile) combination that did not exist before, including three POP3S scenarios because
POP3 had no encrypted coverage at all:

| Capture set | Real rows | Capture holdout | Transfer |
|---|---|---|---|
| 13 captures | 63 | 54/63 (85.7%) | 54/63 |
| 19 captures | 69 | 60/69 (87.0%) | 60/69 (87.0%) |
| **40 captures (after the sweep)** | **90** | **82/90 (91.1%)** | **78/90 (86.7%)** |

More captures moved the honest number up while making the test harder - 19 captures to
generalise across instead of 13, then 40 instead of 19.

**The conclusion:** the lever is the diversity of real captures, not the number of rows, not
the model size, and not the hyperparameters. That is why the remaining time goes into the
capture toolkit rather than into tuning, and it is why no deep model was introduced: a
Random Forest with 220 trees on 26 features is already past the point where its settings
matter, and the sessions it has seen are what limit it.

The two remaining holdout misses, recorded honestly: `imap-cleartext-login.pcapng`
(CRITICAL predicted HIGH) and `smtp-starttls-secure.pcapng` (LOW predicted CRITICAL - a
false alarm on a clean session). Both are single rows in a 69-row sample.

---

## 5b. The next step: more different captures

The cheap way to continue is more scenarios, not more rows:

1. **Widen the generator.** `tools\lab_capture_toolkit.py` has fifteen scenarios. Further
   combinations of modes and profiles it already supports - more certificate problems
   (missing intermediate, self-signed, small key), TLS 1.1, more cipher profiles, a second
   session inside one capture - each adds a genuinely new combination.
2. **Capture and verify them.** `verify` refuses to accept a capture that does not show
   what it claims, so a broken scenario is caught before it reaches the training set.
3. **Label them.** `python -m app.cli batch samples --out data\batch` labels every session
   with the rule engine.
4. **Measure again.** `capture_holdout` and `synthetic_transfer` are printed on every
   training run, so an improvement - or a regression - is visible immediately. If a new
   scenario lowers the holdout, that is a finding worth reporting, not a reason to delete it.

Expected outcome, stated honestly: more varied scenarios should continue to raise the
holdout figure slowly, because each new scenario is a different way of being weak rather
than a new copy of an old one. It will not turn the model into an authority - the rules
remain the verdict either way.

**Dataset size, for the record:** 61 capture files are scanned, 40 contain mail sessions,
and they yield 90 sessions labelled by the rule engine - 15 hand-written lab captures,
42 systematic sweep captures (21 of which contain sessions), 3 third-party Wireshark
fixtures and 1 third-party aggregate capture. In-sample and holdout figures for this dataset
are published in `models\model_metadata.json` and printed by every training run.

The honest limit is data volume, not model capacity, and the fix is now cheap because
the pieces exist:

1. **Widen the generator.** `tools\lab_capture_toolkit.py` has fifteen fixed scenarios.
   Adding randomised ports, SNI values, certificate lifetimes and key sizes, cipher
   preference order, retry counts and session lengths would let one command produce
   hundreds of captures that differ from each other.
2. **Capture them.** A few hundred captures take minutes on loopback.
3. **Label them.** `python -m app.cli batch samples --out data\batch` labels every
   session with the rule engine.
4. **Measure again.** `capture_holdout` and `synthetic_transfer` are already reported
   on every training run, so the improvement (or the lack of one) is visible
   immediately.

Expected outcome, stated honestly: more varied scenarios should raise the holdout
figure and make the published dataset worth contributing. It will not turn the model
into an authority - the rules remain the verdict either way.

---

## 6. Reproducing everything in this document

```powershell
python -m app.cli doctor
python -m app.ml.train                     # prints calibration, holdout and transfer
python -m app.cli batch samples --out data\batch --workers 4
python -m app.cli export data\batch\session_features.csv --stats
python tools\make_dataset_release.py       # publishable dataset + datasheet

# capture the unseen set and measure the analyzer against it
python tools\lab_capture_toolkit.py variants --outdir samples\variants
python tools\capability_test.py            # writes docs\CAPABILITY_TEST.md
```

`lab_capture_toolkit.py variants` prints `SKIPPED` for privileged ports unless the shell is
elevated; on Windows none of them are privileged. `capability_test.py` exits non-zero if any
capture fails its expectations, so it can be run in CI once the captures exist.
