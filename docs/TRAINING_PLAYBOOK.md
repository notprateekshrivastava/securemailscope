# Training and testing playbook

Written for the three days before submission. Every number here was measured on this
project, and the command that produced it is shown next to it. Where a measurement
contradicted the obvious guess, the measurement wins and the guess is recorded as a trap.

---

## 0. First, the question everyone asks

> "If we upload PCAP files it should be capable of extracting the data and analysing it,
> isn't it?"

**Yes - and that part needs no training at all.** There are two layers, and only one of
them is machine learning.

| Layer | What it does | Needs training? | How good is it |
|---|---|---|---|
| **Extraction + rules** | Reads the capture, rebuilds TCP streams and mail sessions, finds STARTTLS/STLS upgrades, reads TLS handshakes and certificates, reports findings | **No** | Deterministic. The same file always gives the same answer, and it works on a capture it has never seen |
| **ML triage** | Ranks sessions and flags inputs unlike anything it has seen | Yes | 91.1% agreement with the rules on unseen captures (measured below) |

So "is it capable of extracting and analysing any PCAP?" is answered by the first layer,
and the answer is yes - for mail traffic, on any port, with any server. The ML layer never
decides whether something is insecure; it only helps you look at the right session first.

**Prove it in four minutes on your machine** (do this before you present):

```powershell
cd "D:\CryptoPost SIH\securemailscope"

# 1. the environment is healthy
python -m app.cli doctor

# 2. analyse one capture from the command line - rules, ML, agreement, training range
python -m app.cli check "samples\lab\imaps-tls10-legacy.pcapng"

# 3. upload one through the dashboard and export the reports
python scripts\restart_and_test.ps1
#    open http://127.0.0.1:8000/dashboard , upload a capture, download JSON / HTML / PDF
```

If `check` prints a session table and a posture, extraction and analysis work. Nothing in
that path depends on the model.

---

## 1. What actually makes the model better: measured, not guessed

I ran the two obvious ideas against each other. Both used the same code, the same seed and
the same evaluation (leave-one-capture-out, which holds out a whole capture so no session
from it helped training).

### Idea A: more training rows

```powershell
python -c "from app.ml.train import train_models; train_models(rows=20000, output_dir=__import__('pathlib').Path('/tmp/big'))"
```

| Synthetic rows | Synthetic accuracy | Capture holdout | Transfer |
|---|---|---|---|
| 5,000 | 0.983 | **53/63** | 53/63 |
| 20,000 | 0.9965 | **53/63** | 53/63 |

**Four times the data, exactly zero change.** The synthetic accuracy went up (0.983 →
0.9965) - which is the trap: that number only says the model memorised its own generator
better. It says nothing about real captures.

### Idea B: more *different* captures

I added six scenarios that did not exist before, each a new (protocol, port, profile)
combination, including three POP3S scenarios - POP3 had no encrypted coverage at all:

```powershell
python tools\lab_capture_toolkit.py capture --scenario pop3s-tls10-legacy ...
python tools\lab_capture_toolkit.py verify --outdir samples\lab     # 15/15 behave as expected
python -m app.ml.train
```

| Capture set | Real rows | Capture holdout | Transfer |
|---|---|---|---|
| 13 captures | 63 | 54/63 (85.7%) | 54/63 |
| **19 captures** | **69** | **60/69 (87.0%)** | **60/69 (87.0%)** |
| **40 captures (after the 42-capture sweep)** | **90** | **82/90 (91.1%)** | **78/90 (86.7%)** |

Six more captures moved the honest number up while making the test **harder** (19 captures
to generalise across, not 13).

### The conclusion, and it is the whole strategy

> **The lever is the diversity of real captures. It is not the number of rows, not the
> model size, and not the hyperparameters.**

That is also why the recommendation is *not* to spend the remaining time tuning the
classifier. A Random Forest with 220 trees on 26 features is already past the point where
its settings matter; the sessions it has seen are what limit it.

**Where the misses still are** (from `models\model_metadata.json`, `capture_holdout`):

| Held-out capture | Rules say | Model said | Reading |
|---|---|---|---|
| `imap-cleartext-login.pcapng` | CRITICAL | HIGH | Credentials in the clear, predicted one band low - a miss in the safe direction |
| `smtp-starttls-secure.pcapng` | LOW | CRITICAL | A clean session predicted worse than it is - a false alarm, the more annoying kind |

Both are single sessions in a 69-row sample. Report them as the known hard cases rather
than pretending the model is clean.

---

## 2. The training method we use, and why it is the right one here

It is called **weak supervision**: the rule engine labels the real captures, and the model
learns to imitate those labels. It is the correct choice for this project because:

* we have no analyst to hand-label hundreds of sessions in three days;
* the rules are explainable, so every training label can be traced to a finding;
* the model inherits the rules' evidence discipline (missing evidence is never "insecure"),
  instead of learning contradictions from a label set we cannot audit.

The loop, in the order that matters:

```powershell
# 1. generate captures (the diverse set is the asset - the synthetic rows are the filler)
python tools\lab_capture_toolkit.py certs
python tools\lab_capture_toolkit.py capture

# 2. confirm each capture shows what it claims to show - never train on unverified data
python tools\lab_capture_toolkit.py verify --outdir samples\lab

# 3. label every session with the rule engine, and measure the scale path while you are there
python -m app.cli batch samples --out data\batch --workers 4

# 4. train, and read the two numbers that matter (calibration is in-sample and proves nothing)
python -m app.ml.train

# 5. test on captures the model has never seen - separate step, separate captures
python tools\lab_capture_toolkit.py variants --outdir samples\variants
python tools\capability_test.py
```

**Why step 2 is not optional:** an early run of this project produced twelve "successful"
captures that were each two packets - a connection attempt and a refusal - because the mock
servers could not bind privileged ports. They were analysed, reported and believed. A
capture that has not been verified is not data.

**Why step 5 uses different captures from step 4:** if the same captures are analysed and
then trained on, those sessions become training rows and the test proves nothing. Train
first, then generate the unseen set. This is written into the report as well, because it is
the easiest mistake to make by accident.

---

## 3. How to test: five levels, each proving something different

| # | Test | Command | What it proves | Pass looks like |
|---|---|---|---|---|
| 1 | Unit and regression tests | `python -m pytest tests\ -q` | The code does what it is supposed to on constructed inputs | **34 passed** |
| 2 | Engine self-check | `python scripts\self_check.py` | The real engine behaves correctly on the real captures, without pytest | **33 passed, 0 failed** |
| 3 | Lab fixtures | `python tools\lab_capture_toolkit.py verify --outdir samples\lab` | Each capture shows the weakness it was built to show, verified against the analyzer's own output | **15/15 behave as expected** |
| 4 | Unseen captures | `python tools\capability_test.py` | Generalisation, and that the ML knows when it is out of its depth | 6/11 with every expected finding, 5 unclassified, 0 crashes, rules vs ML 6/6 |
| 5 | The ML numbers | inside `python -m app.ml.train` output | How the classifier behaves on captures it has not seen | capture holdout **60/69**, transfer **60/69** |

Two more checks worth doing once, by hand, because they are what a judge will ask for:

**Blind test on traffic we did not generate.** `samples\The-Ultimate-PCAP.pcapng` is a
third-party capture that was never used in training: 51 mail sessions, posture 82,
CRITICAL, ~13 s. It is the closest thing to "a file we did not make".

**Manual spot check.** Open one lab capture in Wireshark, follow one TCP stream, and read
the same facts the tool reported: the STARTTLS command, the ServerHello version and cipher,
the certificate's CN and validity dates. Doing this once means you can answer
"how do you know your parser is right?" from your own eyes rather than from a test name.

**What each number may and may not be used for:**

| Number | Quote it? | Why |
|---|---|---|
| Synthetic accuracy (0.98) | Only as "the model fits its own generator" | It is the generator being memorised |
| Calibration (69/69) | **No** - never on its own | Those rows trained the model; it is a consistency check |
| Capture holdout (60/69) | **Yes** | Whole captures held out, sessions never seen |
| Transfer (60/69) | **Yes** | Trained on synthetic rows only, tested on real captures |
| Lab verify (15/15) | **Yes** | It is a correctness check of the engine, not an accuracy claim |

---

## 4. The Kaggle question, in two parts

### Part 1: publishing our dataset - yes, do it

It is a deliverable in its own right (the brief asks for a workable documented sample set),
and the official dataset note explicitly permits participants to generate SMTP/IMAPS/POP3S
traffic and capture it. That is exactly how our captures were made: a mock server and a
client on loopback, recorded by TShark.

```powershell
python tools\make_dataset_release.py            # builds dist\dataset_v1 with a datasheet
kaggle datasets create -p dist\dataset_v1 --dir-mode zip
```

What ships and what does not:

| Ships | Why |
|---|---|
| `samples\lab\` - 15 captures + `EXPECTED_RESULTS.md` | Ours, generated locally, each with its expected finding verified |
| `session_features.csv` filtered to the shipped captures | 26 features per session plus the rule label, ML label and finding codes |
| A datasheet describing each scenario and the evidence rules | Anyone reusing it knows what a missing value means |

| Does not ship | Why |
|---|---|
| `The-Ultimate-PCAP.pcapng`, `imap-ssl` / `pop-ssl` / `smtp-ssl` | Third party. Wireshark sample captures and a blog's aggregate capture are not ours to redistribute under our licence |
| NTRO material | Never leaves the machine it was given on. Not to Kaggle, not to any AI API |
| Trained `.joblib` files | Machine-specific; a reader retrains with `python -m app.ml.train` in under a minute |

In the dataset description, state plainly: generated on loopback by our own toolkit, no
real mail content, no credentials, labels produced by an explainable rule engine (weak
supervision) - and that the ML layer imitates those rules. That last sentence costs nothing
and pre-empts the obvious question.

### Part 2: training on someone else's Kaggle PCAPs - no

Three reasons, and they are the same reasons a judge would give:

1. **No labels.** A classifier needs a target. Unlabelled captures cannot train it.
2. **Wrong domain.** Public PCAP collections are mostly HTTP, DNS, malware traffic and
   intrusion-detection data. Our 26 features are mail-session features; rows from other
   protocols are not just unhelpful, they teach the model about a world we do not operate in.
3. **Provenance.** We cannot show the permission chain for someone else's capture of real
   users' mail. Our whole privacy story is that we know exactly where our data came from.

**One legitimate use:** real third-party captures as a *parser stress test* - does the
reader survive traffic we did not create? `The-Ultimate-PCAP.pcapng` plays that role: it is
never trained on, only analysed, and it proves the parser copes with 51 mixed mail sessions
in 15 MB.

---

## 5. The next process, day by day

### Today (27th) - lock the baseline

1. Copy the new bundle in and run `python -m app.ml.train` once.
2. Run all five tests in section 3 and write the five numbers down. They are your baseline.
3. Do the four-minute proof in section 0, including one dashboard upload with a JSON, HTML
   and PDF export. If a report fails to render, you want to know today.

### Tomorrow (28th) - the only improvement that pays

1. Add scenarios, not rows. The measurement says this is the lever. The cheapest next
   additions are more combinations of things the mock server already supports: more
   certificate problems (chain missing an intermediate, self-signed, too-small key, wrong
   hostname on a different protocol), more cipher profiles, TLS 1.1, and a second session
   in one capture.
2. Capture with the toolkit, run `verify` until you are back to *all captures behave as
   expected*, then `python -m app.ml.train` and compare the holdout against today's number.
3. Keep the old capture set in git. If a new scenario lowers the holdout, that is a finding,
   not a failure - report the drop and keep the scenario, because it is honest coverage.
4. Re-run the unseen-capture test with **freshly generated** variants and quote the result.

### Submission day (29th/30th) - freeze and rehearse

1. `python -m app.cli doctor`, then the five tests. Nothing new gets added today.
2. Regenerate `reports\` and the dashboard snapshot; keep a copy offline.
3. Rehearse the two-minute demo: upload a lab capture → show the finding → export the PDF →
   show `capability_test.py` generating unseen captures live.
4. Prepare the answer to "what are your ML numbers?" with the holdout first, always.

### Is the number good? The baseline, and why not 95%

| Measure | Value | How it is computed |
|---|---|---|
| **In-sample (calibration)** | **90/90** | the rows that trained the model - a consistency check, **not** evidence |
| **Holdout (leave-one-capture-out)** | **82/90 = 91.1%** | whole capture held out; no session from it helped training |
| Holdout on the curated set only | 61/69 = 88.4% | same 19 hand-written/third-party captures as before the sweep existed |
| Transfer (synthetic -> real) | 78/90 = 86.7% | trained on synthetic rows only, tested on real captures |
| **Majority-class baseline** | 44/90 = **48.9%** | always predict MEDIUM; what a useless model scores |

**+42.2 points over the trivial baseline.** The confidence intervals do not overlap:
ours is [85.2%, 97.0%], the baseline's is [38.6%, 59.2%].

**Why not 95%?** Because 90 rows cannot tell the difference. One row is worth 1.1 points; a
95% claim would allow at most 4 misses and we have 8; and 95% sits *inside* our confidence
interval, so "we measured 91% ± 6 points" is the honest sentence. Reaching ±3 points of
certainty needs about 350 rows. Tuning until the number reads 95% on 90 rows would be
fitting the test set, and the next capture would expose it.

**The one error to disclose first:** `imap-cleartext-login` is predicted HIGH where the rules
say CRITICAL - the only understatement in nine errors. The other eight all over-warn (seven
are the same LOW/MEDIUM boundary on one capture). Full breakdown: `docs\SCALE_AND_ML.md`.

---

### Measure it: the held-out test set (never train on it)

`testset/` holds 27 captures and 1,116 sessions that were generated **after** the model was
trained, on situations the training captures did not have: IMAP STARTTLS, POP3 STLS, SMTP with
no STARTTLS offered, and files that mix protocols and ports. Every expectation was written
before the capture ran.

```powershell
python tools\score_testset.py --dir testset     # score it, ~2 minutes
.\scripts\run_testset.ps1                        # same thing, and generates it if missing
```

**Do not add `testset/` to `CAPTURE_DIRS`.** It is not in `samples/`, `train.py` does not read
it, and `tests/test_testset_isolation.py` fails if that ever changes. A model trained on its
own test set reports a number that means nothing, and nothing else about the run looks wrong.

If you want more training data, the honest route is a new capture set under `samples/lab` or
`samples/sweep` - `tools/lab_capture_toolkit.py capture|sweep`. Keep the test set as the
thing you measure against.

### If the score says "MODEL WARNING", the ML number is not the project's best

`tools\score_testset.py` checks one thing before it runs: is any capture that the model should
have learned from newer than the model file? If so it prints a warning, repeats it in
`RESULTS.md`, and tells you what to do. Take it seriously - the gap is large and it looks like
a real result.

Measured, same code and same captures, only the model different:

| Model | Rule checks | ML agreement |
|---|---|---|
| Current (90 rows, includes the sweep) | 100% | **1,073/1,116 = 96.1%** |
| Before the coverage sweep (69 rows) | 100% | **987/1,116 = 88.4%** |

**Whenever you extract an update that adds captures, run `python -m app.ml.train` before you
score or demo anything.** The analyzer's findings are unaffected, which is exactly why the
stale number is easy to miss: only the ML column moves.

### Traps, in order of how likely they are to cost you

1. **Training on the captures you intend to demo as unseen.** Train first, generate after.
2. **Quoting the in-sample 69/69.** It is a consistency check; the holdout is the result.
3. **Quoting synthetic accuracy (0.98).** It measures the generator, and four times the
   rows moved it without moving anything real.
4. **Adding a deep model or tuning hyperparameters.** Measured: the lever is data diversity.
5. **Hand-labelling sessions.** With three days left, the rules are the labels; hand-labelling
   a few hundred sessions is how teams run out of time and end up with unauditable data.
6. **Publishing a third-party capture under our licence.** Check every file you ship.
7. **Sending any NTRO capture anywhere.** Local processing is a promise we make in the pitch.

---

## 6. What to say when asked about the training methodology

> "The rules are the product; the model is a triage layer. The rules need no training and
> handle any capture. The model is trained by weak supervision - the rule engine labels our
> generated captures - and we publish leave-one-capture-out agreement with those rules,
> 60 of 69 sessions on captures it has never seen, plus 60 of 69 when it is trained on
> synthetic rows alone. We tested whether more data helps: four times the synthetic rows
> moved nothing, while six more diverse captures moved it up. So we spent the time on
> capture diversity, not on a bigger model."

That answer contains a measurement, a decision, and the reason for the decision. It is
worth more than a claim of high accuracy.
