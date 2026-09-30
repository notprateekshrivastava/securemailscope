# Held-out test set

Captures generated to **measure** the analyzer and the ML layer, not to train them. Every
expectation was declared before the traffic was generated and is stored in
`ground_truth.json`; `EXPECTED.md` is the same thing in prose.

## Run it (Windows, no administrator rights needed)

```powershell
python tools\score_testset.py --dir testset
```

Takes about two minutes on the large file and prints a scoreboard; it writes
`testset\RESULTS.md` with the detail - what was observed per situation, what failed, and
where the ML layer disagreed with the rules.

## What is in here

| Folder | Files | Sessions | What it is |
|---|---|---|---|
| `captures\` | 24 | 24 | One session per file, one file per situation: SMTP STARTTLS, IMAP STARTTLS and POP3 STLS, each upgraded and refused, across eight TLS profiles |
| `field\` | 2 | 52 | Mixed traffic: three protocols, healthy and unhealthy sessions interleaved in one capture, on both standard and unusual ports |
| `large\` | 1 | 1,040 | One field file repeated with shifted timestamps - a 6 MB capture for session reconstruction and throughput |
| `ground_truth.json` | - | - | What each session must show, written before capture |
| `RESULTS.md` | - | - | Written by the scorer: the measured result |

Coverage that no training capture had: **IMAP STARTTLS** upgraded and refused, **POP3 STLS**
upgraded and refused, **SMTP with no STARTTLS offered**, and capture files that mix protocols
and port families.

## Regenerate or resize it

```powershell
python tools\lab_capture_toolkit.py testset --rounds 40      # ~1 minute
python tools\lab_capture_toolkit.py testset --rounds 120     # a 19 MB file, ~3,100 sessions
python tools\lab_capture_toolkit.py testset --skip-large     # small files only
```

Regenerating rewrites `ground_truth.json`, so score it again afterwards. The expectations
themselves are unchanged between runs: they come from the server configuration, not from a
previous result.

## Three things that are true about this folder

1. **It is not training data.** It sits outside `samples\`, and `app\ml\train.py` does not
   read it. Training a model on its own test set would make every number here meaningless.
2. **It is synthetic and self-generated.** It is not human analyst ground truth. What it can
   show is that declared weaknesses are detected and declared-absent ones are not invented,
   on captures built after the model was trained.
3. **The class column is a policy band, not a fact.** Cleartext credentials are CRITICAL by
   definition; a deprecated version or a weak certificate must land above a healthy session.
   The exact band in between is a policy choice, so it is declared as a band and reported
   as one.
# Held-out test set

Captures generated to **measure** the analyzer and the ML layer, not to train them. Every
expectation was declared before the traffic was generated and is stored in
`ground_truth.json`; `EXPECTED.md` is the same thing in prose.

## Run it (Windows, no administrator rights needed)

```powershell
python tools\score_testset.py --dir testset
```

Takes about two minutes on the large file and prints a scoreboard; it writes
`testset\RESULTS.md` with the detail - what was observed per situation, what failed, and
where the ML layer disagreed with the rules.

## What is in here

| Folder | Files | Sessions | What it is |
|---|---|---|---|
| `captures\` | 24 | 24 | One session per file, one file per situation: SMTP STARTTLS, IMAP STARTTLS and POP3 STLS, each upgraded and refused, across eight TLS profiles |
| `field\` | 2 | 52 | Mixed traffic: three protocols, healthy and unhealthy sessions interleaved in one capture, on both standard and unusual ports |
| `large\` | 1 | 1,040 | One field file repeated with shifted timestamps - a 6 MB capture for session reconstruction and throughput |
| `ground_truth.json` | - | - | What each session must show, written before capture |
| `RESULTS.md` | - | - | Written by the scorer: the measured result |

Coverage that no training capture had: **IMAP STARTTLS** upgraded and refused, **POP3 STLS**
upgraded and refused, **SMTP with no STARTTLS offered**, and capture files that mix protocols
and port families.

## Regenerate or resize it

```powershell
python tools\lab_capture_toolkit.py testset --rounds 40      # ~1 minute
python tools\lab_capture_toolkit.py testset --rounds 120     # a 19 MB file, ~3,100 sessions
python tools\lab_capture_toolkit.py testset --skip-large     # small files only
```

Regenerating rewrites `ground_truth.json`, so score it again afterwards. The expectations
themselves are unchanged between runs: they come from the server configuration, not from a
previous result.

## Three things that are true about this folder

1. **It is not training data.** It sits outside `samples\`, and `app\ml\train.py` does not
   read it. Training a model on its own test set would make every number here meaningless.
2. **It is synthetic and self-generated.** It is not human analyst ground truth. What it can
   show is that declared weaknesses are detected and declared-absent ones are not invented,
   on captures built after the model was trained.
3. **The class column is a policy band, not a fact.** Cleartext credentials are CRITICAL by
   definition; a deprecated version or a weak certificate must land above a healthy session.
   The exact band in between is a policy choice, so it is declared as a band and reported
   as one.
