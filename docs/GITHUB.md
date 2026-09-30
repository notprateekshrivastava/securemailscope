# Putting this on GitHub

Yes, this is possible, and everything needed is already in the repository: a licence,
a `.gitattributes`, a `.gitignore` that keeps captured data out, and a CI workflow in
`.github\workflows\tests.yml` that runs the same checks you run by hand.

**Read section 2 before the first `git add`.** Committing a capture from the
organisation would be a serious mistake, and it is the one thing here that is hard to
undo.

---

## 1. What goes in

| Included | Why |
|---|---|
| `app\`, `tests\`, `tools\`, `scripts\`, `docs\` | The code, the tests, the lab toolkit, the scripts, the documentation |
| `samples\lab\` | The captures **we generated ourselves** on loopback. These are ours to publish |
| `samples\README.md`, `samples\EXPECTED_RESULTS.md` | How the sample set works and what it is expected to produce |
| `requirements.txt`, `requirements-dev.txt`, `Dockerfile`, `docker-compose.yml` | How to install and run |
| `LICENSE`, `.gitattributes`, `.gitignore`, `.github\` | Licence, line-ending rules, ignore rules, CI |

## 2. What stays out, and why

The `.gitignore` already excludes these. Do not override it.

| Never committed | Reason |
|---|---|
| `data\uploads\*`, `data\analyses\*`, `data\sample-results\*` | These hold **uploaded captures and their results**. If a capture came from the organisation, publishing it in a repository would leak confidential traffic. This is the single most important rule on this page |
| `models\*.joblib` | Large binaries, and worthless without the code that produced them. Anyone can rebuild them with `python -m app.ml.train` |
| `samples\lab\certs\*.key.pem` | Private keys. They are test-only, but committing private keys is a bad habit and it makes scanners complain |
| `.venv\`, `__pycache__\`, `.pytest_cache\` | Machine-specific |
| `reports\`, `dist\` | Generated output. Regenerate with the scripts |

Before your first push, confirm none of them are staged:

```powershell
git status --short
git ls-files | Select-String -Pattern "data/(uploads|analyses)|\.joblib|\.key\.pem"
```

The second command must print nothing. If it prints a path, the file is already
tracked, so remove it from the index and commit that removal:

```powershell
git rm --cached "data/uploads/<the-file>"
```

**A note on the third-party captures.** `samples\` contains `imap-ssl.pcapng`,
`pop-ssl.pcapng`, `smtp-ssl.pcapng` (from the Wireshark notes repository) and
`The-Ultimate-PCAP.pcapng` (from weberblog.net). They are useful for local testing, but
they are not ours, so they are excluded from the update bundle and must not be pushed
to a public repository. Keep them local, or move them to a `samples\external\` folder
that is ignored. Only `samples\lab\` is ours to publish.

---

## 3. First push, step by step

```powershell
cd "D:\CryptoPost SIH\securemailscope"

# 1. Check nothing private is about to go in
git status --short
git ls-files | Select-String -Pattern "data/|\.joblib|\.key\.pem"     # must print nothing

# 2. Initialise and commit
git init
git branch -M main
git add .
git commit -m "SecureMailScope: passive SMTP/IMAP/POP3 TLS posture analysis with explainable ML"

# 3. Create an EMPTY repository on github.com first (no README, no licence),
#    then connect it:
git remote add origin https://github.com/<your-account>/<repo-name>.git
git push -u origin main
```

If `git push` asks for a password, use a **personal access token**, not your account
password: GitHub Settings, Developer settings, Personal access tokens, Fine-grained
tokens, with "Contents: Read and write" on that repository.

After the push, open the **Actions** tab. The `tests` workflow runs TShark, trains the
model, runs the self check and the unit tests on Python 3.11 and 3.12, and the badge in
the README turns green. If it fails, the failing step tells you which command to run
locally.

---

## 4. What to put at the top of the README

Add these near the title so a visitor understands the project in ten seconds:

```markdown
[![tests](https://github.com/<account>/<repo>/actions/workflows/tests.yml/badge.svg)](https://github.com/<account>/<repo>/actions/workflows/tests.yml)
```

and, for the demonstration, the screenshots you captured:

```markdown
![Dashboard - capture summary](docs/images/dashboard-overview.png)
![Dashboard - session evidence](docs/images/dashboard-session.png)
```

Create `docs\images\` and copy the screenshots in. Two or three images is enough: the
upload panel with the source selector, the metric cards, and one expanded session
showing the certificate and the ML explanation.

---

## 5. Housekeeping that makes it look maintained

```powershell
# A release tag for the submission
git tag -a v1.0.0 -m "Smart India Hackathon submission build"
git push origin v1.0.0
```

Then on GitHub: **Releases**, *Draft a new release*, choose the tag, attach
`securemailscope_update_2026-09-27.zip`, and paste the numbers from
`samples\EXPECTED_RESULTS.md`.

A short description for the repository:

> Passive forensic analysis of SMTP, IMAP and POP3 traffic. Reconstructs email
> sessions from PCAP files, extracts TLS handshakes and X.509 certificates, detects
> STARTTLS downgrades, deprecated versions, weak ciphers, weak keys and certificate
> problems, and scores the cryptographic posture of every session with an explainable
> rule engine plus a small ML triage layer. Evidence-qualified: missing evidence is
> reported as UNKNOWN, never as weakness. No email content is ever read or decrypted.

Suggested topics: `pcap`, `tls`, `network-security`, `digital-forensics`,
`fastapi`, `scikit-learn`, `smtp`, `imap`, `pop3`, `wireshark`, `tshark`.

---

## 6. If you also want it on Kaggle

Two separate things, and only one of them is about training:

* **Training on Kaggle data**: public labelled mail-TLS-posture data does not exist, so
  there is nothing to download that would teach the model anything our rule engine does
  not already label. See `docs\SCALE_AND_ML.md` section 5.
* **Publishing a dataset**: we can contribute one, and it is ours to publish. Build it
  and check what is inside first:

```powershell
python tools\make_dataset_release.py            # writes dist\dataset_v1\
```

The builder refuses to include third-party captures: only files generated by
`tools\lab_capture_toolkit.py` are copied into `captures\`, and the feature table is
filtered to match exactly those captures. Add `-IncludeThirdParty` only if you want
the quarantine folder for local use, and never publish that folder.

Upload it with the Kaggle CLI:

```powershell
pip install kaggle
# put your API token at %USERPROFILE%\.kaggle\kaggle.json first
kaggle datasets create -p dist\dataset_v1 --dir-mode zip
```

The release folder already contains `README.md` and `DATASHEET.md`, which is what makes
a Kaggle dataset useful to someone else: it states where the data came from, how the
labels were produced, and what the data must not be used for. The labels are
rule-engine output (weak supervision) and the datasheet says so plainly.
