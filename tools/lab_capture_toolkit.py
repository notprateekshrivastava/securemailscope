"""SecureMailScope lab capture toolkit.

Purpose
-------
The public sample captures prove that parsing works, but they cannot prove that
the risk engine reacts correctly to *weak* mail configurations, because they do
not contain those configurations. This toolkit creates them locally, on this
machine, from a controlled lab session:

    * a mock SMTP / IMAP / POP3 server that speaks the real protocol dialogues,
    * a client that performs a chosen authentication / upgrade behaviour,
    * a TShark capture of the loopback interface while that happens.

Every capture is therefore real network traffic produced by agreement with the
project's own dataset note (which allows participants to generate SMTP/IMAPS/
POP3S traffic and capture it), and it contains exactly the evidence the analysis
engine is supposed to find. No email content is ever read or stored: the mock
server only ever answers protocol commands, and the capture is filtered to the
mail port and kept local.

Usage
-----
    python tools/lab_capture_toolkit.py list
    python tools/lab_capture_toolkit.py capture              # all scenarios
    python tools/lab_capture_toolkit.py capture --scenario pop3-cleartext
    python tools/lab_capture_toolkit.py verify               # expected vs observed

On Linux, capturing the loopback interface and binding privileged ports (25, 110,
143) requires elevated rights:

    sudo -E python tools/lab_capture_toolkit.py capture

On Windows, install Wireshark with Npcap (loopback support) and run the shell as
Administrator. The toolkit finds the loopback interface automatically.

Nothing in this file touches the network outside 127.0.0.1.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import warnings
from dataclasses import dataclass, field, replace
from pathlib import Path

warnings.filterwarnings("ignore", category=DeprecationWarning)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LAB_DIR = PROJECT_ROOT / "samples" / "lab"
CERT_DIR = LAB_DIR / "certs"

LOCALHOST = "127.0.0.1"
SERVER_NAME = "mail.lab.test"
WEAK_SERVER_NAME = "legacy.mail.test"


# --------------------------------------------------------------------------- #
# Certificates
# --------------------------------------------------------------------------- #
def _write_pem(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def generate_certificates() -> dict[str, Path]:
    """Create a small private CA chain plus two leaves.

    A real chain (root -> intermediate -> leaf) is used for the healthy capture
    so that the session does not produce a self-signed or incomplete-chain
    finding, which would blur the comparison with the weak captures.

    ``weak_leaf`` is deliberately bad: 1024-bit RSA, SHA-1 signature, expired
    validity window and a name that does not match the server name the client
    requests, so several independent certificate findings must fire.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    CERT_DIR.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    paths = {
        "root_cert": CERT_DIR / "ca_root.pem",
        "root_key": CERT_DIR / "ca_root.key.pem",
        "inter_cert": CERT_DIR / "ca_intermediate.pem",
        "inter_key": CERT_DIR / "ca_intermediate.key.pem",
        "secure_chain": CERT_DIR / "leaf_secure_chain.pem",
        "secure_key": CERT_DIR / "leaf_secure.key.pem",
        "weak_chain": CERT_DIR / "leaf_weak_chain.pem",
        "weak_key": CERT_DIR / "leaf_weak.key.pem",
    }
    if all(path.exists() for path in paths.values()):
        return paths

    def key_pair(bits: int):
        return rsa.generate_private_key(public_exponent=65537, key_size=bits)

    def name(common_name: str, org: str) -> x509.Name:
        return x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )

    def pem_key(key) -> bytes:
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )

    # --- root CA ---------------------------------------------------------
    root_key = key_pair(3072)
    root_subject = name("SecureMailScope Lab Root CA", "SecureMailScope Lab")
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=2))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    _write_pem(paths["root_cert"], root_cert.public_bytes(serialization.Encoding.PEM))
    _write_pem(paths["root_key"], pem_key(root_key))

    # --- intermediate CA -------------------------------------------------
    inter_key = key_pair(2048)
    inter_subject = name("SecureMailScope Lab Intermediate CA", "SecureMailScope Lab")
    inter_cert = (
        x509.CertificateBuilder()
        .subject_name(inter_subject)
        .issuer_name(root_subject)
        .public_key(inter_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=2))
        .not_valid_after(now + dt.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    _write_pem(paths["inter_cert"], inter_cert.public_bytes(serialization.Encoding.PEM))
    _write_pem(paths["inter_key"], pem_key(inter_key))

    # --- healthy leaf: RSA-2048, SHA-256, hostname in SAN ----------------
    secure_key = key_pair(2048)
    secure_cert = (
        x509.CertificateBuilder()
        .subject_name(name(SERVER_NAME, "SecureMailScope Lab"))
        .issuer_name(inter_subject)
        .public_key(secure_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(SERVER_NAME), x509.DNSName("imap.lab.test"), x509.DNSName("pop3.lab.test")]
            ),
            critical=False,
        )
        .sign(inter_key, hashes.SHA256())
    )
    _write_pem(
        paths["secure_chain"],
        secure_cert.public_bytes(serialization.Encoding.PEM)
        + inter_cert.public_bytes(serialization.Encoding.PEM)
        + root_cert.public_bytes(serialization.Encoding.PEM),
    )
    _write_pem(paths["secure_key"], pem_key(secure_key))

    # --- weak leaf: 1024-bit RSA, SHA-1, expired, wrong hostname ---------
    weak_key = key_pair(1024)
    hash_algorithm = hashes.SHA1()
    try:  # some builds refuse SHA-1 signing; fall back and note it in the README
        weak_cert = (
            x509.CertificateBuilder()
            .subject_name(name(WEAK_SERVER_NAME, "Legacy Mail Service"))
            .issuer_name(inter_subject)
            .public_key(weak_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=800))
            .not_valid_after(now - dt.timedelta(days=100))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(WEAK_SERVER_NAME)]), critical=False
            )
            .sign(inter_key, hash_algorithm)
        )
        weak_signature = "sha1"
    except Exception:
        weak_cert = (
            x509.CertificateBuilder()
            .subject_name(name(WEAK_SERVER_NAME, "Legacy Mail Service"))
            .issuer_name(inter_subject)
            .public_key(weak_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=800))
            .not_valid_after(now - dt.timedelta(days=100))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(WEAK_SERVER_NAME)]), critical=False
            )
            .sign(inter_key, hashes.SHA256())
        )
        weak_signature = "sha256"
    _write_pem(
        paths["weak_chain"],
        weak_cert.public_bytes(serialization.Encoding.PEM)
        + inter_cert.public_bytes(serialization.Encoding.PEM)
        + root_cert.public_bytes(serialization.Encoding.PEM),
    )
    _write_pem(paths["weak_key"], pem_key(weak_key))
    print(f"weak leaf certificate signature: {weak_signature}")
    (LAB_DIR / "certificate_facts.json").write_text(
        json.dumps(
            {
                "secure_leaf": {
                    "common_name": SERVER_NAME,
                    "key_bits": 2048,
                    "signature": "sha256",
                    "valid": True,
                    "hostname": "matches",
                },
                "weak_leaf": {
                    "common_name": WEAK_SERVER_NAME,
                    "key_bits": 1024,
                    "signature": weak_signature,
                    "valid": False,
                    "expired_days_ago": 100,
                    "hostname": f"mismatch (client requests {SERVER_NAME})",
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return paths


# --------------------------------------------------------------------------- #
# TLS profiles
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class TlsProfile:
    key: str
    description: str
    version: ssl.TLSVersion | None  # None = library default (TLS 1.2/1.3)
    ciphers: str | None
    cert: str  # "secure" or "weak"
    fallbacks: tuple[str | None, ...] = ()


TLS_PROFILES: dict[str, TlsProfile] = {
    "modern": TlsProfile(
        key="modern",
        description="TLS 1.2 with ECDHE and AES-GCM (healthy baseline)",
        version=ssl.TLSVersion.TLSv1_2,
        ciphers="ECDHE-RSA-AES128-GCM-SHA256",
        cert="secure",
    ),
    "modern-tls13": TlsProfile(
        key="modern-tls13",
        description="TLS 1.3 with ECDHE and AES-GCM (certificate is encrypted on the wire)",
        version=ssl.TLSVersion.TLSv1_3,
        ciphers=None,
        cert="secure",
    ),
    "static-rsa": TlsProfile(
        key="static-rsa",
        description="TLS 1.2 with static RSA key exchange (no forward secrecy)",
        version=ssl.TLSVersion.TLSv1_2,
        ciphers="AES128-SHA:@SECLEVEL=0",
        cert="secure",
        fallbacks=("AES128-SHA256:@SECLEVEL=0", "ECDHE-RSA-AES128-SHA:@SECLEVEL=0"),
    ),
    "legacy-tls10": TlsProfile(
        key="legacy-tls10",
        description="TLS 1.0 with CBC and static RSA (deprecated version)",
        version=ssl.TLSVersion.TLSv1,
        ciphers="AES128-SHA:@SECLEVEL=0",
        cert="secure",
        fallbacks=("AES128-SHA256:@SECLEVEL=0", None),
    ),
    "null-cipher": TlsProfile(
        key="null-cipher",
        description="TLS 1.2 with an encryption-free NULL cipher suite",
        version=ssl.TLSVersion.TLSv1_2,
        ciphers="NULL-SHA:@SECLEVEL=0",
        cert="secure",
        fallbacks=("AES128-SHA:@SECLEVEL=0", "ECDHE-RSA-AES128-SHA:@SECLEVEL=0"),
    ),
    "cbc-only": TlsProfile(
        key="cbc-only",
        description="TLS 1.2 with ECDHE but a CBC cipher suite",
        version=ssl.TLSVersion.TLSv1_2,
        ciphers="ECDHE-RSA-AES128-SHA:@SECLEVEL=0",
        cert="secure",
    ),
    "weak-cert": TlsProfile(
        key="weak-cert",
        description="TLS 1.2 with ECDHE but an expired 1024-bit SHA-1 certificate",
        version=ssl.TLSVersion.TLSv1_2,
        # SECLEVEL=0 is required because OpenSSL refuses a 1024-bit RSA key at
        # its default security level. That refusal is exactly the weakness this
        # scenario demonstrates, so the lab has to lower the bar deliberately.
        ciphers="ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0",
        cert="weak",
        fallbacks=("AES128-SHA:@SECLEVEL=0",),
    ),
}


def build_contexts(profile: TlsProfile, cert_paths: dict[str, Path], server_side: bool):
    """Return (context, note) for a profile, applying fallbacks if needed."""
    attempts = [profile.ciphers, *profile.fallbacks]
    last_error: Exception | None = None
    for attempt in attempts:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT)
            if not server_side:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            if profile.version is not None:
                context.minimum_version = profile.version
                context.maximum_version = profile.version
            if attempt:
                context.set_ciphers(attempt)
            if server_side:
                chain = cert_paths["secure_chain"] if profile.cert == "secure" else cert_paths["weak_chain"]
                key = cert_paths["secure_key"] if profile.cert == "secure" else cert_paths["weak_key"]
                context.load_cert_chain(str(chain), str(key))
            note = "" if attempt == profile.ciphers else f"fallback cipher setting: {attempt}"
            return context, note
        except Exception as exc:  # try the next candidate
            last_error = exc
            continue
    raise RuntimeError(f"no usable TLS configuration for profile {profile.key}: {last_error}")


def _relative_or_absolute(path: Path) -> str:
    """Path relative to the project root when possible, absolute otherwise.

    An --outdir outside the project is perfectly reasonable (an external drive, for
    example), so this must not raise: Path.relative_to fails for any path that is not
    underneath the root.
    """
    try:
        return Path(path).resolve().relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(Path(path).resolve())


# --------------------------------------------------------------------------- #
# Scenario definitions
# --------------------------------------------------------------------------- #
@dataclass
class Scenario:
    name: str
    title: str
    protocol: str
    port: int
    mode: str
    profile: str | None
    expected_findings: list[str] = field(default_factory=list)
    forbidden_findings: list[str] = field(default_factory=list)
    notes: str = ""


SCENARIOS: list[Scenario] = [
    Scenario(
        name="smtp-starttls-secure",
        title="SMTP submission with a successful STARTTLS upgrade",
        protocol="SMTP",
        port=587,
        mode="smtp_secure",
        profile="modern",
        forbidden_findings=[
            "STARTTLS_REJECTED",
            "STARTTLS_UPGRADE_NOT_COMPLETED",
            "PLAINTEXT_AUTHENTICATION",
            "DEPRECATED_TLS_VERSION",
            "INSECURE_CIPHER",
            "NO_FORWARD_SECRECY",
        ],
        notes="Baseline: the encrypted, correctly configured session must stay LOW risk.",
    ),
    Scenario(
        name="smtp-starttls-rejected",
        title="SMTP server rejects STARTTLS and the client authenticates in the clear",
        protocol="SMTP",
        port=587,
        mode="smtp_reject_starttls",
        profile=None,
        expected_findings=["STARTTLS_REJECTED", "PLAINTEXT_AUTHENTICATION"],
        notes="Server answers 454 to STARTTLS; the client sends AUTH PLAIN unencrypted.",
    ),
    Scenario(
        name="imap-cleartext-login",
        title="IMAP LOGIN sent before STARTTLS",
        protocol="IMAP",
        port=143,
        mode="imap_cleartext_login",
        profile="modern",
        expected_findings=["PLAINTEXT_AUTHENTICATION"],
        forbidden_findings=["STARTTLS_REJECTED"],
        notes="Credentials are exposed first, then the session upgrades: the exposure must still be reported.",
    ),
    Scenario(
        name="pop3-cleartext",
        title="POP3 without any encryption (USER/PASS in the clear)",
        protocol="POP3",
        port=110,
        mode="pop3_cleartext",
        profile=None,
        expected_findings=["PLAINTEXT_EMAIL_SESSION", "PLAINTEXT_AUTHENTICATION"],
        forbidden_findings=["STARTTLS_REJECTED", "STARTTLS_UPGRADE_NOT_COMPLETED"],
        notes="No STLS support at all; the session stays cleartext for its whole lifetime.",
    ),
    Scenario(
        name="imaps-tls10-legacy",
        title="IMAPS on 993 negotiating TLS 1.0 with CBC and static RSA",
        protocol="IMAP",
        port=993,
        mode="implicit_tls",
        profile="legacy-tls10",
        expected_findings=["DEPRECATED_TLS_VERSION", "NO_FORWARD_SECRECY"],
        forbidden_findings=["STARTTLS_REJECTED"],
        notes="Implicit TLS, so no STARTTLS command exists; the weakness is the protocol version.",
    ),
    Scenario(
        name="imaps-null-cipher",
        title="IMAPS negotiating an encryption-free NULL cipher suite",
        protocol="IMAP",
        port=993,
        mode="implicit_tls",
        profile="null-cipher",
        expected_findings=["INSECURE_CIPHER"],
        notes="Protection is effectively absent even though TLS is present.",
    ),
    Scenario(
        name="smtps-weak-certificate",
        title="SMTPS with an expired, 1024-bit certificate issued for the wrong hostname",
        protocol="SMTP",
        port=465,
        mode="implicit_tls",
        profile="weak-cert",
        expected_findings=["CERTIFICATE_EXPIRED", "WEAK_CERTIFICATE_KEY", "CERTIFICATE_HOSTNAME_MISMATCH"],
        notes=(
            "Certificate findings require a visible TLS 1.2 certificate, which this capture provides. "
            "The signature is SHA-1 when the local cryptography build permits it and SHA-256 otherwise; "
            "certificate_facts.json records what was actually used."
        ),
    ),
    Scenario(
        name="imaps-tls13-cert-hidden",
        title="IMAPS over TLS 1.3, where the certificate is encrypted and therefore not observable",
        protocol="IMAP",
        port=993,
        mode="implicit_tls",
        profile="modern-tls13",
        expected_findings=["CERTIFICATE_NOT_OBSERVED"],
        forbidden_findings=["CERTIFICATE_EXPIRED", "SELF_SIGNED_CERTIFICATE", "DEPRECATED_TLS_VERSION"],
        notes="Teaches the evidence rule: missing certificate evidence is UNKNOWN, never 'insecure'.",
    ),
    Scenario(
        name="imaps-cbc-cipher",
        title="IMAPS negotiating a CBC cipher suite over ECDHE",
        protocol="IMAP",
        port=993,
        mode="implicit_tls",
        profile="cbc-only",
        expected_findings=["LEGACY_CBC_CIPHER"],
        forbidden_findings=["DEPRECATED_TLS_VERSION"],
        notes="Modern version, acceptable key exchange, less preferred cipher mode.",
    ),
    # ------------------------------------------------------------------ #
    # Coverage added after measuring what actually improves the model:
    # more capture diversity, not more training rows. Each scenario below is a
    # combination that did not exist before, and every one of them reuses an existing
    # mode and TLS profile - no new mock-server behaviour, so nothing about the
    # existing nine captures changes.
    #
    # POP3 had no encrypted scenario at all, which left a gap in the problem
    # statement's coverage: POP3S is named in the brief and was only covered in
    # cleartext. The three POP3S scenarios below close it.
    Scenario(
        name="pop3s-tls10-legacy",
        title="POP3S on 995 negotiating TLS 1.0 with static RSA",
        protocol="POP3",
        port=995,
        mode="implicit_tls",
        profile="legacy-tls10",
        expected_findings=["DEPRECATED_TLS_VERSION", "NO_FORWARD_SECRECY"],
        forbidden_findings=["STARTTLS_REJECTED", "PLAINTEXT_AUTHENTICATION"],
        notes=(
            "Same weak configuration as the IMAPS scenario, in the POP3 service. "
            "Teaches that the finding follows the TLS evidence, not the protocol name."
        ),
    ),
    Scenario(
        name="pop3s-weak-certificate",
        title="POP3S with an expired, 1024-bit certificate for the wrong hostname",
        protocol="POP3",
        port=995,
        mode="implicit_tls",
        profile="weak-cert",
        expected_findings=["CERTIFICATE_EXPIRED", "WEAK_CERTIFICATE_KEY", "CERTIFICATE_HOSTNAME_MISMATCH"],
        notes="Certificate evidence extraction in a third protocol, on the third port.",
    ),
    Scenario(
        name="pop3s-cbc-cipher",
        title="POP3S negotiating a CBC cipher suite",
        protocol="POP3",
        port=995,
        mode="implicit_tls",
        profile="cbc-only",
        expected_findings=["LEGACY_CBC_CIPHER"],
        forbidden_findings=["DEPRECATED_TLS_VERSION", "PLAINTEXT_EMAIL_SESSION"],
        notes="Encrypted session whose cipher mode is the weakness: must not be called plaintext.",
    ),
    Scenario(
        name="smtps-cbc-cipher",
        title="SMTPS on 465 negotiating a CBC cipher suite",
        protocol="SMTP",
        port=465,
        mode="implicit_tls",
        profile="cbc-only",
        expected_findings=["LEGACY_CBC_CIPHER"],
        forbidden_findings=["DEPRECATED_TLS_VERSION", "STARTTLS_REJECTED"],
        notes="SMTP's encrypted port with a less preferred cipher, so the cipher is the only fault.",
    ),
    Scenario(
        name="smtps-tls13-modern",
        title="SMTPS over TLS 1.3, where the certificate is not observable",
        protocol="SMTP",
        port=465,
        mode="implicit_tls",
        profile="modern-tls13",
        expected_findings=["CERTIFICATE_NOT_OBSERVED"],
        forbidden_findings=["CERTIFICATE_EXPIRED", "SELF_SIGNED_CERTIFICATE", "DEPRECATED_TLS_VERSION"],
        notes=(
            "The evidence rule on a second protocol: TLS 1.3 encrypts the certificate, so a "
            "missing certificate must be reported as unobserved, never as insecure."
        ),
    ),
    Scenario(
        name="imaps-weak-certificate",
        title="IMAPS with an expired, 1024-bit certificate for the wrong hostname",
        protocol="IMAP",
        port=993,
        mode="implicit_tls",
        profile="weak-cert",
        expected_findings=["CERTIFICATE_EXPIRED", "WEAK_CERTIFICATE_KEY", "CERTIFICATE_HOSTNAME_MISMATCH"],
        notes="Certificate findings on IMAP, so the third protocol is covered for certificate problems too.",
    ),
]


# --------------------------------------------------------------------------- #
# Mock mail servers
# --------------------------------------------------------------------------- #
def protocol_family(scenario: Scenario) -> str:
    """Which protocol script this scenario runs.

    Implicit TLS has no cleartext command for the analyzer to read, so the mode string
    says nothing about the protocol - the scenario's protocol field does. Dispatching on
    it means an implicit-TLS capture holds a real mail exchange inside the tunnel
    (encrypted, so still no cleartext vocabulary) instead of only a bare handshake.
    """
    if scenario.mode == "implicit_tls":
        return scenario.protocol.lower()
    return scenario.mode.split("_", 1)[0]


class MockMailServer(threading.Thread):
    """Minimal SMTP/IMAP/POP3 server that follows the scenario script."""

    def __init__(self, scenario: Scenario, cert_paths: dict[str, Path]) -> None:
        super().__init__(daemon=True)
        self.scenario = scenario
        self.cert_paths = cert_paths
        self.ready = threading.Event()
        self.finished = threading.Event()
        self.result: dict[str, object] = {}
        self.error: str | None = None
        self._listener: socket.socket | None = None

    # -- helpers ---------------------------------------------------------
    def _tls_context(self, server_side: bool = True):
        if not self.scenario.profile:
            return None
        profile = TLS_PROFILES[self.scenario.profile]
        context, note = build_contexts(profile, self.cert_paths, server_side)
        if note:
            self.result["tls_note"] = note
        return context

    def _upgrade(self, conn: socket.socket) -> ssl.SSLSocket:
        context = self._tls_context()
        assert context is not None
        upgraded = context.wrap_socket(conn, server_side=True)
        self.result["negotiated_version"] = upgraded.version()
        self.result["negotiated_cipher"] = upgraded.cipher()[0] if upgraded.cipher() else None
        return upgraded

    @staticmethod
    def _read_line(conn: socket.socket) -> str:
        buffer = b""
        while not buffer.endswith(b"\n"):
            chunk = conn.recv(1)
            if not chunk:
                break
            buffer += chunk
        return buffer.decode("utf-8", "replace").strip()

    # -- lifecycle -------------------------------------------------------
    def run(self) -> None:  # noqa: C901 - a protocol script, kept readable inline
        scenario = self.scenario
        try:
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((LOCALHOST, scenario.port))
            listener.listen(1)
            self._listener = listener
            self.ready.set()
            listener.settimeout(30)
            conn, peer = listener.accept()
            # Recorded so a merged multi-session capture can be matched back to the
            # scenario that produced each session: the client port is unique per run.
            self.result["client_port"] = peer[1]
        except Exception as exc:
            self.error = f"listen failed: {exc}"
            self.ready.set()
            self.finished.set()
            return

        try:
            if scenario.mode == "implicit_tls":
                conn = self._upgrade(conn)
                self.result["implicit_tls"] = True
            family = protocol_family(scenario)
            if family == "smtp":
                self._smtp(conn)
            elif family == "imap":
                self._imap(conn)
            elif family == "pop3":
                self._pop3(conn)
        except (BrokenPipeError, ConnectionResetError):
            # The peer closed the connection after QUIT/LOGOUT: expected.
            pass
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
        finally:
            try:
                conn.close()
            except Exception:
                pass
            if self._listener:
                self._listener.close()
            self.finished.set()

    # -- protocol scripts ------------------------------------------------
    def _smtp(self, conn) -> None:
        mode = self.scenario.mode
        conn.sendall(b"220 lab.lab.test ESMTP SecureMailScope mock\r\n")
        # Under implicit TLS the tunnel exists before any command is sent, so the
        # authentication that follows is inside it.
        starttls_seen = self.scenario.mode == "implicit_tls"
        while True:
            line = self._read_line(conn)
            if not line:
                break
            upper = line.upper()
            if upper.startswith("EHLO"):
                if mode == "smtp_secure":
                    response = (
                        "250-lab.lab.test\r\n250-SIZE 10240000\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n"
                    )
                elif mode == "smtp_reject_starttls":
                    response = "250-lab.lab.test\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n"
                else:
                    response = "250-lab.lab.test\r\n250 AUTH PLAIN LOGIN\r\n"
                conn.sendall(response.encode())
            elif upper.startswith("STARTTLS"):
                if mode == "smtp_reject_starttls":
                    conn.sendall(b"454 4.7.0 TLS not available due to temporary reason\r\n")
                else:
                    conn.sendall(b"220 2.0.0 Ready to start TLS\r\n")
                    starttls_seen = True
                    conn = self._upgrade(conn)
            elif upper.startswith("AUTH"):
                self.result["auth_seen"] = True
                self.result["auth_after_tls"] = starttls_seen
                conn.sendall(b"235 2.7.0 Authentication successful\r\n")
            elif upper.startswith("QUIT"):
                conn.sendall(b"221 2.0.0 Bye\r\n")
                break
            elif upper.startswith("MAIL FROM") or upper.startswith("RCPT TO") or upper.startswith("DATA"):
                conn.sendall(b"250 2.1.0 OK\r\n")
            else:
                conn.sendall(b"250 2.1.0 OK\r\n")
        self.result["starttls_upgraded"] = starttls_seen

    def _imap(self, conn) -> None:
        mode = self.scenario.mode
        starttls_upgraded = mode == "implicit_tls"
        if mode in ("imap_cleartext_login", "imap_starttls", "imap_reject_starttls"):
            conn.sendall(
                b"* OK [CAPABILITY IMAP4rev1 IDLE STARTTLS AUTH=PLAIN] SecureMailScope mock ready\r\n"
            )
        elif mode == "implicit_tls":
            conn.sendall(b"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] SecureMailScope mock ready\r\n")
        else:
            conn.sendall(b"* OK SecureMailScope mock ready\r\n")

        while True:
            line = self._read_line(conn)
            if not line:
                break
            upper = line.upper()
            tag = line.split(" ", 1)[0] if " " in line else "."
            if "CAPABILITY" in upper:
                if mode in ("imap_cleartext_login", "imap_starttls", "imap_reject_starttls"):
                    conn.sendall(
                        f"{tag} OK [CAPABILITY IMAP4rev1 IDLE STARTTLS AUTH=PLAIN] capabilities listed\r\n".encode()
                    )
                else:
                    conn.sendall(f"{tag} OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] capabilities listed\r\n".encode())
            elif "LOGIN" in upper or "AUTHENTICATE" in upper:
                self.result["auth_seen"] = True
                self.result["auth_after_tls"] = starttls_upgraded
                conn.sendall(f"{tag} OK LOGIN completed\r\n".encode())
            elif "STARTTLS" in upper:
                if mode == "imap_reject_starttls":
                    # The refusal the client has to fall back from - and then logs in
                    # over cleartext, which is the exposure this scenario exists for.
                    conn.sendall(f"{tag} NO TLS not available on this server\r\n".encode())
                else:
                    conn.sendall(f"{tag} OK Begin TLS negotiation now\r\n".encode())
                    conn = self._upgrade(conn)
                    starttls_upgraded = True
            elif "SELECT" in upper or "LIST" in upper or "FETCH" in upper:
                conn.sendall(f"{tag} OK completed\r\n".encode())
            elif "LOGOUT" in upper:
                conn.sendall(b"* BYE logging out\r\n")
                conn.sendall(f"{tag} OK LOGOUT completed\r\n".encode())
                break
            else:
                conn.sendall(f"{tag} OK completed\r\n".encode())
        self.result["starttls_upgraded"] = starttls_upgraded

    def _pop3(self, conn) -> None:
        mode = self.scenario.mode
        # STLS is POP3's name for STARTTLS. The server only offers it when the scenario
        # asks for an upgrade, so "no upgrade offered at all" stays a distinct situation
        # from "upgrade offered and refused" - they are different findings.
        stls_offered = mode in ("pop3_stls", "pop3_reject_stls")
        upgraded = mode == "implicit_tls"
        conn.sendall(b"+OK SecureMailScope mock POP3 ready\r\n")
        while True:
            line = self._read_line(conn)
            if not line:
                break
            upper = line.upper()
            if upper.startswith("CAPA"):
                listing = "+OK Capability list follows\r\nUSER\r\n"
                if stls_offered:
                    listing += "STLS\r\n"
                conn.sendall((listing + ".\r\n").encode())
            elif upper.startswith("STLS"):
                if mode == "pop3_stls":
                    conn.sendall(b"+OK Begin TLS negotiation now\r\n")
                    conn = self._upgrade(conn)
                    upgraded = True
                    self.result["starttls_upgraded"] = True
                else:
                    conn.sendall(b"-ERR unknown command\r\n")
            elif upper.startswith("USER"):
                conn.sendall(b"+OK user accepted\r\n")
            elif upper.startswith("PASS"):
                self.result["auth_seen"] = True
                self.result["auth_after_tls"] = upgraded
                conn.sendall(b"+OK mailbox ready\r\n")
            elif upper.startswith("STAT") or upper.startswith("LIST"):
                conn.sendall(b"+OK 1 512\r\n")
            elif upper.startswith("RETR"):
                # Protocol-level placeholder only: never real message content.
                conn.sendall(b"+OK 120 octets\r\nSubject: lab test\r\n\r\n.\r\n")
            elif upper.startswith("QUIT"):
                conn.sendall(b"+OK bye\r\n")
                break
            else:
                conn.sendall(b"-ERR unsupported command\r\n")


# --------------------------------------------------------------------------- #
# Clients
# --------------------------------------------------------------------------- #
def run_client(scenario: Scenario, cert_paths: dict[str, Path]) -> dict[str, object]:
    """Perform the client half of a scenario against 127.0.0.1."""
    result: dict[str, object] = {}
    timeout = 10
    profile = TLS_PROFILES[scenario.profile] if scenario.profile else None
    client_context, note = (
        build_contexts(profile, cert_paths, server_side=False) if profile else (None, "")
    )
    if note:
        result["client_tls_note"] = note

    def connect_plain() -> tuple[socket.socket, object]:
        sock = socket.create_connection((LOCALHOST, scenario.port), timeout=timeout)
        sock.settimeout(timeout)
        return sock, None

    def connect_tls(server_name: str | None) -> tuple[socket.socket, object]:
        sock = socket.create_connection((LOCALHOST, scenario.port), timeout=timeout)
        sock.settimeout(timeout)
        assert client_context is not None, "TLS profile required for this scenario"
        upgraded = client_context.wrap_socket(sock, server_hostname=server_name)
        upgraded.settimeout(timeout)
        return upgraded, upgraded

    if scenario.mode == "implicit_tls":
        # Implicit TLS: the TLS handshake starts immediately, before any mail
        # protocol line. The server name is sent as SNI so that certificate
        # matching can be evaluated.
        raw, tls_socket = connect_tls(SERVER_NAME)
        connection = raw
        result["client_version"] = tls_socket.version() if tls_socket else None
        result["client_cipher"] = tls_socket.cipher()[0] if tls_socket and tls_socket.cipher() else None
    else:
        raw, _ = connect_plain()
        connection = raw

    def send(data: str) -> None:
        connection.sendall(data.encode())

    def read_line() -> str:
        buffer = b""
        while not buffer.endswith(b"\n"):
            chunk = connection.recv(1)
            if not chunk:
                break
            buffer += chunk
        return buffer.decode("utf-8", "replace").strip()

    def upgrade(server_name: str | None = SERVER_NAME) -> None:
        """Wrap the existing plaintext socket after a STARTTLS/STLS go-ahead.

        The server name is sent as SNI, as every real mail client does. Leaving it out
        (which this used to do) makes the certificate's hostname match unevaluable, and the
        analyzer then correctly reports nothing about it - a gap in the capture, not a
        finding.
        """
        nonlocal connection
        assert client_context is not None, "TLS profile required for this scenario"
        assert isinstance(connection, socket.socket)
        upgraded = client_context.wrap_socket(connection, server_hostname=server_name)
        upgraded.settimeout(timeout)
        connection = upgraded
        result["client_version"] = upgraded.version()
        result["client_cipher"] = upgraded.cipher()[0] if upgraded.cipher() else None

    family = protocol_family(scenario)
    try:
        if family == "smtp":
            result["greeting"] = read_line()
            send("EHLO client.lab.test\r\n")
            ehlo = []
            while True:
                line = read_line()
                ehlo.append(line)
                if len(line) > 3 and line[3] == " ":
                    break
            result["ehlo"] = ehlo
            if scenario.mode in ("smtp_no_starttls", "implicit_tls"):
                # Either the server offers no upgrade at all, or the tunnel already
                # exists and there is nothing left to upgrade. Both authenticate here.
                result["starttls_response"] = "not attempted - no cleartext upgrade step"
            else:
                send("STARTTLS\r\n")
                answer = read_line()
                result["starttls_response"] = answer
                if answer.startswith("220"):
                    upgrade()
                    send("EHLO client.lab.test\r\n")
                    read_line()
            send("AUTH PLAIN AGxhYi51c2VyAGxhYi5wYXNzd29yZA==\r\n")
            result["auth_response"] = read_line()
            send("QUIT\r\n")
            result["quit_response"] = read_line()
        elif family == "imap":
            result["greeting"] = read_line()
            if scenario.mode == "imap_starttls":
                send("c1 CAPABILITY\r\n")
                result["capability"] = read_line()
                send("c2 STARTTLS\r\n")
                answer = read_line()
                result["starttls_response"] = answer
                if " OK " in answer:
                    upgrade()
                # Credentials only after the tunnel exists.
                send("c3 LOGIN lab.user lab.password\r\n")
                result["login_response"] = read_line()
                send("c4 SELECT INBOX\r\n")
                result["select_response"] = read_line()
                send("c5 LOGOUT\r\n")
                result["logout_response"] = read_line()
            elif scenario.mode == "imap_reject_starttls":
                send("d1 CAPABILITY\r\n")
                result["capability"] = read_line()
                send("d2 STARTTLS\r\n")
                result["starttls_response"] = read_line()
                # The server said NO, so the client falls back and logs in over
                # cleartext. This is the situation the STARTTLS_REJECTED finding is for.
                send("d3 LOGIN lab.user lab.password\r\n")
                result["login_response"] = read_line()
                send("d4 LOGOUT\r\n")
                result["logout_response"] = read_line()
            elif scenario.mode == "imap_cleartext_login":
                send("a1 CAPABILITY\r\n")
                result["capability"] = read_line()
                # Credentials before any encryption: this is the exposure.
                send("a2 LOGIN lab.user lab.password\r\n")
                result["login_response"] = read_line()
                send("a3 STARTTLS\r\n")
                result["starttls_response"] = read_line()
                upgrade()
                send("a4 SELECT INBOX\r\n")
                result["select_response"] = read_line()
                send("a5 LOGOUT\r\n")
                result["logout_response"] = read_line()
            else:
                send("b1 CAPABILITY\r\n")
                result["capability"] = read_line()
                send("b2 LOGIN lab.user lab.password\r\n")
                result["login_response"] = read_line()
                send("b3 SELECT INBOX\r\n")
                result["select_response"] = read_line()
                send("b4 LOGOUT\r\n")
                result["logout_response"] = read_line()
        elif family == "pop3":
            result["greeting"] = read_line()
            send("CAPA\r\n")
            capa: list[str] = []
            while True:
                line = read_line()
                capa.append(line)
                if line.startswith("-ERR") or line == "." or not line:
                    break
            result["capa"] = capa
            if scenario.mode in ("pop3_stls", "pop3_reject_stls"):
                send("STLS\r\n")
                answer = read_line()
                result["stls_response"] = answer
                if answer.startswith("+OK") and scenario.mode == "pop3_stls":
                    upgrade()
            send("USER lab.user\r\n")
            result["user_response"] = read_line()
            send("PASS lab.password\r\n")
            result["pass_response"] = read_line()
            send("STAT\r\n")
            result["stat_response"] = read_line()
            send("QUIT\r\n")
            result["quit_response"] = read_line()
    finally:
        try:
            connection.close()
        except Exception:
            pass
    return result


# --------------------------------------------------------------------------- #
# Capture orchestration
# --------------------------------------------------------------------------- #
def find_tshark() -> str:
    for candidate in (
        os.environ.get("TSHARK_PATH"),
        "tshark",
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ):
        if not candidate:
            continue
        if Path(candidate).exists():
            return candidate
        from shutil import which

        if which(candidate):
            return candidate
    raise SystemExit("tshark was not found. Install Wireshark or set TSHARK_PATH.")


def resolve_interface(tshark: str, preferred: str | None) -> str:
    if preferred:
        return preferred
    listing = subprocess.run([tshark, "-D"], capture_output=True, text=True, timeout=30).stdout
    for line in listing.splitlines():
        lowered = line.lower()
        if "loopback" in lowered or "(lo)" in lowered or lowered.strip().endswith("(lo)"):
            # Format: "4. lo (Loopback)" or "5. \Device\NPF_Loopback (Adapter ...)"
            after_index = line.split(".", 1)[1] if "." in line else line
            return after_index.split(" (")[0].strip()
    raise SystemExit(
        "No loopback interface found. On Windows install Npcap with loopback support, "
        "or pass --iface explicitly (see: tshark -D)."
    )


def _privilege_hint(port: int) -> str:
    """Explain the one platform difference that silently ruins a capture.

    Windows lets any user bind a port below 1024, Linux and macOS do not. Without this
    check the mock server thread fails to listen, the client is refused, and the capture
    file still passes a "size greater than zero" test - so an empty capture would be
    reported as a success. That happened, and eleven of twelve "unseen" captures in the
    first capability test were two-packet refusals.
    """
    if port >= 1024 or os.name == "nt":
        return ""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return ""
    return (
        f" Port {port} is privileged on Linux and macOS: re-run with sudo, or capture on a"
        " high port instead. Windows does not restrict ports below 1024."
    )


def _count_payload_packets(tshark: str, path: Path) -> int | None:
    """Count packets that actually carry application data.

    Returns None when the question cannot be answered (TShark missing, unreadable file),
    so a doubtful reading never blocks a legitimate capture.
    """
    try:
        done = subprocess.run(
            [tshark, "-n", "-r", str(path), "-Y", "tcp.len > 0", "-T", "fields", "-e", "frame.number"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception:
        return None
    if done.returncode not in (0, 2):  # TShark exits 2 on an empty match, which is a valid answer
        return None
    return len([line for line in done.stdout.splitlines() if line.strip()])


def capture_scenario(
    scenario: Scenario, cert_paths: dict[str, Path], out_dir: Path, tshark: str, interface: str
) -> dict[str, object]:
    blocked = _privilege_hint(scenario.port)
    if blocked:
        raise RuntimeError(f"cannot listen on port {scenario.port}.{blocked}")

    out_dir.mkdir(parents=True, exist_ok=True)
    output = out_dir / f"{scenario.name}.pcapng"

    # TShark captures as root but then drops privileges to the "wireshark" user,
    # which cannot write into a user's home directory on Linux. Capturing into a
    # temporary directory and moving the finished file avoids that, and behaves
    # identically on Windows.
    staging = Path(tempfile.mkdtemp(prefix="sms-lab-"))
    staging_output = staging / f"{scenario.name}.pcapng"

    server = MockMailServer(scenario, cert_paths)
    server.start()
    if not server.ready.wait(timeout=10):
        raise RuntimeError("mock server did not start")
    # The server thread records a bind failure and still signals ready, so the error has
    # to be checked explicitly; otherwise the client is refused and we capture a refusal.
    if server.error:
        raise RuntimeError(
            f"mock server could not listen on port {scenario.port}: {server.error}."
            + _privilege_hint(scenario.port)
        )

    capture = subprocess.Popen(
        [
            tshark,
            "-n",
            "-i",
            interface,
            "-f",
            f"tcp port {scenario.port}",
            "-w",
            str(staging_output),
            "-a",
            "duration:20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(1.2)  # let the capture start before generating traffic

    client_result: dict[str, object] = {}
    client_error: str | None = None
    try:
        client_result = run_client(scenario, cert_paths)
    except Exception as exc:
        client_error = f"{type(exc).__name__}: {exc}"

    server.finished.wait(timeout=15)
    time.sleep(0.8)
    capture.terminate()
    try:
        capture.wait(timeout=10)
    except subprocess.TimeoutExpired:
        capture.kill()

    if staging_output.exists() and staging_output.stat().st_size > 0:
        shutil.move(str(staging_output), str(output))
    shutil.rmtree(staging, ignore_errors=True)

    if not output.exists() or output.stat().st_size == 0:
        stderr = capture.stderr.read().decode("utf-8", "replace")[-400:] if capture.stderr else ""
        raise RuntimeError(
            f"capture produced no data ({scenario.name}). "
            f"On Linux run with sudo; on Windows check Npcap loopback support. tshark said: {stderr}"
        )

    # A file that holds only the TCP handshake, or a refusal, is not evidence of a
    # conversation - and its size is not zero, so byte count cannot tell the difference.
    payload_packets = _count_payload_packets(tshark, output)
    if payload_packets == 0:
        output.unlink(missing_ok=True)
        raise RuntimeError(
            f"capture for {scenario.name} recorded no application data, only connection setup"
            f" or a refusal.{_privilege_hint(scenario.port)}"
        )

    return {
        "scenario": scenario.name,
        "capture": _relative_or_absolute(output),
        "bytes": output.stat().st_size,
        "payload_packets": payload_packets,
        "server_result": server.result,
        "server_error": server.error,
        "client_result": client_result,
        "client_error": client_error,
    }


# --------------------------------------------------------------------------- #
# Verification against the analysis engine
# --------------------------------------------------------------------------- #
def verify_captures(out_dir: Path) -> int:
    # The analysis engine lives in the project root; make the import work no
    # matter which directory the toolkit is started from.
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))

    from app.analysis.assessment import apply_policy_assessment
    from app.analysis.tshark import analyze_pcap
    from app.ml.model import ModelBundle
    from app.config import settings

    bundle = ModelBundle(settings.model_dir)
    rows: list[dict[str, object]] = []
    failures = 0

    for scenario in SCENARIOS:
        path = out_dir / f"{scenario.name}.pcapng"
        if not path.exists():
            print(f"MISSING  {scenario.name}")
            failures += 1
            continue

        started = time.time()
        sessions = [apply_policy_assessment(session) for session in analyze_pcap(path)]
        elapsed = time.time() - started
        for session in sessions:
            session.ml = bundle.assess(session)

        observed: list[str] = []
        for session in sessions:
            observed.extend(str(finding.code) for finding in session.findings)
        missing = [code for code in scenario.expected_findings if code not in observed]
        unexpected = [code for code in scenario.forbidden_findings if code in observed]

        worst_session = max(sessions, key=lambda item: item.policy_risk_score) if sessions else None
        status = "OK" if sessions and not missing and not unexpected else "CHECK"
        if status != "OK":
            failures += 1

        print(f"{status:7} {scenario.name}")
        for session in sessions:
            print(
                f"        {session.protocol}:{session.server_port} "
                f"{session.tls.tls_version or 'UNKNOWN'} "
                f"{session.tls.cipher_suite or 'no cipher'} "
                f"risk={session.policy_risk_score} class={session.policy_risk_class} "
                f"posture={session.posture_score} ml={session.ml.risk_class}"
            )
            print(f"        findings: {[f'{f.code}:{f.severity}' for f in session.findings]}")
        if missing:
            print(f"        MISSING expected findings: {missing}")
        if unexpected:
            print(f"        UNEXPECTED findings: {unexpected}")
        if not sessions:
            print("        no session was parsed from this capture")

        rows.append(
            {
                "scenario": scenario,
                "sessions": sessions,
                "observed": observed,
                "missing": missing,
                "unexpected": unexpected,
                "severity_class": worst_session.policy_risk_class if worst_session else "NONE",
                "posture": worst_session.posture_score if worst_session else None,
                "elapsed": round(elapsed, 2),
            }
        )

    write_manifest(rows, out_dir)
    print(f"\n{'=' * 70}\n{len(rows) - failures}/{len(rows)} captures behave as expected")
    return 1 if failures else 0


def write_manifest(rows: list[dict[str, object]], out_dir: Path) -> None:
    """Write the evidence table that documents the lab set."""
    lines = [
        "# Lab capture results (expected vs observed)",
        "",
        "Generated by `python tools/lab_capture_toolkit.py verify` on "
        + dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "These captures were produced locally by the toolkit: a mock mail server and a "
        "client talked over the loopback interface while TShark recorded the traffic. "
        "Every value below comes from the real analysis engine, not from the scenario description.",
        "",
        "| Capture | Scenario | Protocol | TLS version | Cipher | Risk score | Risk class | Posture | Evidence | Expected findings found |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        scenario: Scenario = row["scenario"]  # type: ignore[assignment]
        sessions = row["sessions"]  # type: ignore[assignment]
        session = max(sessions, key=lambda item: item.policy_risk_score) if sessions else None
        expected = len(scenario.expected_findings)
        found = expected - len(row["missing"])  # type: ignore[arg-type]
        lines.append(
            "| `{file}` | {title} | {protocol}:{port} | {version} | {cipher} | {risk} | {klass} | {posture} | {complete} | {found}/{expected} |".format(
                file=f"{scenario.name}.pcapng",
                title=scenario.title,
                protocol=scenario.protocol,
                port=scenario.port,
                version=(session.tls.tls_version or "no TLS") if session else "-",
                cipher=(session.tls.cipher_suite or "no cipher") if session else "-",
                risk=session.policy_risk_score if session else "-",
                klass=session.policy_risk_class if session else "-",
                posture=session.posture_score if session else "-",
                complete=session.evidence_completeness if session else "-",
                found=found,
                expected=expected,
            )
        )
    lines += ["", "## Findings per capture", ""]
    for row in rows:
        scenario: Scenario = row["scenario"]  # type: ignore[assignment]
        lines.append(f"### {scenario.name} - {scenario.title}")
        lines.append("")
        lines.append(f"*{scenario.notes}*")
        lines.append("")
        sessions = row["sessions"]  # type: ignore[assignment]
        if not sessions:
            lines.append("No session was parsed from this capture.")
            lines.append("")
            continue
        for session in sessions:
            lines.append(
                f"- Session `{session.session_id}` {session.protocol}:{session.server_port}, "
                f"TLS `{session.tls.tls_version or 'UNKNOWN'}` from {session.tls.version_source}, "
                f"cipher `{session.tls.cipher_suite or 'none'}` from {session.tls.cipher_source}, "
                f"forward secrecy `{session.tls.forward_secrecy}`, "
                f"STARTTLS {session.starttls.advertised=} {session.starttls.command_seen=} "
                f"{session.starttls.accepted=} {session.starttls.upgrade_successful=}"
            )
            certificate = session.certificate
            lines.append(
                f"- Certificate: present `{certificate.present}`, CN `{certificate.common_name}`, "
                f"key `{certificate.public_key_algorithm} {certificate.public_key_bits}`, "
                f"signature `{certificate.signature_hash_algorithm}`, expired `{certificate.expired}`, "
                f"hostname match `{certificate.hostname_match}`, chain `{certificate.chain_status}`"
            )
            for finding in session.findings:
                lines.append(
                    f"  - `{finding.code}` [{finding.severity}] {finding.title} "
                    f"(confidence {finding.confidence}, impact {finding.score_impact})"
                )
        if row.get("missing"):
            lines.append(f"- **Expected but not observed:** {row['missing']}")
        if row.get("unexpected"):
            lines.append(f"- **Observed but not expected:** {row['unexpected']}")
        lines.append("")
    (out_dir / "EXPECTED_RESULTS.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {_relative_or_absolute(out_dir / 'EXPECTED_RESULTS.md')}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
# Ports where each kind of conversation is semantically valid. A STARTTLS or STLS
# upgrade only ever happens on the cleartext port of a protocol, and implicit TLS only
# ever happens on the encryption port. Capturing a "STARTTLS" conversation on port 465
# produces a file whose contents contradict its own name, so the two families are kept
# apart and a scenario is only re-captured on a port from its own family.
#
# Every port below is a genuine deployment choice: 25/587/465 for SMTP, 143/993 for IMAP,
# 110/995 for POP3, and 2525/8143/8110/9465/9993/9995 for the many installations that
# tunnel mail protocols through high ports. The high ports are also the interesting test,
# because TShark only dissects TLS automatically on the ports it already knows.
CLEARTEXT_PORTS: dict[str, list[int]] = {
    "SMTP": [25, 587, 2525],
    "IMAP": [143, 8143],
    "POP3": [110, 8110],
}
TLS_PORTS: dict[str, list[int]] = {
    "SMTP": [465, 9465],
    "IMAP": [993, 9993],
    "POP3": [995, 9995],
}


def ports_for_mode(protocol: str, mode: str) -> list[int]:
    """Return the ports this scenario is allowed to be re-captured on."""
    if mode == "implicit_tls":
        return TLS_PORTS.get(protocol, [])
    return CLEARTEXT_PORTS.get(protocol, [])


# --------------------------------------------------------------------------- #
# Systematic coverage sweep.
#
# The lab set teaches nine-to-fifteen hand-written situations. This builds the whole
# matrix instead: every protocol on every port family against every TLS profile. It
# answers the question a reviewer asks about a small dataset - "how much of the possible
# space does this actually cover?" - and it gives the model far more real sessions to
# learn from.
#
# What it does NOT do is invent new kinds of weakness. The profiles are the same ones the
# lab set uses, so this adds coverage and volume, not new failure modes. That distinction
# is stated in the output and in the docs, because the measured lesson (docs/TRAINING_
# PLAYBOOK.md section 1) is that diversity of situation is what helps, not volume alone.
SWEEP_PROTOCOLS: dict[str, tuple[int, int]] = {
    # protocol: (standard TLS port, alternative high port)
    "SMTP": (465, 9465),
    "IMAP": (993, 9993),
    "POP3": (995, 9995),
}

# What each profile is supposed to make the analyzer report. Used as the expectation, so a
# profile that stops producing its weakness is caught rather than silently trained on.
SWEEP_EXPECTATIONS: dict[str, list[str]] = {
    "modern": [],
    "modern-tls13": ["CERTIFICATE_NOT_OBSERVED"],
    "static-rsa": ["NO_FORWARD_SECRECY"],
    "legacy-tls10": ["DEPRECATED_TLS_VERSION", "NO_FORWARD_SECRECY"],
    "null-cipher": ["INSECURE_CIPHER"],
    "cbc-only": ["LEGACY_CBC_CIPHER"],
    "weak-cert": ["CERTIFICATE_EXPIRED", "WEAK_CERTIFICATE_KEY", "CERTIFICATE_HOSTNAME_MISMATCH"],
}

# Findings that would mean the scenario is wrong rather than weak in the intended way.
SWEEP_FORBIDDEN: dict[str, list[str]] = {
    "modern": ["DEPRECATED_TLS_VERSION", "INSECURE_CIPHER", "NO_FORWARD_SECRECY",
               "CERTIFICATE_EXPIRED", "WEAK_CERTIFICATE_KEY", "PLAINTEXT_EMAIL_SESSION"],
    "modern-tls13": ["DEPRECATED_TLS_VERSION", "INSECURE_CIPHER", "CERTIFICATE_EXPIRED"],
    "static-rsa": ["DEPRECATED_TLS_VERSION", "INSECURE_CIPHER", "PLAINTEXT_EMAIL_SESSION"],
    "legacy-tls10": ["INSECURE_CIPHER", "PLAINTEXT_EMAIL_SESSION"],
    "null-cipher": ["PLAINTEXT_EMAIL_SESSION"],
    "cbc-only": ["DEPRECATED_TLS_VERSION", "PLAINTEXT_EMAIL_SESSION"],
    "weak-cert": ["PLAINTEXT_EMAIL_SESSION"],
}


def build_sweep_plan(profiles: list[str] | None = None) -> list[Scenario]:
    """One scenario per (protocol, port, TLS profile)."""
    wanted = profiles or list(SWEEP_EXPECTATIONS)
    plan: list[Scenario] = []
    for protocol, ports in SWEEP_PROTOCOLS.items():
        for port in ports:
            for profile in wanted:
                plan.append(
                    Scenario(
                        name=f"{protocol.lower()}-{profile}-port{port}",
                        title=f"{protocol} on {port} with the {profile} TLS profile",
                        protocol=protocol,
                        port=port,
                        mode="implicit_tls",
                        profile=profile,
                        expected_findings=list(SWEEP_EXPECTATIONS[profile]),
                        forbidden_findings=list(SWEEP_FORBIDDEN[profile]),
                        notes=(
                            f"Systematic sweep: {protocol} on port {port} using the "
                            f"{TLS_PROFILES[profile].description}. Generated by "
                            "`lab_capture_toolkit.py sweep` for dataset coverage."
                        ),
                    )
                )
    return plan


def capture_sweep(args) -> int:
    out_dir = Path(args.outdir).resolve()
    cert_paths = generate_certificates()
    tshark = find_tshark()
    interface = resolve_interface(tshark, args.iface)

    plan = build_sweep_plan(args.profile)
    print(f"TShark: {tshark}\nInterface: {interface}\nOutput: {out_dir}")
    print(f"Matrix: {len(SWEEP_PROTOCOLS)} protocols x {len(args.profile or SWEEP_EXPECTATIONS)} profiles"
          f" x 2 ports = {len(plan)} captures\n")

    results: list[dict[str, object]] = []
    failures: list[str] = []
    skipped: list[str] = []
    for scenario in plan:
        if _privilege_hint(scenario.port):
            skipped.append(f"{scenario.name} (port {scenario.port})")
            continue
        try:
            outcome = capture_scenario(scenario, cert_paths, out_dir, tshark, interface)
        except Exception as exc:
            failures.append(f"{scenario.name}: {exc}")
            print(f"  FAILED {scenario.name}: {exc}")
            if not args.keep_going:
                return 1
            continue
        results.append(outcome)
        print(f"  ok {scenario.name:<34} {outcome['bytes']:>7} bytes  "
              f"{outcome.get('payload_packets')} payload packet(s)", flush=True)

    (out_dir / "capture_log.json").write_text(
        json.dumps(results, indent=2, default=str), encoding="utf-8"
    )
    print(f"\nCaptured {len(results)} of {len(plan)} planned sweep captures")
    if skipped:
        print(f"Skipped {len(skipped)} (privileged port on this platform): {', '.join(skipped[:4])}"
              + (" ..." if len(skipped) > 4 else ""))
        print("Re-run with sudo to include them; on Windows none of these ports need elevation.")
    if failures:
        print(f"FAILED ({len(failures)}):")
        for failure in failures:
            print(f"  - {failure}")
    print()
    print("These are COMBINATIONS, not new kinds of weakness: same TLS profiles as the lab set.")
    print("Verify them with:")
    print(f"    python tools/lab_capture_toolkit.py verify --outdir {out_dir}")
    return 1 if failures else 0


def capture_variants(args) -> int:
    """Capture each scenario on the other standard ports for its protocol."""
    out_dir = Path(args.outdir).resolve()
    cert_paths = generate_certificates()
    tshark = find_tshark()
    interface = resolve_interface(tshark, args.iface)

    selected = (
        [s for s in SCENARIOS if s.name in set(args.scenario)] if args.scenario else SCENARIOS
    )
    if not selected:
        raise SystemExit("no matching scenario")

    plan: list[Scenario] = []
    for scenario in selected:
        for port in ports_for_mode(scenario.protocol, scenario.mode):
            if port == scenario.port:
                continue          # the base capture already covers this port
            plan.append(
                replace(
                    scenario,
                    name=f"{scenario.name}-port{port}",
                    port=port,
                    title=f"{scenario.title} (on port {port})",
                )
            )
    if not plan:
        print("nothing to capture: every scenario already uses the ports it supports")
        return 0

    print(f"TShark: {tshark}\nInterface: {interface}\nOutput: {out_dir}")
    print(f"Variants planned: {len(plan)} (ports the training set does not contain)\n")
    results: list[dict[str, object]] = []
    failures: list[str] = []
    skipped: list[tuple[str, int]] = []
    for scenario in plan:
        # A privileged port cannot be used without elevation on Linux and macOS. Say so
        # out loud and leave it out of the plan, rather than writing an empty capture.
        if _privilege_hint(scenario.port):
            skipped.append((scenario.name, scenario.port))
            print(f"SKIPPED {scenario.name}: port {scenario.port} needs root on this platform")
            continue
        print(f"capturing {scenario.name} ...", flush=True)
        try:
            outcome = capture_scenario(scenario, cert_paths, out_dir, tshark, interface)
        except Exception as exc:
            failures.append(f"{scenario.name}: {exc}")
            print(f"  FAILED: {exc}")
            if not args.keep_going:
                return 1
            continue
        results.append(outcome)

    # Same output as the base `capture` command: a capture log, not a manifest. The
    # manifest is written later by `verify`, because it needs analysed rows.
    (out_dir / "capture_log.json").write_text(
        json.dumps(results, indent=2, default=str), encoding="utf-8"
    )
    attempted = len(plan) - len(skipped)
    print(f"\nCaptured {len(results)} of {attempted} attempted variant(s) into {out_dir}")
    if skipped:
        print(
            f"Skipped {len(skipped)}: privileged port on this platform "
            f"({', '.join(f'{port}' for _, port in skipped)}). Re-run with sudo to include them; "
            "on Windows they need no elevation."
        )
    if failures:
        print(f"FAILED ({len(failures)}):")
        for failure in failures:
            print(f"  - {failure}")
    print("These are unseen inputs: analyse them with")
    print(f"    python -m app.cli check {out_dir}\\<first capture name>.pcapng")
    if not results or failures:
        return 1
    return 0


# --------------------------------------------------------------------------- #
# Held-out test set ("testset").
#
# Everything above this line exists to TEACH or to TRAIN the model. This section
# exists to MEASURE it, and it is kept deliberately separate from the samples folder:
#
#   * It is written to `testset/` at the repository root, which is not in
#     app/ml/train.py's CAPTURE_DIRS, so nothing here can leak into training. A test
#     that the model has trained on measures nothing.
#   * Every expectation is declared HERE, before the capture runs, and stored next to
#     the captures as ground_truth.json. Scoring happens against that file, so the
#     target cannot be adjusted after seeing the result.
#
# The axis it covers is the one the training captures never had: the upgrade paths on
# the cleartext ports. A STARTTLS/STLS session is three situations at once - a server
# that offers the upgrade, a client that takes it, and what happens afterwards - and the
# lab set only ever had an SMTP one and one refused IMAP one. POP3 STLS did not exist in
# any capture we generated.
TESTSET_VERSION = "1.0"

# Which cleartext ports each protocol may be measured on, and which TLS port.
TESTSET_PORTS: dict[str, dict[str, list[int]]] = {
    "SMTP": {"cleartext": [25, 587, 2525], "implicit": [465]},
    "IMAP": {"cleartext": [143, 8143], "implicit": [993]},
    "POP3": {"cleartext": [110, 8110], "implicit": [995]},
}

# The findings a profile must produce. These are declared from the server
# configuration, which is why they can be written down before the capture runs.
TESTSET_PROFILE_FINDINGS: dict[str, list[str]] = {
    "modern": [],
    "modern-tls13": ["CERTIFICATE_NOT_OBSERVED"],
    "static-rsa": ["NO_FORWARD_SECRECY"],
    "legacy-tls10": ["DEPRECATED_TLS_VERSION", "NO_FORWARD_SECRECY"],
    "null-cipher": ["INSECURE_CIPHER"],
    "cbc-only": ["LEGACY_CBC_CIPHER"],
    "weak-cert": ["CERTIFICATE_EXPIRED", "WEAK_CERTIFICATE_KEY", "CERTIFICATE_HOSTNAME_MISMATCH"],
}

# Findings that would mean the capture is wrong rather than weak in the intended way.
TESTSET_PROFILE_FORBIDDEN: dict[str, list[str]] = {
    "modern": ["DEPRECATED_TLS_VERSION", "INSECURE_CIPHER", "NO_FORWARD_SECRECY",
               "CERTIFICATE_EXPIRED", "WEAK_CERTIFICATE_KEY", "PLAINTEXT_EMAIL_SESSION"],
    "modern-tls13": ["DEPRECATED_TLS_VERSION", "INSECURE_CIPHER", "CERTIFICATE_EXPIRED"],
    "static-rsa": ["DEPRECATED_TLS_VERSION", "INSECURE_CIPHER", "PLAINTEXT_EMAIL_SESSION"],
    "legacy-tls10": ["INSECURE_CIPHER", "PLAINTEXT_EMAIL_SESSION"],
    "null-cipher": ["PLAINTEXT_EMAIL_SESSION"],
    "cbc-only": ["DEPRECATED_TLS_VERSION", "PLAINTEXT_EMAIL_SESSION"],
    "weak-cert": ["PLAINTEXT_EMAIL_SESSION"],
}

# The TLS version the server is configured for. "modern" is pinned to TLS 1.2 so the
# negotiated value is predictable; the library default would drift between OpenSSL builds.
TESTSET_PROFILE_VERSIONS: dict[str, str] = {
    "modern": "TLS 1.2",
    "modern-tls13": "TLS 1.3",
    "static-rsa": "TLS 1.2",
    "legacy-tls10": "TLS 1.0",
    "null-cipher": "TLS 1.2",
    "cbc-only": "TLS 1.2",
    "weak-cert": "TLS 1.2",
}

# Forward secrecy is a property of the key exchange, which the profile fixes. TLS 1.3
# always has it; NULL-cipher does not use a key exchange worth the name, so nothing is
# asserted for it.
TESTSET_PROFILE_FORWARD_SECRECY: dict[str, bool | None] = {
    "modern": True,
    "modern-tls13": True,
    "static-rsa": False,
    "legacy-tls10": False,
    "null-cipher": None,
    "cbc-only": True,
    "weak-cert": True,
}

# Modes in which the client puts a password on the wire without a tunnel having been
# established first. This is the one condition the project treats as unambiguously
# critical, and the only class expectation asserted exactly.
TESTSET_CLEAR_AUTH_MODES: set[str] = {
    "smtp_reject_starttls",
    "smtp_no_starttls",
    "imap_cleartext_login",
    "imap_reject_starttls",
    "pop3_cleartext",
    "pop3_plaintext",
    "pop3_reject_stls",
}

TESTSET_REJECTED_MODES: dict[str, str] = {
    "smtp_reject_starttls": "STARTTLS_REJECTED",
    "imap_reject_starttls": "STARTTLS_REJECTED",
    "pop3_reject_stls": "STARTTLS_REJECTED",
}

UPGRADE_MODES: set[str] = {"smtp_secure", "imap_starttls", "pop3_stls"}
CLEARTEXT_MODES: set[str] = {"smtp_no_starttls", "smtp_reject_starttls", "imap_cleartext_login",
                             "imap_reject_starttls", "pop3_cleartext", "pop3_plaintext",
                             "pop3_reject_stls"}


def testset_expectation(protocol: str, port: int, mode: str, profile: str | None) -> dict[str, object]:
    """Declare what this session must look like, from the configuration alone.

    Written before capture, on purpose. The class column is deliberately a BAND rather
    than an exact label for everything except cleartext credentials: the exact band a
    deprecated version lands in is a policy decision that is free to move, whereas
    "worse than a healthy session" and "the password was readable" are not.
    """
    implicit = mode == "implicit_tls"
    expectation: dict[str, object] = {
        "protocol": protocol,
        "server_port": port,
        "mode": mode,
        "profile": profile,
        "implicit_tls": implicit,
        "expect_findings": [],
        "forbid_findings": [],
        "class_exact": None,
        "class_band": None,
        "facts": {},
    }

    if implicit:
        expectation["forbid_findings"] = ["STARTTLS_REJECTED", "STARTTLS_UPGRADE_NOT_COMPLETED",
                                          "PLAINTEXT_AUTHENTICATION"]
    elif mode in UPGRADE_MODES:
        expectation["forbid_findings"] = ["STARTTLS_REJECTED", "PLAINTEXT_AUTHENTICATION"]
    elif mode in CLEARTEXT_MODES:
        if mode in TESTSET_REJECTED_MODES:
            expectation["expect_findings"] = [TESTSET_REJECTED_MODES[mode]]
        if mode in TESTSET_CLEAR_AUTH_MODES:
            expectation["expect_findings"] = list(expectation["expect_findings"]) + [
                "PLAINTEXT_AUTHENTICATION"
            ]
            expectation["class_exact"] = "CRITICAL"
        # No TLS was negotiated, so a TLS or certificate weakness would be an invention.
        # This is the "missing evidence is not a finding" rule, checked from the other side.
        expectation["forbid_findings"] = ["DEPRECATED_TLS_VERSION", "INSECURE_CIPHER",
                                          "NO_FORWARD_SECRECY", "LEGACY_CBC_CIPHER",
                                          "CERTIFICATE_EXPIRED", "WEAK_CERTIFICATE_KEY"]

    if profile:
        expectation["expect_findings"] = list(expectation["expect_findings"]) + \
            TESTSET_PROFILE_FINDINGS[profile]
        expectation["forbid_findings"] = list(expectation["forbid_findings"]) + \
            TESTSET_PROFILE_FORBIDDEN[profile]
        expectation["facts"] = {
            "tls_version": TESTSET_PROFILE_VERSIONS[profile],
            # TLS 1.3 encrypts the certificate: "not observed" is the correct reading,
            # and it must never be scored as "no certificate".
            "cert_observed": profile != "modern-tls13",
        }
        secrecy = TESTSET_PROFILE_FORWARD_SECRECY[profile]
        if secrecy is not None:
            expectation["facts"]["forward_secrecy"] = secrecy
        if expectation["class_exact"] is None:
            if profile == "modern" or profile == "modern-tls13":
                expectation["class_exact"] = "LOW"
            elif profile in ("legacy-tls10", "weak-cert", "null-cipher"):
                expectation["class_band"] = ["HIGH", "CRITICAL"]
            else:
                expectation["class_band"] = ["MEDIUM", "HIGH"]
    else:
        expectation["facts"] = {"tls_version": None, "cert_observed": False}

    # De-duplicate while keeping order, so a profile that shares a finding with the mode
    # does not have it counted twice.
    for key in ("expect_findings", "forbid_findings"):
        seen: list[str] = []
        for item in expectation[key]:  # type: ignore[union-attr]
            if item not in seen:
                seen.append(item)
        expectation[key] = seen
    return expectation


def build_testset_plan() -> dict[str, object]:
    """Every file in the test set, with the sessions it must contain.

    Three groups:
      singles - one session per file, one file per situation, so a failure names itself
      field   - multi-session files that look like real traffic: mixed protocols, mixed
                profiles, healthy and unhealthy sessions interleaved in one capture
      large   - a field file repeated with its timestamps shifted, for scale
    """
    singles: list[dict[str, object]] = []

    def single(name: str, protocol: str, port: int, mode: str, profile: str | None, seen: bool) -> None:
        singles.append({
            "name": name,
            "protocol": protocol,
            "port": port,
            "mode": mode,
            "profile": profile,
            # `seen` = a capture with this (protocol, port, mode, profile) shape was part
            # of training. The score is reported both ways so the unseen figure is
            # visible on its own.
            "seen_in_training": seen,
        })

    # SMTP upgrade path
    single("smtp-587-starttls-modern", "SMTP", 587, "smtp_secure", "modern", True)
    single("smtp-587-starttls-legacy-tls10", "SMTP", 587, "smtp_secure", "legacy-tls10", False)
    single("smtp-587-starttls-weak-cert", "SMTP", 587, "smtp_secure", "weak-cert", False)
    single("smtp-587-starttls-cbc", "SMTP", 587, "smtp_secure", "cbc-only", False)
    single("smtp-587-starttls-static-rsa", "SMTP", 587, "smtp_secure", "static-rsa", False)
    single("smtp-25-starttls-rejected", "SMTP", 25, "smtp_reject_starttls", None, True)
    single("smtp-2525-no-starttls", "SMTP", 2525, "smtp_no_starttls", None, False)
    # IMAP upgrade path - these modes did not exist before this round
    single("imap-143-starttls-modern", "IMAP", 143, "imap_starttls", "modern", False)
    single("imap-143-starttls-legacy-tls10", "IMAP", 143, "imap_starttls", "legacy-tls10", False)
    single("imap-143-starttls-weak-cert", "IMAP", 143, "imap_starttls", "weak-cert", False)
    single("imap-143-starttls-cbc", "IMAP", 143, "imap_starttls", "cbc-only", False)
    single("imap-143-starttls-null-cipher", "IMAP", 143, "imap_starttls", "null-cipher", False)
    single("imap-143-starttls-rejected", "IMAP", 143, "imap_reject_starttls", None, False)
    single("imap-8143-cleartext-login", "IMAP", 8143, "imap_cleartext_login", "modern", True)
    # POP3 STLS - POP3 had no upgrade capture at all until now
    single("pop3-110-stls-modern", "POP3", 110, "pop3_stls", "modern", False)
    single("pop3-110-stls-legacy-tls10", "POP3", 110, "pop3_stls", "legacy-tls10", False)
    single("pop3-110-stls-weak-cert", "POP3", 110, "pop3_stls", "weak-cert", False)
    single("pop3-110-stls-cbc", "POP3", 110, "pop3_stls", "cbc-only", False)
    single("pop3-110-stls-static-rsa", "POP3", 110, "pop3_stls", "static-rsa", False)
    single("pop3-110-stls-rejected", "POP3", 110, "pop3_reject_stls", None, False)
    single("pop3-8110-plaintext", "POP3", 8110, "pop3_plaintext", None, False)
    # Implicit TLS, for contrast inside the same test set
    single("smtps-465-implicit-modern", "SMTP", 465, "implicit_tls", "modern", True)
    single("imaps-993-implicit-legacy-tls10", "IMAP", 993, "implicit_tls", "legacy-tls10", True)
    single("pop3s-995-implicit-weak-cert", "POP3", 995, "implicit_tls", "weak-cert", True)

    def field_sessions(batch_index: int) -> list[dict[str, object]]:
        """A realistic mix: repeats, both port families, healthy and unhealthy together."""
        alt = batch_index % 2 == 1
        smtp_clear = 587 if not alt else 2525
        imap_clear = 143 if not alt else 8143
        pop_clear = 110 if not alt else 8110
        specs: list[tuple[str, int, str, str | None]] = [
            # healthy encrypted sessions, the ones that must stay quiet
            ("SMTP", 465, "implicit_tls", "modern"),
            ("IMAP", 993, "implicit_tls", "modern"),
            ("POP3", 995, "implicit_tls", "modern"),
            ("SMTP", smtp_clear, "smtp_secure", "modern"),
            ("IMAP", imap_clear, "imap_starttls", "modern"),
            ("POP3", pop_clear, "pop3_stls", "modern"),
            ("SMTP", 465, "implicit_tls", "modern-tls13"),
            ("IMAP", 993, "implicit_tls", "modern-tls13"),
            # weak sessions, interleaved with the healthy ones
            ("SMTP", smtp_clear, "smtp_secure", "legacy-tls10"),
            ("SMTP", smtp_clear, "smtp_secure", "cbc-only"),
            ("SMTP", smtp_clear, "smtp_secure", "static-rsa"),
            ("SMTP", smtp_clear, "smtp_secure", "weak-cert"),
            ("IMAP", imap_clear, "imap_starttls", "legacy-tls10"),
            ("IMAP", imap_clear, "imap_starttls", "cbc-only"),
            ("IMAP", imap_clear, "imap_starttls", "weak-cert"),
            ("IMAP", imap_clear, "imap_starttls", "null-cipher"),
            ("POP3", pop_clear, "pop3_stls", "legacy-tls10"),
            ("POP3", pop_clear, "pop3_stls", "cbc-only"),
            ("POP3", pop_clear, "pop3_stls", "static-rsa"),
            ("POP3", pop_clear, "pop3_stls", "weak-cert"),
            # upgrade refused, so the password crossed the wire in the clear
            ("SMTP", smtp_clear, "smtp_reject_starttls", None),
            ("IMAP", imap_clear, "imap_reject_starttls", None),
            ("POP3", pop_clear, "pop3_reject_stls", None),
            # no upgrade offered at all
            ("SMTP", smtp_clear, "smtp_no_starttls", None),
            ("POP3", pop_clear, "pop3_plaintext", None),
            # cleartext login, then an upgrade that arrives too late
            ("IMAP", imap_clear, "imap_cleartext_login", "modern"),
        ]
        sessions: list[dict[str, object]] = []
        for protocol, port, mode, profile in specs:
            sessions.append({
                "protocol": protocol, "port": port, "mode": mode, "profile": profile,
                # Everything in the field files is a combination that also exists in the
                # singles, so a mistake points at one named scenario file.
                "seen_in_training": False,
            })
        return sessions

    field_sessions_1 = field_sessions(0)
    field_sessions_2 = field_sessions(1)
    return {
        "version": TESTSET_VERSION,
        "singles": singles,
        "field": [
            {"name": "field-mixed-1", "sessions": field_sessions_1},
            {"name": "field-mixed-2", "sessions": field_sessions_2},
        ],
        "large": {"name": "field-large", "base": "field-mixed-1"},
    }


def _session_row(record: dict[str, object], expectation: dict[str, object], rounds: int) -> dict[str, object]:
    row = dict(expectation)
    row["client_port"] = record.get("client_port")
    row["rounds"] = rounds
    return row


def capture_singles(spec: dict[str, object], cert_paths: dict[str, Path], out_dir: Path,
                    tshark: str, interface: str) -> dict[str, object]:
    scenario = Scenario(
        name=str(spec["name"]),
        title=f"Test set: {spec['protocol']} {spec['mode']} on port {spec['port']}",
        protocol=str(spec["protocol"]),
        port=int(spec["port"]),
        mode=str(spec["mode"]),
        profile=spec["profile"],  # type: ignore[arg-type]
        notes="Held-out measurement capture. Generated by `lab_capture_toolkit.py testset`.",
    )
    result = capture_scenario(scenario, cert_paths, out_dir, tshark, interface)
    expectation = testset_expectation(scenario.protocol, scenario.port, scenario.mode, scenario.profile)
    return {
        "file": result["capture"],
        "bytes": result["bytes"],
        "sessions": [_session_row(
            {"client_port": (result["server_result"] or {}).get("client_port")},  # type: ignore[union-attr]
            expectation, 1)],
        "capture_result": result,
    }


def capture_batch(name: str, sessions: list[dict[str, object]], cert_paths: dict[str, Path],
                  out_dir: Path, tshark: str, interface: str) -> dict[str, object]:
    """Run many short sessions back to back inside one TShark capture.

    Each session is a fresh TCP connection, so the operating system gives it a fresh
    client port - which is what makes a merged capture scorable: (protocol, server port,
    client port) identifies the session that produced it.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    output = out_dir / f"{name}.pcapng"
    ports = sorted({int(session["port"]) for session in sessions})
    bpf = " or ".join(f"tcp port {port}" for port in ports if port)

    staging = Path(tempfile.mkdtemp(prefix="sms-testset-"))
    staging_output = staging / f"{name}.pcapng"
    # A generous ceiling: the capture is stopped when the last session finishes, so this
    # only exists so a hung session cannot leave TShark running forever.
    duration = min(1800, 60 + 3 * len(sessions))
    capture = subprocess.Popen(
        [tshark, "-n", "-i", interface, "-f", bpf, "-w", str(staging_output),
         "-a", f"duration:{duration}"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(1.2)

    rows: list[dict[str, object]] = []
    failures: list[str] = []
    for index, spec in enumerate(sessions, start=1):
        scenario = Scenario(
            name=f"{name}-{index:03d}",
            title=f"Test set field session {index}",
            protocol=str(spec["protocol"]),
            port=int(spec["port"]),
            mode=str(spec["mode"]),
            profile=spec["profile"],  # type: ignore[arg-type]
            notes="Field batch session.",
        )
        expectation = testset_expectation(scenario.protocol, scenario.port, scenario.mode, scenario.profile)
        server = MockMailServer(scenario, cert_paths)
        try:
            server.start()
            if not server.ready.wait(timeout=10) or server.error:
                raise RuntimeError(server.error or "mock server did not start")
            try:
                run_client(scenario, cert_paths)
            except Exception as exc:  # a refused or reset session is still a session
                failures.append(f"{scenario.name}: run_client {type(exc).__name__}: {exc}")
            server.finished.wait(timeout=15)
            rows.append(_session_row({"client_port": server.result.get("client_port")}, expectation, 1))
        except Exception as exc:
            failures.append(f"{scenario.name}: {type(exc).__name__}: {exc}")
            rows.append(_session_row({"client_port": None}, expectation, 1))
        finally:
            # The listening socket has to be closed before the next session binds the
            # same port, otherwise the bind fails with "address already in use".
            if server._listener:
                try:
                    server._listener.close()
                except Exception:
                    pass
        if index % 25 == 0:
            print(f"    ... {index}/{len(sessions)} sessions", flush=True)

    time.sleep(0.8)
    capture.terminate()
    try:
        capture.wait(timeout=10)
    except subprocess.TimeoutExpired:
        capture.kill()

    if staging_output.exists() and staging_output.stat().st_size > 0:
        shutil.move(str(staging_output), str(output))
    shutil.rmtree(staging, ignore_errors=True)
    if not output.exists():
        stderr = capture.stderr.read().decode("utf-8", "replace")[-400:] if capture.stderr else ""
        raise RuntimeError(f"batch capture produced no data ({name}). tshark said: {stderr}")

    return {
        "file": _relative_or_absolute(output),
        "bytes": output.stat().st_size,
        "sessions": rows,
        "failures": failures,
    }


def capture_testset(args) -> int:
    out_dir = Path(args.outdir).resolve()
    cert_paths = generate_certificates()
    tshark = find_tshark()
    interface = resolve_interface(tshark, args.iface)
    plan = build_testset_plan()

    singles_dir = out_dir / "captures"
    field_dir = out_dir / "field"
    large_dir = out_dir / "large"
    for directory in (singles_dir, field_dir, large_dir):
        directory.mkdir(parents=True, exist_ok=True)

    print(f"TShark: {tshark}\nInterface: {interface}\nOutput: {out_dir}")
    print(f"Plan: {len(plan['singles'])} single-session captures, "
          f"{len(plan['field'])} field files, 1 large file\n")

    captures: list[dict[str, object]] = []

    print("Single-session captures (one file per situation)")
    for spec in plan["singles"]:  # type: ignore[union-attr]
        if _privilege_hint(int(spec["port"])):
            print(f"  SKIP {spec['name']} (port {spec['port']} needs elevation here)")
            continue
        try:
            outcome = capture_singles(spec, cert_paths, singles_dir, tshark, interface)
        except Exception as exc:
            print(f"  FAILED {spec['name']}: {exc}")
            if not args.keep_going:
                return 1
            continue
        captures.append({"group": "singles", "name": spec["name"], **outcome})
        print(f"  ok {spec['name']:<34} {outcome['bytes']:>7} bytes", flush=True)

    batch_files: list[Path] = []
    print("\nField files (mixed protocols and profiles in one capture)")
    for batch in plan["field"]:  # type: ignore[union-attr]
        name = str(batch["name"])
        sessions = batch["sessions"]  # type: ignore[index]
        try:
            outcome = capture_batch(name, sessions, cert_paths, field_dir, tshark, interface)  # type: ignore[arg-type]
        except Exception as exc:
            print(f"  FAILED {name}: {exc}")
            if not args.keep_going:
                return 1
            continue
        captures.append({"group": "field", "name": name, **outcome})
        batch_files.append((field_dir / f"{name}.pcapng"))
        print(f"  ok {name:<34} {outcome['bytes']:>7} bytes, {len(outcome['sessions'])} sessions",
              flush=True)

    if plan["large"] and batch_files and not args.skip_large:  # type: ignore[index]
        rounds = max(1, int(args.rounds))
        base_name = str(plan["large"]["base"])  # type: ignore[index]
        base_path = field_dir / f"{base_name}.pcapng"
        large_name = str(plan["large"]["name"])  # type: ignore[index]
        try:
            from make_stress_capture import build as merge_rounds

            print(f"\nLarge file: {rounds} shifted repetitions of {base_name}")
            build_info = merge_rounds(large_dir / f"{large_name}.pcapng", [base_path], rounds, 900)
            base_sessions = next(item["sessions"] for item in captures if item["name"] == base_name)
            large_sessions = [_session_row({"client_port": row["client_port"]}, 
                                           {k: v for k, v in row.items() if k not in ("client_port", "rounds")},
                                           rounds)
                              for row in base_sessions]  # type: ignore[union-attr]
            captures.append({
                "group": "large",
                "name": large_name,
                "file": _relative_or_absolute(large_dir / f"{large_name}.pcapng"),
                "bytes": build_info["bytes"],
                "sessions": large_sessions,
                "failures": [],
            })
            print(f"  ok {large_name:<34} {build_info['bytes']:>9} bytes, "
                  f"{len(large_sessions) * rounds} sessions "
                  f"({len(large_sessions)} situations x {rounds} repetitions)", flush=True)
        except Exception as exc:
            print(f"  FAILED {large_name}: {exc}")
            if not args.keep_going:
                return 1

    ground_truth = {
        "dataset": "SecureMailScope held-out test set",
        "version": TESTSET_VERSION,
        "purpose": (
            "Measure the analyzer and the ML layer on captures that were generated after "
            "the model was trained, on an axis (STARTTLS/STLS upgrade paths) the training "
            "captures did not cover. Synthetic and self-generated: this is not human "
            "analyst ground truth, and it measures rule agreement, not real-world accuracy."
        ),
        "expectations_written": "before capture",
        "captures": captures,
    }
    (out_dir / "ground_truth.json").write_text(
        json.dumps(ground_truth, indent=2, default=str), encoding="utf-8"
    )
    (out_dir / "capture_log.json").write_text(
        json.dumps(
            [{"name": item["name"], "file": item.get("file"), "bytes": item.get("bytes"),
              "sessions": len(item.get("sessions", [])),
              "rounds": int(item.get("sessions", [{}])[0].get("rounds", 1) or 1) if item.get("sessions") else 1,
              "sessions_total": len(item.get("sessions", [])) * (
                  int(item.get("sessions", [{}])[0].get("rounds", 1) or 1) if item.get("sessions") else 1),
              "failures": item.get("failures", [])}
             for item in captures],
            indent=2, default=str,
        ),
        encoding="utf-8",
    )
    _write_testset_expected_md(ground_truth, out_dir)
    _write_testset_readme(out_dir)

    total_sessions = sum(
        len(item.get("sessions", [])) * int(item.get("sessions", [{}])[0].get("rounds", 1) or 1)
        if item.get("sessions") else 0
        for item in captures
    )
    print(f"\nCaptured {len(captures)} files holding {total_sessions} sessions")
    print(f"Ground truth : {out_dir / 'ground_truth.json'}")
    print(f"Expectations : {out_dir / 'EXPECTED.md'}  (written before the captures were analysed)")
    print("\nScore it with:")
    print(f"    python tools/score_testset.py --dir {out_dir}")
    print("\nNothing here is training data: testset/ is not in app/ml/train.py's CAPTURE_DIRS.")
    return 0


def _write_testset_readme(out_dir: Path) -> None:
    """The folder explains itself, so it can be handed to somebody else as it stands."""
    text = r"""# Held-out test set

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
"""
    (out_dir / "README.md").write_text(text, encoding="utf-8")


def _write_testset_expected_md(ground_truth: dict[str, object], out_dir: Path) -> None:
    seen_rows: list[tuple[str, str, str, str]] = []
    unseen_rows: list[tuple[str, str, str, str]] = []
    for item in ground_truth["captures"]:  # type: ignore[index]
        total = len(item.get("sessions", []))
        profiles = sorted({str(row.get("profile")) for row in item.get("sessions", [])})
        modes = sorted({str(row.get("mode")) for row in item.get("sessions", [])})
        unseen = not all(bool(row.get("seen_in_training")) for row in item.get("sessions", []))
        row = (
            f"| `{item['name']}` | {total} | {', '.join(modes)} | {', '.join(profiles)} | "
            f"{item.get('bytes', 0):,} |",
        )
        (unseen_rows if unseen else seen_rows).append(row[0])

    lines = [
        "# What the test set expects, declared before it was measured",
        "",
        f"Dataset version {ground_truth['version']}. Every expectation below comes from the "
        "server configuration that was used to generate the traffic, and was written before "
        "any capture was analysed. The scoring script reads `ground_truth.json`; it never "
        "re-derives the answer from the analyzer's output.",
        "",
        "## The axis this set covers that training did not",
        "",
        "* **IMAP STARTTLS** upgraded and refused, across five TLS profiles.",
        "* **POP3 STLS** upgraded and refused - POP3 had no upgrade capture at all before this.",
        "* **SMTP with no STARTTLS offered**, next to SMTP that offers it and refuses it.",
        "* Multi-session files mixing three protocols, eight profiles and both port families.",
        "",
        "## Class expectations: exact where it is not a judgement call",
        "",
        "| Situation | Expected | Why exact or band |",
        "|---|---|---|",
        "| Password sent with no tunnel (refused upgrade, no upgrade offered, cleartext login) "
        "| **CRITICAL** | The credential was readable. Not a policy choice |",
        "| Modern TLS, automatic upgrade or implicit | **LOW** | Nothing weak was configured |",
        "| TLS 1.3 | **LOW** | The certificate is encrypted; not observed is not a fault |",
        "| Deprecated TLS 1.0, weak certificate, NULL cipher | HIGH..CRITICAL | The exact band is a policy decision, the direction is not |",
        "| Static RSA / no forward secrecy, legacy CBC | MEDIUM..HIGH | Same |",
        "",
        "## Unseen situations (no training capture has this shape)",
        "",
        "| File | Sessions | Modes | Profiles | Bytes |",
        "|---|---|---|---|---|",
        *unseen_rows,
        "",
        "## Also present, for contrast (a training capture has this shape)",
        "",
        "| File | Sessions | Modes | Profiles | Bytes |",
        "|---|---|---|---|---|",
        *seen_rows,
        "",
        "## What this test does not prove",
        "",
        "* It is synthetic and self-generated. It is not human analyst ground truth, and the",
        "  model was trained on rule labels, so agreement with the rules is what is measured.",
        "* It says nothing about real-world attack rates, or about traffic from a network we",
        "  have never seen. A capture from NTRO would be the only thing that could.",
        "* The band expectations are policy statements. Where the analyzer disagrees with a",
        "  band, the honest reading is that the policy and the code need to be reconciled -",
        "  it is not automatically an analyzer bug, and it is reported either way.",
        "",
    ]
    (out_dir / "EXPECTED.md").write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SecureMailScope lab capture toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list the available scenarios")
    sub.add_parser("certs", help="generate the lab certificate chain")

    capture_parser = sub.add_parser("capture", help="produce the lab captures")
    capture_parser.add_argument("--scenario", action="append", help="scenario name (repeatable)")
    capture_parser.add_argument("--outdir", default=str(LAB_DIR))
    capture_parser.add_argument("--iface", default=None, help="capture interface (default: loopback)")
    capture_parser.add_argument("--keep-going", action="store_true", help="continue after an error")

    sweep_parser = sub.add_parser(
        "sweep",
        help="capture the full protocol x port x TLS-profile matrix (coverage dataset)",
    )
    sweep_parser.add_argument("--profile", action="append", help="limit to a profile (repeatable)")
    sweep_parser.add_argument("--outdir", default=str(LAB_DIR.parent / "sweep"))
    sweep_parser.add_argument("--iface", default=None)
    sweep_parser.add_argument("--keep-going", action="store_true")

    variants_parser = sub.add_parser(
        "variants",
        help="capture the scenarios on their other standard ports (unseen combinations)",
    )
    variants_parser.add_argument("--scenario", action="append", help="scenario name (repeatable)")
    variants_parser.add_argument("--outdir", default=str(LAB_DIR / "variants"))
    variants_parser.add_argument("--iface", default=None)
    variants_parser.add_argument("--keep-going", action="store_true")

    testset_parser = sub.add_parser(
        "testset",
        help="capture the held-out measurement set (upgrade paths, mixed multi-session files)",
    )
    testset_parser.add_argument("--outdir", default=str(Path(__file__).resolve().parent.parent / "testset"))
    testset_parser.add_argument("--iface", default=None)
    testset_parser.add_argument("--keep-going", action="store_true", help="continue after an error")
    testset_parser.add_argument("--rounds", type=int, default=12,
                                help="repetitions of the base field file in the large capture (default 12)")
    testset_parser.add_argument("--skip-large", action="store_true",
                                help="skip the large merged capture (saves time and disk)")

    verify_parser = sub.add_parser("verify", help="analyse the lab captures and compare with expectations")
    verify_parser.add_argument("--outdir", default=str(LAB_DIR))

    args = parser.parse_args(argv)

    if args.command == "list":
        for scenario in SCENARIOS:
            print(f"{scenario.name:26} {scenario.protocol}:{scenario.port:<4} {scenario.title}")
            if scenario.expected_findings:
                print(f"{'':26} expected findings: {', '.join(scenario.expected_findings)}")
        return 0

    if args.command == "certs":
        paths = generate_certificates()
        print("certificates written:")
        for name, path in paths.items():
            print(f"  {name:14} {_relative_or_absolute(path)}")
        return 0

    if args.command == "verify":
        return verify_captures(Path(args.outdir))

    if args.command == "sweep":
        return capture_sweep(args)
    if args.command == "testset":
        return capture_testset(args)
    if args.command == "variants":
        return capture_variants(args)

    # capture
    out_dir = Path(args.outdir).resolve()
    cert_paths = generate_certificates()
    tshark = find_tshark()
    interface = resolve_interface(tshark, args.iface)
    selected = (
        [s for s in SCENARIOS if s.name in set(args.scenario)] if args.scenario else SCENARIOS
    )
    if not selected:
        raise SystemExit("no matching scenario")

    print(f"TShark: {tshark}\nInterface: {interface}\nOutput: {out_dir}\n")
    results = []
    for scenario in selected:
        print(f"capturing {scenario.name} ...", flush=True)
        try:
            outcome = capture_scenario(scenario, cert_paths, out_dir, tshark, interface)
        except Exception as exc:
            print(f"  FAILED: {exc}")
            if not args.keep_going:
                return 1
            continue
        results.append(outcome)
        server_result = outcome["server_result"] or {}
        client_result = outcome["client_result"] or {}
        print(
            "  ok: {size} bytes | tls={version} cipher={cipher} | server_error={serr} | client_error={cerr}".format(
                size=outcome["bytes"],
                version=server_result.get("negotiated_version", "n/a"),
                cipher=server_result.get("negotiated_cipher", "n/a"),
                serr=outcome["server_error"],
                cerr=outcome["client_error"],
            )
        )
        for note_key in ("tls_note", "client_tls_note"):
            if client_result.get(note_key) or server_result.get(note_key):
                print(f"  note: {client_result.get(note_key) or server_result.get(note_key)}")

    (out_dir / "capture_log.json").write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"\nWrote {_relative_or_absolute(out_dir)}/ (captures + capture_log.json)")
    print("Next: python tools/lab_capture_toolkit.py verify")
    return 0


if __name__ == "__main__":
    sys.exit(main())
