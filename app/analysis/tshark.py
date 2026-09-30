from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..config import settings
from ..schemas import (
    CertificateInfo,
    EvidenceStatus,
    ProtocolName,
    SessionAnalysis,
    SessionFeatures,
    StartTLSInfo,
    TLSInfo,
)
from .certificates import candidate_der_values, enrich_chain, parse_certificate
from .ciphers import is_cipher_value, is_scsv_or_grease, resolve_cipher_suite
from .constants import EMAIL_PORT_PROTOCOL, IMPLICIT_TLS_PORTS, TLS_VERSION_RANK


logger = logging.getLogger("securemailscope.tshark")

# Only mail traffic can produce a mail-security session: every mail port (plain,
# STARTTLS and implicit TLS alike) plus any stream Wireshark dissects as SMTP,
# IMAP or POP on a non-standard port. TLS on other ports is deliberately excluded
# so that a general-purpose capture does not flood the report with unrelated
# HTTPS sessions. Filtering at capture-read time is also what makes large
# forensic PCAPs fast to parse.
MAIL_TLS_DISPLAY_FILTER = "tcp.port in {25,110,143,465,587,993,995} || smtp || imap || pop"

TSHARK_TIMEOUT_SECONDS = 900

# A mail session longer than this, or a single step larger than this between two
# consecutive packets, means the capture timestamps are unreliable.
MAX_PLAUSIBLE_SESSION_SECONDS = 6 * 3600.0
MAX_PLAUSIBLE_PACKET_GAP_SECONDS = 300.0


class TSharkUnavailable(RuntimeError):
    pass


class TSharkAnalysisError(RuntimeError):
    pass


def tshark_binary() -> str:
    """Resolve TShark for Linux, macOS and Windows.

    Prefer the explicit environment variable, then PATH, then common Windows
    installation locations. This lets the backend work even when PowerShell
    cannot find a local executable automatically.
    """
    if settings.tshark_path:
        return settings.tshark_path
    found = shutil.which("tshark")
    if found:
        return found
    candidates = [
        Path.cwd() / "tshark.exe",
        Path(r"C:\Program Files\Wireshark\tshark.exe"),
        Path(r"C:\Program Files (x86)\Wireshark\tshark.exe"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return "tshark"


def tshark_available() -> bool:
    try:
        result = subprocess.run([tshark_binary(), "--version"], capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def tshark_version() -> str | None:
    """The TShark version string, for example ``4.4.1``.

    Worth recording: a newer dissector resolves more of a TLS stream, so the same
    capture can legitimately produce fewer "evidence not visible" INFO notes on one
    machine than another. Knowing the version explains that difference instead of
    it looking like a bug.
    """
    try:
        result = subprocess.run(
            [tshark_binary(), "--version"], capture_output=True, text=True, timeout=10
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    first_line = (result.stdout or result.stderr or "").splitlines()[:1]
    if not first_line:
        return None
    # "TShark (Wireshark) 4.4.1 (Git commit ...)" -> "4.4.1"
    # Take the first token that looks like a version number, so the "(Wireshark)"
    # part of the product name is never mistaken for one.
    for token in first_line[0].split():
        candidate = token.strip("(),.")
        if candidate and candidate[0].isdigit() and "." in candidate:
            return candidate
    return first_line[0].strip() or None


def _scalar(value: Any) -> str:
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return ""


def _normalise_key(key: str) -> str:
    """Return a comparable field name.

    TShark JSON mixes dotted field names (``tls.handshake.type``) with the
    "pretty" layer aliases it prints first (``tls_tls_handshake_type``). Both
    describe the same value, so underscores are normalised to dots before any
    lookup. This makes the parser work on Wireshark 3.x and 4.x output.
    """
    return str(key).lower().replace("_", ".")


def _walk_fields(value: Any, prefix: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            yield from _walk_fields(child, child_prefix)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_fields(child, prefix)
    else:
        scalar = _scalar(value)
        if scalar:
            yield _normalise_key(prefix), scalar


def _values(fields: list[tuple[str, str]], *needles: str) -> list[str]:
    normalised = [_normalise_key(needle) for needle in needles]
    return [value for key, value in fields if any(needle in key for needle in normalised)]



def _first(fields: list[tuple[str, str]], *needles: str) -> str | None:
    found = _values(fields, *needles)
    return found[0] if found else None


def _first_int(fields: list[tuple[str, str]], *needles: str) -> int | None:
    value = _first(fields, *needles)
    if value is None:
        return None
    try:
        return int(value, 0)
    except ValueError:
        try:
            return int(float(value))
        except ValueError:
            return None


def _first_float(fields: list[tuple[str, str]], *needles: str) -> float | None:
    value = _first(fields, *needles)
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None


def _normalise_version(value: str | None) -> str | None:
    if not value:
        return None
    text = value.lower().strip()
    if "1.3" in text or text in {"0x0304", "772"}:
        return "TLS 1.3"
    if "1.2" in text or text in {"0x0303", "771"}:
        return "TLS 1.2"
    if "1.1" in text or text in {"0x0302", "770"}:
        return "TLS 1.1"
    if "1.0" in text or text in {"0x0301", "769"}:
        return "TLS 1.0"
    if "ssl" in text or text in {"0x0300", "768"}:
        return "SSLv3"
    return None


# Mail protocols do not announce themselves by port number: the port is a convention,
# not evidence. An organisation that runs IMAPS on 8143, POP3S on 8110 or a submission
# service on 2525 produces captures that a port table cannot classify, and TShark only
# dissects a protocol on the ports it knows. These are the words the protocols actually
# use, which is how a capture on an unfamiliar port can still be identified - from its
# content rather than from a guess about the port.
#
# Only distinctive tokens are listed. "STARTTLS" alone proves nothing, because SMTP and
# IMAP both use it; it only counts alongside the protocol's own vocabulary.
MAIL_VOCABULARY: dict[str, tuple[str, ...]] = {
    "smtp": (
        "ehlo", "helo", "mail from:", "rcpt to:", "esmtp", "starttls",
        "auth plain", "auth login", "250-", "354 ", "220 ", "smtp",
    ),
    "imap": (
        "imap4", "capability", "* ok", "* no", "* bad", "starttls",
        "login ", "authenticate ", " select ", " logout", "a001 ", "a002 ", "a003 ",
    ),
    "pop": (
        "+ok", "-err", "stls", "user ", "pass ", "retr ", "dele ", "capa", "stat",
    ),
}

# Tokens a *server* sends first. Mail protocols all open with a greeting from the
# server, so the direction of the greeting identifies which side is listening.
_SERVER_GREETING = {
    "smtp": ("220 ", "220-"),
    "imap": ("* ok", "* preauth", "* bye"),
    "pop": ("+ok", "-err"),
}

# A hint is only worth acting on when the evidence is not a single coincidence: three
# matching tokens, and a clear winner over the runner-up.
MIN_VOCABULARY_SCORE = 3

# The vocabulary map is keyed by TShark's dissector name; the rest of the code speaks in
# ProtocolName values. Both directions are spelled out rather than derived, so a typo
# fails loudly here instead of silently classifying traffic as UNKNOWN.
_DISSECTOR_TO_PROTOCOL = {"smtp": "SMTP", "imap": "IMAP", "pop": "POP3"}
_PROTOCOL_TO_DISSECTOR = {value: key for key, value in _DISSECTOR_TO_PROTOCOL.items()}


def _vocabulary_scores(text: str) -> dict[str, int]:
    """Count how strongly a chunk of readable payload speaks each mail protocol."""
    lowered = text.lower()
    return {
        protocol: sum(lowered.count(token) for token in tokens)
        for protocol, tokens in MAIL_VOCABULARY.items()
    }


def discover_mail_ports(path: Path, tshark: str | None = None) -> dict[int, str]:
    """Identify mail protocols on ports that TShark does not dissect by default.

    Returns a mapping of server port to a protocol name, for example ``{8143: "IMAP"}``.
    The result is used to add "decode as" hints and to widen the
    display filter, so TShark itself then does the parsing - the vocabulary is only
    used to decide *which* dissector to apply, never to decide what the traffic means.

    An empty mapping means the capture gave no usable evidence, not that it holds no
    mail traffic: implicit TLS hides the vocabulary completely, because everything
    after the handshake is encrypted.
    """
    if not tshark_available():
        return {}
    binary = tshark or tshark_binary()

    # Bounded and selective: only segments that already contain mail vocabulary are
    # returned, so a large capture of unrelated traffic costs one pass and outputs
    # nothing.
    needle = " or ".join(
        f'tcp contains "{token}"'
        for token in ("EHLO", "HELO", "MAIL FROM", "ESMTP", "IMAP4", "CAPABILITY",
                      "+OK", "-ERR", "STLS", "USER ", "STARTTLS", "LOGIN ")
    )
    try:
        result = subprocess.run(
            [
                binary, "-n", "-r", str(path),
                "-Y", f"tcp.len > 0 and ({needle})",
                "-T", "fields", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.payload",
            ],
            capture_output=True,
            text=True,
            timeout=TSHARK_TIMEOUT_SECONDS,
        )
    except Exception:
        return {}
    if result.returncode not in (0, 2):
        return {}

    # port -> {protocol: score}, and the port that sent each protocol's greeting.
    scores: dict[int, dict[str, int]] = {}
    greetings: dict[str, int] = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            source_port = int(parts[0])
        except ValueError:
            continue
        payload = bytes.fromhex(parts[2].replace(":", "")) if parts[2] else b""
        text = payload.decode("latin-1", "replace")
        packet_scores = _vocabulary_scores(text)
        for port in (source_port, int(parts[1]) if parts[1].strip().isdigit() else source_port):
            bucket = scores.setdefault(port, {})
            for protocol, value in packet_scores.items():
                if value:
                    bucket[protocol] = bucket.get(protocol, 0) + value
        # A server greeting at the start of a conversation names the listening port.
        # Every mail protocol opens with the server speaking first, so this is the
        # direction check: without it the client's ephemeral port is scored as well,
        # because both directions carry protocol words.
        stripped = text.lower().lstrip()
        for protocol, opening in _SERVER_GREETING.items():
            if stripped.startswith(opening) and protocol not in greetings:
                greetings[protocol] = source_port

    hints: dict[int, str] = {}
    for port, bucket in scores.items():
        if port in EMAIL_PORT_PROTOCOL:
            continue          # already dissected: never override a known port
        ranked = sorted(bucket.items(), key=lambda item: -item[1])
        if not ranked:
            continue
        protocol, best = ranked[0]
        runner_up = ranked[1][1] if len(ranked) > 1 else 0
        if best < MIN_VOCABULARY_SCORE or best <= runner_up:
            continue
        hints[port] = _DISSECTOR_TO_PROTOCOL[protocol]

    if not hints:
        return {}

    # Prefer the port that greeted the client. Falling back to every scored port would
    # hand TShark the client's ephemeral port as if it spoke the protocol, which is both
    # meaningless here and a false hint in a larger capture where that port is reused.
    # Every protocol whose greeting and vocabulary agree is returned, not just the first
    # one. Returning early meant a capture that held mail for two protocols on two
    # unusual ports only ever had one of them dissected - the other was silently dropped.
    named = {
        port: _DISSECTOR_TO_PROTOCOL[protocol]
        for protocol, port in greetings.items()
        if hints.get(port) == _DISSECTOR_TO_PROTOCOL[protocol]
    }
    if named:
        return named
    for port in greetings.values():
        if port in EMAIL_PORT_PROTOCOL:
            # The greeting came from a port TShark already dissects, so there is nothing
            # to add: guessing would only risk overriding a correct dissection.
            return {}
    logger.info("mail vocabulary found, but no server greeting to name the port: %s", hints)
    return hints


def _normalise_protocol(value: str | None) -> ProtocolName:
    if not value:
        return ProtocolName.UNKNOWN
    value = value.upper()
    if "SMTP" in value:
        return ProtocolName.SMTP
    if "IMAP" in value:
        return ProtocolName.IMAP
    if "POP" in value:
        return ProtocolName.POP3
    return ProtocolName.UNKNOWN


def _port_protocol(
    src_port: int | None,
    dst_port: int | None,
    known_ports: dict[int, str] | None = None,
) -> ProtocolName:
    table = known_ports if known_ports is not None else EMAIL_PORT_PROTOCOL
    for port in (src_port, dst_port):
        if port in table:
            return ProtocolName(table[port])
    return ProtocolName.UNKNOWN


def _server_side(
    src_ip: str | None,
    src_port: int | None,
    dst_ip: str | None,
    dst_port: int | None,
    known_ports: dict[int, str] | None = None,
) -> tuple[str | None, int | None, str | None, int | None]:
    table = known_ports if known_ports is not None else EMAIL_PORT_PROTOCOL
    if dst_port in table:
        return src_ip, src_port, dst_ip, dst_port
    if src_port in table:
        return dst_ip, dst_port, src_ip, src_port
    return src_ip, src_port, dst_ip, dst_port


def _derive_key_exchange(cipher: str | None, tls_version: str | None, fields: list[tuple[str, str]]) -> str | None:
    profile = resolve_cipher_suite(cipher)
    if profile.key_exchange:
        return profile.key_exchange
    if tls_version == "TLS 1.3":
        group = _first(fields, "key.share.group", "key.share", "named.group")
        if group:
            return "TLS 1.3 ephemeral"
    return None


def _forward_secrecy(key_exchange: str | None, tls_version: str | None) -> bool | None:
    if key_exchange in {"ECDHE", "DHE", "TLS 1.3 ephemeral"}:
        return True
    if key_exchange == "RSA":
        return False
    return None


def _cipher_strength(cipher: str | None) -> int:
    return resolve_cipher_suite(cipher).strength


def _key_exchange_code(value: str | None) -> int:
    return {None: 0, "RSA": 1, "DHE": 2, "ECDHE": 3, "TLS 1.3 ephemeral": 4}.get(value, 0)


def _split_multi(value: str) -> list[str]:
    """Split Wireshark's comma-joined multi-value rendering.

    When several occurrences of one field are packed into a single JSON string
    (some builds render ``tls.handshake.type`` as ``"2,11,12,14"``), the value
    has to be split before it can be compared against one known value. Text
    fields are never touched by this helper.
    """
    if "," not in value:
        return [value.strip()]
    return [part.strip() for part in value.split(",") if part.strip()]


def _handshake_types(fields: list[tuple[str, str]]) -> set[str]:
    """Return every TLS handshake message type observed in one packet."""
    types: set[str] = set()
    for value in _values(fields, "handshake.type"):
        types.update(part.lower() for part in _split_multi(value))
    return types


def _cipher_values(fields: list[tuple[str, str]]) -> list[str]:
    """Return cipher-suite values from one packet, ignoring length fields.

    ``tls.handshake.ciphersuites.length`` matches a naive substring search for
    ``handshake.ciphersuite``, so values are accepted only when they look like a
    real suite (``0xc02f`` or ``TLS_...``).
    """
    return [value for value in _values(fields, "handshake.ciphersuite") if is_cipher_value(value)]



def _packet_time(fields: list[tuple[str, str]]) -> datetime | None:
    """Return the packet timestamp, or ``None`` when the capture has none.

    Some captures (and some capture tools) omit absolute timestamps. In that
    case the timestamp stays UNKNOWN instead of being invented.
    """
    value = _first(fields, "frame.time.epoch")
    try:
        return datetime.fromtimestamp(float(value), timezone.utc) if value else None
    except (ValueError, TypeError, OSError):
        return None


def _packet_relative_time(fields: list[tuple[str, str]]) -> float | None:
    """Return the packet's offset from the start of the capture, if present."""
    value = _first(fields, "frame.time.relative")
    try:
        return float(value) if value is not None else None
    except (ValueError, TypeError):
        return None


def _mail_field_text(fields: list[tuple[str, str]]) -> list[str]:
    """Return per-packet SMTP/IMAP/POP values, excluding message content.

    Email bodies (``smtp.data``, ``imap.data``, ...) are deliberately excluded:
    a body line starting with "USER" or containing "AUTH LOGIN" must never be
    mistaken for a credential exchange. The project only inspects protocol
    command/response vocabulary, never message content.
    """
    text: list[str] = []
    for key, value in fields:
        if not any(token in key for token in ("smtp", "imap", "pop")):
            continue
        if any(token in key for token in ("data", "fragment", "reassembled", "body")):
            continue
        text.append(value)
    return text


def _contains(fields: list[tuple[str, str]], pattern: str) -> bool:
    searchable = " ".join(f"{key} {value}" for key, value in fields)
    return re.search(pattern, searchable, re.IGNORECASE) is not None


def _protocol_from_packet(
    fields: list[tuple[str, str]],
    src_port: int | None,
    dst_port: int | None,
    known_ports: dict[int, str] | None = None,
) -> ProtocolName:
    # TShark's own dissection wins, because it is reading the protocol grammar. The port
    # table is only the fallback for streams TShark did not label.
    keys = " ".join(key for key, _ in fields)
    if "smtp" in keys:
        return ProtocolName.SMTP
    if "imap" in keys:
        return ProtocolName.IMAP
    if "pop" in keys and ("pop3" in keys or "pop" in keys):
        return ProtocolName.POP3
    return _port_protocol(src_port, dst_port, known_ports)


def _ip_value(fields: list[tuple[str, str]], *keys: str) -> str | None:
    value = _first(fields, *keys)
    if value and value.startswith("0x"):
        return None
    return value


def _parse_json_packets(payload: str) -> list[dict[str, Any]]:
    try:
        loaded = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise TSharkAnalysisError(f"TShark returned invalid JSON: {exc}") from exc
    if isinstance(loaded, list):
        return loaded
    if isinstance(loaded, dict) and "packets" in loaded:
        return loaded["packets"]
    return []


MAIL_FIELD_TOKENS: tuple[str, ...] = ("smtp", "imap", "pop")

# "STARTTLS" (SMTP/IMAP) or "STLS" (POP3) requested by the client.
_STARTTLS_COMMAND_RE = re.compile(r"(?:^|[^A-Za-z])(STARTTLS|STLS)\b", re.IGNORECASE)

# Lines that advertise capabilities are never an answer to a STARTTLS command.
_CAPABILITY_TOKENS: tuple[str, ...] = (
    "CAPABILITY",
    "PERMANENTFLAGS",
    "AUTH=",
    "LOGIN-REFERRALS",
)


def _lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _handshake_versions(fields: list[tuple[str, str]]) -> list[str]:
    """Return every TLS version mentioned by a handshake packet."""
    values = _values(
        fields,
        "handshake.extensions.supported.version",
        "handshake.supported.version",
        "handshake.version",
    )
    return [version for version in (_normalise_version(value) for value in values) if version]


def _classify_upgrade_response(line: str, tag: str | None) -> str | None:
    """Classify one server line as the answer to a STARTTLS/STLS request.

    This is intentionally strict. A capability banner such as the Dovecot
    greeting ``* OK [CAPABILITY IMAP4rev1 ... STARTTLS ...]`` is *not* an
    acceptance of the command: it only advertises it. Only a direct, tagged
    response is treated as evidence of acceptance or rejection.
    """
    text = line.strip()
    if not text:
        return None
    upper = text.upper()
    if any(token in upper for token in _CAPABILITY_TOKENS):
        return None

    if tag:
        if re.match(rf"^{re.escape(tag)}[ ]+OK\b", text, re.IGNORECASE):
            return "positive"
        if re.match(rf"^{re.escape(tag)}[ ]+(?:NO|BAD|BYE)\b", text, re.IGNORECASE):
            return "negative"
        return None

    if re.match(r"^\+OK\b", text, re.IGNORECASE):
        return "positive"
    if re.match(r"^-ERR\b", text, re.IGNORECASE):
        return "negative"
    smtp_code = re.match(r"^(\d{3})[ -]", text)
    if smtp_code:
        code = int(smtp_code.group(1))
        if 200 <= code < 300:
            return "positive"
        if code >= 400:
            return "negative"
        return None
    if re.match(r"^\S{1,16}[ ]+OK\b", text, re.IGNORECASE):
        return "positive"
    if re.match(r"^\S{1,16}[ ]+(?:NO|BAD|BYE)\b", text, re.IGNORECASE):
        return "negative"
    return None


class _StreamAccumulator:
    """Aggregate every packet of one TCP stream into one email session.

    The class keeps three kinds of state apart on purpose:

    * what the client asked for (commands),
    * what the server answered (responses),
    * what was actually observed on the wire (TLS records, handshakes).

    Only the third kind is used to claim that encryption is in place.
    """

    def __init__(self, stream_id: str, known_ports: dict[int, str] | None = None) -> None:
        self.stream_id = stream_id
        # The standard ports plus any port this capture was found to use for a mail
        # protocol. Passing it in keeps a capture on an unusual port analysable without
        # touching a module-level table.
        self.known_ports: dict[int, str] = {**EMAIL_PORT_PROTOCOL, **(known_ports or {})}
        self.packet_count = 0
        self.packet_index = 0
        self.byte_count = 0
        self.retransmissions = 0
        self.first_frame: int | None = None
        self.last_frame: int | None = None
        self.start_time: datetime | None = None
        self.end_time: datetime | None = None
        self.relative_times: list[float] = []
        self.last_timestamp: datetime | None = None
        self.observed_seconds = 0.0
        self.src_ip: str | None = None
        self.dst_ip: str | None = None
        self.src_port: int | None = None
        self.dst_port: int | None = None
        self.server_port_hint: int | None = None
        self.initial_src_port: int | None = None
        self.protocols: Counter[str] = Counter()
        self.frames: list[int] = []
        # TLS evidence
        self.tls_seen = False
        self.tls_started_index: int | None = None
        self.offered_versions: list[str] = []
        self.server_versions: list[str] = []
        self.record_versions: list[str] = []
        self.offered_ciphers: list[str] = []
        self.negotiated_ciphers: list[str] = []
        self.sni: str | None = None
        self.key_groups: list[str] = []
        self.client_hello_count = 0
        self.server_hello_seen = False
        self.certificate_seen = False
        self.tls_alert = False
        self.handshake_failures = 0
        self.cert_values: list[str] = []
        # STARTTLS / STLS evidence
        self.starttls_advertised = False
        self.starttls_command = False
        self.starttls_command_index: int | None = None
        self.starttls_tag: str | None = None
        self.awaiting_starttls_response = False
        self.starttls_positive_response = False
        self.starttls_negative_response = False
        self.upgrade_successful = False
        # Plaintext authentication evidence
        self.plaintext_auth = False

    # ------------------------------------------------------------------ util
    def protocol_hint(self) -> ProtocolName:
        return _port_protocol(self.src_port, self.dst_port, self.known_ports)

    def _is_from_client(self, src_port: int | None, dst_port: int | None) -> bool:
        if self.server_port_hint is not None:
            if src_port == self.server_port_hint:
                return False
            if dst_port == self.server_port_hint:
                return True
        if self.initial_src_port is not None:
            return src_port == self.initial_src_port
        return True

    def _remember_server_port(self, src_port: int | None, dst_port: int | None) -> None:
        if self.server_port_hint is not None:
            return
        if dst_port in self.known_ports:
            self.server_port_hint = dst_port
        elif src_port in self.known_ports:
            self.server_port_hint = src_port

    # ------------------------------------------------------- command scanner
    def _scan_client_commands(self, text: str) -> None:
        flat = " ".join(text.split())
        starttls = _STARTTLS_COMMAND_RE.search(flat)
        if starttls:
            self.starttls_command = True
            self.starttls_command_index = self.packet_index
            self.awaiting_starttls_response = True
            tag_match = re.match(
                r"^([A-Za-z0-9*+._-]{1,16})[ ]+(?:STARTTLS|STLS)\b", flat, re.IGNORECASE
            )
            if tag_match and self.protocol_hint() == ProtocolName.IMAP:
                self.starttls_tag = tag_match.group(1)
        if self._credentials_were_sent_in_clear(flat):
            self.plaintext_auth = True

    def _credentials_were_sent_in_clear(self, flat: str) -> bool:
        """True when a client authentication command is visible before TLS.

        Authentication lines are only searched for the mail protocols this
        project covers, and only while TLS has not started yet, so a normal
        encrypted session can never be flagged.
        """
        protocol = self.protocol_hint()
        if protocol == ProtocolName.UNKNOWN:
            return False
        if self.tls_started_index is not None and self.packet_index >= self.tls_started_index:
            return False
        if protocol in {ProtocolName.SMTP, ProtocolName.UNKNOWN} and re.search(
            r"\bAUTH(?:ENTICATE)?[ ]+(?:PLAIN|LOGIN|NTLM)\b", flat, re.IGNORECASE
        ):
            return True
        if protocol in {ProtocolName.IMAP, ProtocolName.UNKNOWN} and (
            re.search(r"\bLOGIN[ ]+\S+", flat, re.IGNORECASE)
            or re.search(r"\bAUTHENTICATE[ ]+(?:PLAIN|LOGIN)\b", flat, re.IGNORECASE)
        ):
            return True
        if protocol in {ProtocolName.POP3, ProtocolName.UNKNOWN} and (
            re.search(r"\bUSER[ ]+\S+", flat, re.IGNORECASE)
            or re.search(r"\bPASS[ ]+\S+", flat, re.IGNORECASE)
        ):
            return True
        return False

    # ------------------------------------------------------ response scanner
    def _scan_server_responses(self, text: str) -> None:
        if not self.starttls_advertised and re.search(r"\b(?:STARTTLS|STLS)\b", text, re.IGNORECASE):
            self.starttls_advertised = True
        if not self.awaiting_starttls_response or self.starttls_command_index is None:
            return
        if self.packet_index - self.starttls_command_index > 4:
            # No answer within a few packets: stop guessing, keep it UNKNOWN.
            self.awaiting_starttls_response = False
            return
        for line in _lines(text):
            verdict = _classify_upgrade_response(line, self.starttls_tag)
            if verdict == "positive":
                self.starttls_positive_response = True
                self.awaiting_starttls_response = False
                return
            if verdict == "negative":
                self.starttls_negative_response = True
                self.awaiting_starttls_response = False
                return

    # --------------------------------------------------------------- ingest
    def ingest(self, fields: list[tuple[str, str]]) -> None:
        self.packet_index += 1
        self.packet_count += 1
        frame = _first_int(fields, "frame.number")
        if frame is not None:
            self.frames.append(frame)
            self.first_frame = frame if self.first_frame is None else min(self.first_frame, frame)
            self.last_frame = frame if self.last_frame is None else max(self.last_frame, frame)
        timestamp = _packet_time(fields)
        if timestamp:
            self.start_time = timestamp if self.start_time is None else min(self.start_time, timestamp)
            self.end_time = timestamp if self.end_time is None else max(self.end_time, timestamp)
            # Some captures contain rewound or jumped timestamps. Only plausible
            # forward steps are accumulated, so the reported duration stays
            # meaningful instead of spanning decades.
            if self.last_timestamp is not None:
                delta = (timestamp - self.last_timestamp).total_seconds()
                if 0 <= delta <= MAX_PLAUSIBLE_PACKET_GAP_SECONDS:
                    self.observed_seconds += delta
            self.last_timestamp = timestamp
        relative = _packet_relative_time(fields)
        if relative is not None:
            self.relative_times.append(relative)

        src_port = _first_int(fields, "tcp.srcport", "udp.srcport")
        dst_port = _first_int(fields, "tcp.dstport", "udp.dstport")
        self._remember_server_port(src_port, dst_port)
        if self.src_ip is None:
            self.src_ip = _ip_value(fields, "ip.src", "ipv6.src")
            self.dst_ip = _ip_value(fields, "ip.dst", "ipv6.dst")
            self.src_port = src_port
            self.dst_port = dst_port
            self.initial_src_port = src_port

        packet_bytes = _first_int(fields, "frame.len", "tcp.len") or 0
        self.byte_count += max(packet_bytes, 0)
        if any("retransmission" in key for key, _ in fields):
            self.retransmissions += 1

        protocol = _protocol_from_packet(fields, self.src_port, self.dst_port, self.known_ports)
        if protocol != ProtocolName.UNKNOWN:
            self.protocols[protocol.value] += 1

        keys = " ".join(key for key, _ in fields)
        tls_packet = "tls" in keys or "ssl" in keys
        if tls_packet:
            self.tls_seen = True
            if self.tls_started_index is None:
                self.tls_started_index = self.packet_index
            self.record_versions.extend(_handshake_versions(fields))
            handshake_types = _handshake_types(fields)
            is_client_hello = bool(handshake_types & {"1", "client hello", "client.hello"})
            is_server_hello = bool(handshake_types & {"2", "server hello", "server.hello"})
            if not is_client_hello and _contains(fields, r"client.?hello"):
                is_client_hello = True
            if not is_server_hello and _contains(fields, r"server.?hello"):
                is_server_hello = True
            ciphers = _cipher_values(fields)
            if is_client_hello:
                self.client_hello_count += 1
                self.offered_versions.extend(_handshake_versions(fields))
                self.offered_ciphers.extend(ciphers)
            if is_server_hello:
                self.server_hello_seen = True
                self.server_versions.extend(_handshake_versions(fields))
                self.negotiated_ciphers.extend(ciphers)
            if not is_client_hello and not is_server_hello:
                # Unknown handshake message: keep the evidence but do not
                # pretend it is a negotiated value.
                self.offered_ciphers.extend(ciphers)
            group = _first(fields, "key.share.group", "supported.groups", "named.group")
            if group:
                self.key_groups.append(group)
            for candidate in _values(fields, "extensions.server.name"):
                # The same extension exposes *_list_len, *_name_len and *_type
                # before the name itself, so only hostname-shaped values count.
                if "." in candidate and not candidate.replace(".", "").isdigit():
                    self.sni = candidate
                    break
            certificate_values = [
                value
                for key, value in fields
                if "handshake.certificate" in key
                and not any(token in key for token in ("request", "status", "url", "authorities", "types"))
            ]
            if certificate_values:
                self.certificate_seen = True
                self.cert_values.extend(certificate_values)
            if "alert" in keys:
                self.tls_alert = True
            if _contains(fields, r"handshake.failure|fatal"):
                self.handshake_failures += 1

        mail_text = _mail_field_text(fields)
        if mail_text:
            joined = "\n".join(mail_text)
            if self._is_from_client(src_port, dst_port):
                self._scan_client_commands(joined)
            else:
                self._scan_server_responses(joined)

        if self.upgrade_successful is False and self.starttls_command:
            if (
                self.tls_started_index is not None
                and self.starttls_command_index is not None
                and self.tls_started_index >= self.starttls_command_index
            ):
                self.upgrade_successful = True

    # ------------------------------------------------------------- finalise
    def finalise(self) -> SessionAnalysis:
        client_ip, client_port, server_ip, server_port = _server_side(
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.known_ports
        )

        protocol_name = self.protocols.most_common(1)[0][0] if self.protocols else None
        protocol = (
            _normalise_protocol(protocol_name)
            if protocol_name
            else _port_protocol(self.src_port, self.dst_port, self.known_ports)
        )
        if protocol == ProtocolName.UNKNOWN:
            protocol = _port_protocol(server_port, client_port, self.known_ports)
        protocol_confidence = 0.98 if protocol_name else (0.82 if protocol != ProtocolName.UNKNOWN else 0.0)

        implicit_tls = bool(server_port in IMPLICIT_TLS_PORTS)
        tls_detected = self.tls_seen or implicit_tls

        # ---- negotiated version: ServerHello evidence only -----------------
        negotiated_versions = sorted(
            set(self.server_versions), key=lambda value: TLS_VERSION_RANK.get(value, 0)
        )
        offered_versions = sorted(
            set(self.offered_versions), key=lambda value: TLS_VERSION_RANK.get(value, 0)
        )
        if negotiated_versions:
            tls_version = negotiated_versions[-1]
            version_source = "SERVER_HELLO"
        elif self.server_hello_seen and self.record_versions:
            tls_version = sorted(
                set(self.record_versions), key=lambda value: TLS_VERSION_RANK.get(value, 0)
            )[-1]
            version_source = "RECORD_LAYER"
        else:
            tls_version = None
            version_source = "UNKNOWN"

        # ---- negotiated cipher: ServerHello evidence only ------------------
        negotiated_ciphers = [value for value in self.negotiated_ciphers if not is_scsv_or_grease(value)]
        offered_ciphers = [value for value in self.offered_ciphers if not is_scsv_or_grease(value)]
        cipher_seen = negotiated_ciphers[-1] if negotiated_ciphers else None
        profile = resolve_cipher_suite(cipher_seen)
        cipher_display = profile.display if cipher_seen else None
        cipher_source = "SERVER_HELLO" if cipher_seen else ("CLIENT_OFFER" if offered_ciphers else "UNKNOWN")
        if cipher_source == "CLIENT_OFFER":
            # The client's wish list is not a negotiated result. Report it as an
            # offer and leave the negotiated cipher UNKNOWN.
            key_exchange = None
            fs = None
            cipher_strength = 0
            cipher_display = None
            offered_display = [resolve_cipher_suite(value).display for value in offered_ciphers[:8]]
        else:
            key_exchange = profile.key_exchange or _derive_key_exchange(cipher_seen, tls_version, [])
            fs = profile.forward_secrecy if profile.key_exchange else _forward_secrecy(key_exchange, tls_version)
            cipher_strength = profile.strength
            offered_display = [resolve_cipher_suite(value).display for value in offered_ciphers[:8]]

        handshake_complete = self.client_hello_count > 0 and self.server_hello_seen
        if handshake_complete and self.certificate_seen:
            handshake_status = EvidenceStatus.COMPLETE
        elif tls_detected:
            handshake_status = EvidenceStatus.PARTIAL
        else:
            handshake_status = EvidenceStatus.UNKNOWN

        cert_info = CertificateInfo()
        ders = candidate_der_values(self.cert_values)
        if ders:
            try:
                cert_info = parse_certificate(ders[0], self.sni)
                cert_info = enrich_chain(cert_info, ders)
            except Exception:
                # A truncated certificate is still evidence that a certificate
                # message was present, but it must not be treated as valid.
                cert_info = CertificateInfo(present=True, chain_status="UNKNOWN", chain_complete=None)

        # ---- STARTTLS / STLS outcome ---------------------------------------
        # ``rejected`` describes the final outcome of the negotiation. A server
        # that answers "no" and is then followed by a real TLS handshake did not
        # leave the session in cleartext, so that case is reported as a retry
        # (evidence mentions the refusal) instead of as a rejected upgrade.
        if self.starttls_positive_response:
            accepted: bool | None = True
            rejected: bool | None = False
        elif self.starttls_negative_response:
            accepted = True if self.upgrade_successful else False
            rejected = not self.upgrade_successful
        else:
            accepted = True if self.upgrade_successful else None
            rejected = False

        plaintext_authentication_seen = bool(self.plaintext_auth)
        starttls_evidence: list[str] = []
        if self.starttls_advertised:
            starttls_evidence.append("STARTTLS/STLS advertised by server")
        if self.starttls_command:
            starttls_evidence.append("STARTTLS/STLS command sent by client")
        if self.starttls_positive_response:
            starttls_evidence.append("Server accepted the upgrade request")
        if self.starttls_negative_response and rejected:
            starttls_evidence.append("Server rejected the upgrade request")
        elif self.starttls_negative_response:
            starttls_evidence.append("A refusal response was observed before the successful handshake")
        if self.upgrade_successful:
            starttls_evidence.append("TLS handshake observed after the upgrade request")
        if implicit_tls:
            starttls_evidence.append("Implicit TLS port (SMTPS/IMAPS/POP3S)")
        if plaintext_authentication_seen:
            starttls_evidence.append("Cleartext authentication command observed before TLS")
        starttls = StartTLSInfo(
            advertised=self.starttls_advertised,
            command_seen=self.starttls_command,
            accepted=accepted,
            rejected=rejected,
            upgrade_successful=self.upgrade_successful or (implicit_tls and tls_detected),
            implicit_tls=implicit_tls,
            plaintext_authentication_seen=plaintext_authentication_seen,
            evidence=starttls_evidence,
        )

        # ---- timing ---------------------------------------------------------
        duration_ms = 0.0
        if self.start_time and self.end_time:
            span = max((self.end_time - self.start_time).total_seconds(), 0.0)
            if span <= MAX_PLAUSIBLE_SESSION_SECONDS:
                duration_ms = span * 1000
            else:
                # Timestamps are unusable (jumped clock or merged capture); fall
                # back to the summed monotonic steps instead of reporting a
                # multi-decade session.
                duration_ms = self.observed_seconds * 1000
        elif self.relative_times:
            duration_ms = max((max(self.relative_times) - min(self.relative_times)) * 1000, 0.0)

        evidence_count = sum(
            [
                bool(protocol != ProtocolName.UNKNOWN),
                bool(self.packet_count),
                bool(tls_version),
                bool(cipher_display),
                bool(cert_info.present),
            ]
        )
        evidence_completeness = round(evidence_count / 5, 2)
        stream_status = EvidenceStatus.COMPLETE if self.packet_count and self.frames else EvidenceStatus.UNKNOWN
        if tls_detected and not (handshake_complete and self.certificate_seen):
            stream_status = EvidenceStatus.PARTIAL

        features = SessionFeatures(
            protocol=protocol.value,
            server_port=server_port or 0,
            packet_count=self.packet_count,
            byte_count=self.byte_count,
            duration_ms=duration_ms,
            retransmission_rate=self.retransmissions / max(self.packet_count, 1),
            handshake_failure_count=self.handshake_failures,
            tls_detected=int(tls_detected),
            tls_version_rank=TLS_VERSION_RANK.get(tls_version or "", 0),
            cipher_strength_score=cipher_strength,
            key_exchange_code=_key_exchange_code(key_exchange),
            forward_secrecy=1 if fs is True else (0 if fs is False else -1),
            starttls_advertised=int(self.starttls_advertised),
            starttls_success=int(starttls.upgrade_successful),
            plaintext_authentication=int(plaintext_authentication_seen),
            certificate_present=int(cert_info.present),
            certificate_expired=int(cert_info.expired is True),
            certificate_self_signed=int(cert_info.self_signed is True),
            certificate_key_bits=cert_info.public_key_bits or 0,
            certificate_signature_strength=1 if cert_info.weak_signature else (3 if cert_info.present else 0),
            hostname_match=1 if cert_info.hostname_match is True else (0 if cert_info.hostname_match is False else -1),
            chain_complete=1 if cert_info.chain_complete is True else (0 if cert_info.chain_complete is False else -1),
            sni_present=int(bool(self.sni)),
            handshake_complete=int(handshake_complete),
            repeated_client_hellos=max(0, self.client_hello_count - 1),
        )

        return SessionAnalysis(
            session_id=f"tcp.stream.{self.stream_id}",
            tcp_stream_id=self.stream_id,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            protocol=protocol,
            protocol_confidence=protocol_confidence,
            first_frame=self.first_frame,
            last_frame=self.last_frame,
            start_time=self.start_time,
            end_time=self.end_time,
            duration_ms=duration_ms,
            packet_count=self.packet_count,
            byte_count=self.byte_count,
            retransmission_count=self.retransmissions,
            stream_status=stream_status,
            starttls=starttls,
            tls=TLSInfo(
                detected=tls_detected,
                handshake_status=handshake_status,
                client_hello_seen=self.client_hello_count > 0,
                server_hello_seen=self.server_hello_seen,
                certificate_seen=self.certificate_seen,
                tls_version=tls_version,
                version_source=version_source,
                offered_versions=offered_versions,
                cipher_suite=cipher_display,
                cipher_source=cipher_source,
                offered_cipher_suites=offered_display,
                key_exchange=key_exchange,
                forward_secrecy=fs,
                named_group=self.key_groups[-1] if self.key_groups else None,
                sni=self.sni,
                session_resumed=None,
                alert_seen=self.tls_alert,
                handshake_failures=self.handshake_failures,
                repeated_client_hellos=max(0, self.client_hello_count - 1),
                handshake_duration_ms=duration_ms if handshake_complete else None,
            ),
            certificate=cert_info,
            features=features,
            evidence_completeness=evidence_completeness,
        )


def _run_tshark(path: Path, port_map: dict[int, str] | None = None,
                exclude_ports: set[int] | None = None) -> str:
    """Run TShark once and return its JSON output.

    Two deliberate choices keep this usable on forensic captures:

    * ``-n`` disables name resolution (no reverse-DNS round trips),
    * a display filter keeps only email and TLS traffic, so a 15 MB capture
      that contains mostly routing protocols is parsed in seconds instead of
      minutes.

    The filter never changes the meaning of a session: streams outside email
    and TLS simply cannot produce email findings.
    """
    if not tshark_available():
        raise TSharkUnavailable("tshark is not installed or is not available on PATH")
    binary = tshark_binary()

    # When mail traffic was found on ports TShark does not dissect by default, ask it to
    # treat those ports as the protocol they were found to speak. The dissector is still
    # TShark's own: the vocabulary only decides which dissector to apply.
    filter_expression = MAIL_TLS_DISPLAY_FILTER
    decode_arguments: list[str] = []
    if port_map:
        listed = ",".join(str(port) for port in sorted(port_map))
        filter_expression = f"({MAIL_TLS_DISPLAY_FILTER}) || tcp.port in {{{listed}}}"
        for port, protocol in sorted(port_map.items()):
            dissector = _PROTOCOL_TO_DISSECTOR.get(protocol, protocol.lower())
            decode_arguments += ["-d", f"tcp.port=={port},{dissector}"]
    if exclude_ports:
        # Used by the second pass, which only exists to pick up mail on ports TShark does
        # not dissect by default. Excluding the ports the first pass already analysed
        # keeps that pass cheap on a large capture instead of re-parsing all of it.
        listed = ",".join(str(port) for port in sorted(exclude_ports))
        filter_expression = f"({filter_expression}) && !(tcp.port in {{{listed}}})"

    command = [
        binary,
        "-n",
        "-r",
        str(path),
        *decode_arguments,
        "-Y",
        filter_expression,
        "-T",
        "json",
        # One TCP segment can carry several TLS records (ServerHello,
        # Certificate, ServerKeyExchange, ...). Without this switch those
        # records share the same JSON key and Python's JSON parser keeps only
        # the last one, which silently deletes the certificate and the
        # ServerHello - the two most important pieces of evidence.
        "--no-duplicate-keys",
        "-o",
        "tcp.desegment_tcp_streams:TRUE",
        "-o",
        "tls.desegment_ssl_records:TRUE",
    ]
    logger.info("tshark: %s", " ".join(command))
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=TSHARK_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - depends on capture size
        raise TSharkAnalysisError(
            f"TShark did not finish within {TSHARK_TIMEOUT_SECONDS} seconds. "
            "Split the capture or increase the timeout."
        ) from exc
    if result.returncode != 0:
        # Older Wireshark builds use different preference names, filter syntax or
        # may not know --no-duplicate-keys. Retry with a reduced command so an
        # old installation still produces a (less complete) result.
        logger.warning("tshark failed with the filtered command, retrying: %s", result.stderr[-400:])
        for fallback_command in (
            [binary, "-n", "-r", str(path), "-Y", filter_expression, "-T", "json"],
            [binary, "-n", "-r", str(path), "-T", "json", "--no-duplicate-keys"],
            [binary, "-n", "-r", str(path), "-T", "json"],
        ):
            fallback = subprocess.run(
                fallback_command, capture_output=True, text=True, timeout=TSHARK_TIMEOUT_SECONDS
            )
            if fallback.returncode == 0:
                logger.warning("tshark succeeded with fallback: %s", " ".join(fallback_command))
                return fallback.stdout
        raise TSharkAnalysisError(fallback.stderr[-2000:] or result.stderr[-2000:])
    return result.stdout


def _analyse_pass(path: Path, port_map: dict[int, str],
                  exclude_ports: set[int] | None = None) -> list[SessionAnalysis]:
    """One analysis run, optionally told which ports speak a mail protocol."""
    packets = _parse_json_packets(_run_tshark(path, port_map, exclude_ports))
    streams: dict[str, _StreamAccumulator] = {}
    for packet_index, packet in enumerate(packets, start=1):
        source = packet.get("_source", packet)
        layers = source.get("layers", source) if isinstance(source, dict) else {}
        fields = list(_walk_fields(layers))
        stream_id = _first(fields, "tcp.stream") or f"unknown-{packet_index}"
        accumulator = streams.setdefault(stream_id, _StreamAccumulator(stream_id, port_map))
        accumulator.ingest(fields)
    return [stream.finalise() for stream in streams.values() if stream.packet_count]


def analyze_pcap(path: Path) -> list[SessionAnalysis]:
    """Analyse one capture into email sessions, on any port.

    The first pass trusts the port conventions every mail tool already uses. If that
    finds nothing, the capture is not treated as empty: the protocol's own vocabulary is
    looked for, and when it is found the same analysis is repeated with TShark told to
    dissect those ports. A capture taken on 8143 instead of 143 therefore produces the
    same session as one taken on 143, instead of silently producing none.

    The second pass runs whenever the capture contains mail vocabulary on a port TShark
    does not dissect by default, even when the first pass already found sessions. It used
    to run only when the first pass found nothing, which meant a capture mixing standard
    and unusual ports silently lost the unusual ones - and a real capture of an
    organisation's mail traffic mixes both. The two passes are merged by stream, so a
    session cannot be counted twice.
    """
    sessions = _analyse_pass(path, {})
    discovered = discover_mail_ports(path)
    if not discovered:
        # Nothing on a standard port and no protocol vocabulary to go on. That is an
        # honest empty result: implicit TLS hides the vocabulary entirely, and a capture
        # of something that is not mail has nothing for this analyzer to assess.
        if not sessions:
            logger.info("no mail session and no mail vocabulary found in %s", path.name)
        return sessions

    logger.info(
        "%s: port-convention pass found %d session(s); re-analysing with decode hints %s",
        path.name,
        len(sessions),
        discovered,
    )
    extra = _analyse_pass(
        path, discovered, exclude_ports=set(EMAIL_PORT_PROTOCOL)
    )
    # Merged on the stream AND the address pair, so the same stream cannot be counted
    # twice even if the two passes disagree about its number.
    seen = {(session.session_id, session.server_port, session.client_port) for session in sessions}
    merged = list(sessions) + [
        session for session in extra
        if (session.session_id, session.server_port, session.client_port) not in seen
    ]
    merged.sort(key=lambda session: (session.first_frame or 0, session.session_id))
    return merged
