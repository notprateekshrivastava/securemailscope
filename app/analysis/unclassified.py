"""Account for encrypted streams that could not be attributed to a mail protocol.

Why this exists
---------------
SMTP, IMAP and POP3 all begin in cleartext, even when they end up encrypted: a STARTTLS
or STLS conversation shows its own vocabulary before the upgrade, which is how traffic on
an unusual port can be identified from its content. Implicit TLS is different. On a port
TShark recognises (465, 993, 995) the protocol is known from the port and everything is
fine. On a port it does not recognise, the client sends a TLS ClientHello as the very
first byte of the conversation, so there is no vocabulary to read and no way to prove
which protocol is inside.

This module does not guess. It reports what was seen - a TLS stream, on this port, with
this version and this SNI - and says plainly that the protocol was not identified. That is
the honest answer, and for a passive analyzer it is the only defensible one: claiming
"this is IMAPS" from a port number alone would be inventing evidence, and silently
dropping the stream would hide evidence.

The practical consequence for a report: a capture of a mail service on a non-standard port
with implicit TLS will show one email session, not zero - and it will say the protocol
inside could not be proven.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .tshark import (
    TSHARK_TIMEOUT_SECONDS,
    _normalise_version,
    tshark_available,
    tshark_binary,
)

logger = logging.getLogger(__name__)

# Handshake message types that identify which side is the server and what is visible.
SERVER_HELLO = "2"
CERTIFICATE = "11"


@dataclass
class UnclassifiedStream:
    """A TLS conversation that the analyzer could not name as a mail session."""

    stream_number: int
    server_port: int | None = None
    client_port: int | None = None
    tls_version: str | None = None
    # Which packet the version came from. A version read out of a ClientHello is an offer;
    # only the ServerHello states what was negotiated, and the project draws that line
    # everywhere else too.
    tls_version_source: str = "UNKNOWN"
    server_name: str | None = None
    certificate_visible: bool = False

    @property
    def stream_id(self) -> str:
        return f"tcp.stream.{self.stream_number}"

    def describe(self) -> str:
        parts = [f"port {self.server_port if self.server_port is not None else 'UNKNOWN'}"]
        if self.tls_version:
            parts.append(f"{self.tls_version} (from {self.tls_version_source})")
        else:
            parts.append("TLS version UNKNOWN")
        if self.server_name:
            parts.append(f"client asked for {self.server_name}")
        parts.append(
            "certificate visible" if self.certificate_visible else "certificate NOT observable"
        )
        return ", ".join(parts)


@dataclass
class UnclassifiedReport:
    """Every TLS stream in a capture that is not part of an identified mail session."""

    streams: list[UnclassifiedStream] = field(default_factory=list)
    checked: bool = False
    note: str | None = None

    @property
    def count(self) -> int:
        return len(self.streams)

    @property
    def ports(self) -> list[int]:
        seen: list[int] = []
        for stream in self.streams:
            if stream.server_port is not None and stream.server_port not in seen:
                seen.append(stream.server_port)
        return seen

    def headline(self) -> str:
        if not self.checked:
            return self.note or "Not checked."
        if not self.streams:
            return "Every encrypted stream in this capture belongs to an identified session."
        listed = ", ".join(str(port) for port in self.ports[:6])
        extra = "" if len(self.ports) <= 6 else f" (+{len(self.ports) - 6} more)"
        return (
            f"{self.count} encrypted stream(s) were not attributed to a mail protocol "
            f"(ports: {listed}{extra}). The protocol inside them cannot be proven from the "
            "capture, because implicit TLS hides all protocol vocabulary."
        )


def count_readable_packets(capture: Path) -> int | None:
    """How many packets TShark can actually read from this file.

    Returns None when the question cannot be answered. Used to tell three empty-looking
    cases apart, which are not the same thing at all:

    * a valid capture of traffic that contains no mail (many packets, no mail session),
    * an empty or truncated file (no packets at all),
    * a file that is not a capture (TShark refuses it outright).

    Only the middle case is a bad upload, and without this check it was reported as a
    clean analysis with a perfect posture score.
    """
    if not tshark_available():
        return None
    try:
        done = subprocess.run(
            [tshark_binary(), "-n", "-r", str(capture), "-T", "fields", "-e", "frame.number", "-c", "1"],
            capture_output=True,
            text=True,
            timeout=TSHARK_TIMEOUT_SECONDS,
        )
    except Exception:
        return None
    if done.returncode != 0:
        return None
    return len([line for line in done.stdout.splitlines() if line.strip()])


def find_unclassified_tls(
    capture: Path, analysed_session_ids: set[str] | None = None
) -> UnclassifiedReport:
    """List TLS streams that did not become an analyzed email session.

    ``analysed_session_ids`` holds the session ids the normal analysis produced
    (``"tcp.stream.3"``), so a stream that was already analyzed is never reported twice.
    """
    if not tshark_available():
        return UnclassifiedReport(checked=False, note="tshark is not available.")

    analysed = analysed_session_ids or set()
    try:
        result = subprocess.run(
            [
                tshark_binary(),
                "-n",
                "-r",
                str(capture),
                "-Y",
                "tls.handshake.type || tls.record.content_type",
                "-T",
                "fields",
                "-e",
                "tcp.stream",
                "-e",
                "tcp.srcport",
                "-e",
                "tcp.dstport",
                "-e",
                "tls.handshake.type",
                "-e",
                "tls.handshake.version",
                "-e",
                "tls.handshake.extensions.supported_version",
                "-e",
                "tls.handshake.extensions_server_name",
            ],
            capture_output=True,
            text=True,
            timeout=TSHARK_TIMEOUT_SECONDS,
        )
    except Exception as exc:  # a diagnostic must never break the analysis it describes
        logger.info("could not check for unclassified TLS streams: %s", exc)
        return UnclassifiedReport(checked=False, note=f"Check failed: {type(exc).__name__}.")

    if result.returncode not in (0, 2):
        return UnclassifiedReport(checked=False, note="TShark could not read the capture.")

    found: dict[int, UnclassifiedStream] = {}
    for line in result.stdout.splitlines():
        parts = (line.split("\t") + [""] * 7)[:7]
        number, src_port, dst_port, handshake, version, supported, sni = parts
        if not number.strip().isdigit():
            continue
        stream_number = int(number)
        stream_id = f"tcp.stream.{stream_number}"
        if stream_id in analysed:
            continue
        stream = found.setdefault(stream_number, UnclassifiedStream(stream_number=stream_number))
        types = {item.strip() for item in handshake.split(",") if item.strip()}
        try:
            source = int(src_port)
            destination = int(dst_port)
        except ValueError:
            source, destination = None, None  # type: ignore[assignment]
        if SERVER_HELLO in types and stream.server_port is None:
            # The ServerHello is sent by the server, so its source port names the server.
            # This is the same direction rule the email analysis uses, applied to TLS.
            stream.server_port, stream.client_port = source, destination
        elif stream.server_port is None and source is not None and destination is not None:
            stream.server_port, stream.client_port = min(source, destination), max(source, destination)
        if CERTIFICATE in types:
            stream.certificate_visible = True
        # The negotiated version is whatever the server's own hello states, preferring the
        # supported_versions extension, which is the only place a TLS 1.3 session says so:
        # in TLS 1.3 the legacy record version still reads 0x0303, which is also TLS 1.2.
        if SERVER_HELLO in types and stream.tls_version_source != "SERVER_HELLO":
            negotiated = _normalise_version(supported.split(",")[0].strip()) if supported.strip() else None
            if negotiated:
                stream.tls_version, stream.tls_version_source = negotiated, "SERVER_HELLO"
            elif version.strip():
                fallback = _normalise_version(version.split(",")[0].strip())
                if fallback:
                    stream.tls_version, stream.tls_version_source = fallback, "SERVER_HELLO_LEGACY"
        if sni.strip() and not stream.server_name:
            stream.server_name = sni.strip().split(",")[0]

    return UnclassifiedReport(
        streams=[found[key] for key in sorted(found)], checked=True
    )
