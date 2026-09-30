from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Iterable

from ..schemas import CertificateInfo

try:  # Optional during lightweight unit tests; required in production image.
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import (
        dsa,
        ec,
        ed25519,
        ed448,
        rsa,
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:  # pragma: no cover
    x509 = None  # type: ignore[assignment]


_HEX_RE = re.compile(r"^[0-9a-fA-F:\s]+$")


def _normalise_hex(value: str) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", value)


def candidate_der_values(values: Iterable[str]) -> list[bytes]:
    """Convert likely TShark certificate field values to DER bytes."""
    candidates: list[bytes] = []
    for value in values:
        if not isinstance(value, str):
            continue
        cleaned = _normalise_hex(value)
        if len(cleaned) < 100 or len(cleaned) % 2 or not _HEX_RE.match(value):
            continue
        try:
            raw = bytes.fromhex(cleaned)
        except ValueError:
            continue
        # X.509 DER certificates begin with a SEQUENCE tag.
        if raw[:1] == b"\x30":
            candidates.append(raw)
    return candidates


def _name_value(name: object, attr: object) -> str | None:
    try:
        values = name.get_attributes_for_oid(attr)  # type: ignore[attr-defined]
        return values[0].value if values else None
    except Exception:
        return None


def _key_details(public_key: object) -> tuple[str | None, int | None, str | None]:
    if x509 is None:
        return None, None, None
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size, None
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC", public_key.key_size, public_key.curve.name
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size, None
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, None
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 448, None
    return type(public_key).__name__, getattr(public_key, "key_size", None), None


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _match_dns_pattern(pattern: str, hostname: str) -> bool:
    """RFC 6125 style comparison of one certificate name against a host name.

    Wildcards are accepted only in the left-most label (``*.example.com``), which
    is what public CAs and mail clients accept, and never match a bare suffix
    such as ``example.com`` itself.
    """
    pattern = pattern.strip().rstrip(".").lower()
    hostname = hostname.strip().rstrip(".").lower()
    if not pattern or not hostname:
        return False
    if pattern == hostname:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        if hostname == suffix:
            return False
        head, _, tail = hostname.partition(".")
        return bool(tail) and tail == suffix and bool(head)
    return False


def _hostname_matches(sans: list[str], common_name: str | None, hostname: str) -> bool:
    """Return whether the certificate is valid for ``hostname``.

    Preference order follows the certificate standard: subjectAltName entries are
    authoritative when present, and the common name is only consulted for
    certificates that carry no SAN at all.
    """
    if "." not in hostname and ":" not in hostname:
        return False
    candidates = [value for value in sans if value]
    if candidates:
        return any(_match_dns_pattern(value, hostname) for value in candidates)
    if common_name:
        return _match_dns_pattern(common_name, hostname)
    return False


def parse_certificate(der: bytes, sni: str | None = None) -> CertificateInfo:
    if x509 is None:
        return CertificateInfo(present=True, chain_status="UNKNOWN")

    cert = x509.load_der_x509_certificate(der)
    now = datetime.now(timezone.utc)
    # Newer cryptography releases expose timezone-aware properties. The eager
    # default argument was removed because building it triggers a deprecation
    # warning even when the aware property is available.
    if hasattr(cert, "not_valid_before_utc"):
        not_before = _utc(cert.not_valid_before_utc)
        not_after = _utc(cert.not_valid_after_utc)
    else:  # pragma: no cover - older cryptography only
        not_before = _utc(cert.not_valid_before)
        not_after = _utc(cert.not_valid_after)

    try:
        san_values = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = san_values.get_values_for_type(x509.DNSName)
    except Exception:
        sans = []

    public_key = cert.public_key()
    algorithm, bits, curve = _key_details(public_key)
    signature_hash = None
    try:
        signature_hash = cert.signature_hash_algorithm.name
    except Exception:
        signature_hash = None
    signature_name = getattr(cert.signature_hash_algorithm, "name", None)
    if algorithm:
        signature_name = f"{signature_hash or 'unknown'}-{algorithm}"

    expired = now > not_after
    not_yet_valid = now < not_before
    self_signed = cert.subject == cert.issuer
    hostname_match: bool | None = None
    if sni:
        # Evaluated only when the client actually named a server (SNI). Without
        # SNI there is nothing to compare against, so the result stays UNKNOWN.
        hostname_match = _hostname_matches(
            sans, _name_value(cert.subject, x509.NameOID.COMMON_NAME), sni
        )

    weak_signature = (signature_hash or "").lower() in {"md5", "sha1"}
    weak_key = (algorithm == "RSA" and (bits or 0) < 2048) or (
        algorithm == "EC" and (bits or 0) < 256
    )

    status = "VALID"
    if expired:
        status = "EXPIRED"
    elif not_yet_valid:
        status = "NOT_YET_VALID"
    elif hostname_match is False:
        status = "HOSTNAME_MISMATCH"
    elif weak_key:
        status = "WEAK_KEY"
    elif weak_signature:
        status = "WEAK_SIGNATURE"
    elif self_signed:
        status = "SELF_SIGNED"

    return CertificateInfo(
        present=True,
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        common_name=_name_value(cert.subject, x509.NameOID.COMMON_NAME),
        subject_alternative_names=list(sans),
        serial_number=format(cert.serial_number, "x"),
        valid_from=not_before,
        valid_until=not_after,
        days_remaining=(not_after - now).days,
        expired=expired,
        not_yet_valid=not_yet_valid,
        self_signed=self_signed,
        hostname_match=hostname_match,
        public_key_algorithm=algorithm,
        public_key_bits=bits,
        elliptic_curve=curve,
        signature_algorithm=signature_name,
        signature_hash_algorithm=signature_hash,
        weak_signature=weak_signature,
        chain_status="UNKNOWN",
        chain_length=1,
        chain_complete=None,
        fingerprint_sha256=hashlib.sha256(der).hexdigest(),
    )


def enrich_chain(leaf: CertificateInfo, ders: list[bytes]) -> CertificateInfo:
    """Perform conservative offline chain-link checks.

    Full trust validation requires a trust store and is deliberately not claimed
    here. Only two facts are derived, both from the capture itself:

    * how many certificates were actually sent, and
    * whether each certificate's issuer name equals the next certificate's
      subject name.

    Unparsable candidate byte strings are skipped instead of discarding the
    whole chain, because TShark can expose the certificate list in more than one
    representation for the same message.
    """
    if not ders:
        return leaf

    parsed = []
    if x509 is not None:
        for value in ders:
            try:
                parsed.append(x509.load_der_x509_certificate(value))
            except Exception:
                continue

    if not parsed:
        leaf.chain_status = "UNKNOWN"
        leaf.chain_complete = None
        return leaf

    leaf.chain_length = len(parsed)
    if len(parsed) == 1:
        if leaf.self_signed:
            # A self-signed certificate is its own root: the chain is not
            # missing, it is untrusted. Trust is reported by the
            # SELF_SIGNED_CERTIFICATE finding, not as an incomplete chain.
            leaf.chain_status = "SELF_SIGNED"
            leaf.chain_complete = True
        else:
            leaf.chain_status = "INCOMPLETE"
            leaf.chain_complete = False
        return leaf

    try:
        linked = all(
            parsed[index].issuer == parsed[index + 1].subject for index in range(len(parsed) - 1)
        )
    except Exception:  # pragma: no cover - defensive
        leaf.chain_status = "UNKNOWN"
        leaf.chain_complete = None
        return leaf

    leaf.chain_complete = linked
    if linked:
        leaf.chain_status = "COMPLETE" if parsed[-1].subject == parsed[-1].issuer else "COMPLETE_UNVERIFIED_ROOT"
    else:
        leaf.chain_status = "INCOMPLETE"
    return leaf
