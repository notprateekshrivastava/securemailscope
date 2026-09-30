"""Cipher-suite knowledge base for evidence-qualified TLS assessment.

Why this file exists
--------------------
TShark's JSON output reports the negotiated cipher suite as a *hex code*
(for example ``0xc030``), not as a readable name. Without a lookup table the
rules cannot tell whether the session used AES-GCM with ephemeral ECDHE
(strong) or static RSA with 3DES (weak), so every cipher would look identical.

The table below maps the cipher codes that matter for SMTP/IMAP/POP3 traffic
to three facts the report needs:

* a human readable suite name,
* the key-exchange family (which decides forward secrecy),
* a 0-100 strength score used by the feature vector.

Unknown codes are kept as UNKNOWN. They are never guessed, because inventing
cipher properties would break the evidence rules of this project.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

# Codes that must never be counted as a real negotiated cipher.
# 0x00ff = TLS_EMPTY_RENEGOTIATION_INFO_SCSV, 0x5600 = TLS_FALLBACK_SCSV.
_CIPHER_SCSV_CODES: Final[set[int]] = {0x00FF, 0x5600}

_CIPHER_CODE_RE = re.compile(r"^(?:0x)?([0-9a-fA-F]{4})(?:\s*\(.*\))?$")


@dataclass(frozen=True)
class CipherProfile:
    """Evidence-qualified description of one cipher suite."""

    raw: str
    code: str | None
    name: str | None
    key_exchange: str | None
    forward_secrecy: bool | None
    strength: int  # 0-100, 0 means "not assessable"

    @property
    def display(self) -> str:
        """Return the value stored in the report (name plus code when known)."""
        if self.name and self.code:
            return f"{self.name} ({self.code})"
        return self.name or self.raw

    @property
    def known(self) -> bool:
        return self.name is not None


# code -> (name, key exchange, strength 0-100)
CIPHER_SUITES: Final[dict[str, tuple[str, str, int]]] = {
    # ---- TLS 1.3 (all provide forward secrecy) ----
    "0x1301": ("TLS_AES_128_GCM_SHA256", "TLS 1.3 ephemeral", 90),
    "0x1302": ("TLS_AES_256_GCM_SHA384", "TLS 1.3 ephemeral", 95),
    "0x1303": ("TLS_CHACHA20_POLY1305_SHA256", "TLS 1.3 ephemeral", 95),
    "0x1304": ("TLS_AES_128_CCM_SHA256", "TLS 1.3 ephemeral", 85),
    "0x1305": ("TLS_AES_128_CCM_8_SHA256", "TLS 1.3 ephemeral", 70),
    # ---- ECDHE + AEAD (preferred TLS 1.2) ----
    "0xc02b": ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", 90),
    "0xc02c": ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", 95),
    "0xc02f": ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", 90),
    "0xc030": ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", 95),
    "0xcca8": ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", 95),
    "0xcca9": ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", 95),
    # ---- ECDHE + CBC (acceptable but not preferred) ----
    "0xc013": ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE", 55),
    "0xc014": ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE", 55),
    "0xc023": ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE", 55),
    "0xc027": ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE", 55),
    "0xc028": ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE", 55),
    # ---- DHE + CBC / AEAD ----
    "0x0033": ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE", 55),
    "0x0039": ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE", 55),
    "0x0067": ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE", 55),
    "0x006b": ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE", 55),
    "0x009e": ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE", 85),
    "0x009f": ("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE", 90),
    # ---- Static RSA (no forward secrecy) ----
    "0x002f": ("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", 45),
    "0x0035": ("TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", 45),
    "0x003c": ("TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA", 45),
    "0x003d": ("TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA", 45),
    "0x009c": ("TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", 60),
    "0x009d": ("TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA", 60),
    # ---- Obsolete / weak ----
    "0x0004": ("TLS_RSA_WITH_RC4_128_MD5", "RSA", 5),
    "0x0005": ("TLS_RSA_WITH_RC4_128_SHA", "RSA", 5),
    "0x000a": ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", 20),
    "0x0016": ("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "DHE", 20),
    "0xc012": ("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE", 20),
    "0x0009": ("TLS_RSA_WITH_DES_CBC_SHA", "RSA", 10),
    "0x0015": ("TLS_DHE_RSA_WITH_DES_CBC_SHA", "DHE", 10),
    # ---- Encryption-free (NULL) suites: TLS is negotiated but nothing is encrypted
    "0x0000": ("TLS_NULL_WITH_NULL_NULL", "NULL", 0),
    "0x0001": ("TLS_RSA_WITH_NULL_MD5", "RSA", 0),
    "0x0002": ("TLS_RSA_WITH_NULL_SHA", "RSA", 0),
    "0x003b": ("TLS_RSA_WITH_NULL_SHA256", "RSA", 0),
    # ---- Export-grade (deliberately breakable) ----
    "0x0003": ("TLS_RSA_EXPORT_WITH_RC4_40_MD5", "RSA", 5),
    "0x0006": ("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "RSA", 5),
    "0x0008": ("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "RSA", 5),
    "0x0014": ("TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "DHE", 5),
    # ---- Anonymous (no server authentication at all) ----
    "0x0017": ("TLS_DH_anon_WITH_DES_CBC_SHA", "ANON", 0),
    "0x0018": ("TLS_DH_anon_WITH_RC4_128_MD5", "ANON", 0),
    "0x001a": ("TLS_DH_anon_WITH_AES_128_CBC_SHA", "ANON", 0),
    "0x001b": ("TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "ANON", 0),
    "0x002c": ("TLS_PSK_WITH_NULL_SHA", "PSK", 0),
    "0x006c": ("TLS_DH_anon_WITH_AES_256_CBC_SHA256", "ANON", 0),
}

# Keyword fallback for builds that report readable names instead of codes.
_NAME_HINTS: Final[tuple[tuple[str, str, int], ...]] = (
    ("NULL", "NULL", 0),
    ("ANON", "ANON", 0),
    ("EXPORT", "RSA", 5),
    ("RC4", "RSA", 5),
    ("RC2", "RSA", 5),
    ("3DES", "RSA", 20),
    ("DES_CBC3", "RSA", 20),
    ("CHACHA20", "ECDHE", 95),
    ("_GCM_", "ECDHE", 90),
    ("_CBC_", "ECDHE", 55),
)


def normalise_cipher_code(value: str) -> str | None:
    """Return a canonical ``0xXXXX`` code for a cipher value, else ``None``."""
    if not value:
        return None
    match = _CIPHER_CODE_RE.match(value.strip())
    if not match:
        return None
    return f"0x{match.group(1).lower()}"


def is_scsv_or_grease(value: str) -> bool:
    """True for signalling-only codes that are not negotiated ciphers.

    * ``0x00ff`` / ``0x5600`` are TLS signalling values (SCSV).
    * GREASE values (``0x?a?a`` with both bytes equal) are random placeholders
      that clients inject to keep middleboxes honest. TShark shows them as
      cipher codes exactly like real suites, so they must be filtered out.
    """
    code = normalise_cipher_code(value)
    if code is None:
        return False
    number = int(code, 16)
    if number in _CIPHER_SCSV_CODES:
        return True
    high, low = number >> 8, number & 0xFF
    return high == low and (high & 0x0F) == 0x0A


def resolve_cipher_suite(value: str | None) -> CipherProfile:
    """Describe a cipher suite value exactly as far as the evidence allows."""
    if not value:
        return CipherProfile(raw="", code=None, name=None, key_exchange=None, forward_secrecy=None, strength=0)

    code = normalise_cipher_code(value)
    if code and code in CIPHER_SUITES:
        name, key_exchange, strength = CIPHER_SUITES[code]
        return CipherProfile(
            raw=value,
            code=code,
            name=name,
            key_exchange=key_exchange,
            forward_secrecy=None if key_exchange in {"NULL", "ANON", "PSK"} else key_exchange != "RSA",
            strength=strength,
        )
    if code:
        # Real cipher we do not model yet: keep the code, refuse to guess.
        return CipherProfile(
            raw=value, code=code, name=None, key_exchange=None, forward_secrecy=None, strength=0
        )

    # A readable suite name was supplied by TShark.
    text = value.upper()
    key_exchange = None
    if "ECDHE" in text or "ECDH_" in text or "X25519" in text:
        key_exchange = "ECDHE"
    elif "DHE" in text or "DH_" in text:
        key_exchange = "DHE"
    elif "RSA" in text:
        key_exchange = "RSA"

    strength = 50
    for token, guessed_kx, score in _NAME_HINTS:
        if token in text:
            strength = score
            if guessed_kx and key_exchange is None:
                key_exchange = guessed_kx
            break
    if "TLS_AES_" in text or "TLS_CHACHA20" in text:
        key_exchange = "TLS 1.3 ephemeral"
        strength = 90
    forward_secrecy = None if key_exchange in {None, "NULL", "ANON", "PSK"} else key_exchange != "RSA"
    if key_exchange == "TLS 1.3 ephemeral":
        forward_secrecy = True
    return CipherProfile(
        raw=value,
        code=None,
        name=value,
        key_exchange=key_exchange,
        forward_secrecy=forward_secrecy,
        strength=strength if key_exchange is not None else 50,
    )


def is_known_cipher(value: str | None) -> bool:
    """True when the suite can be named and scored.

    An unknown code is not treated as weak or strong; it is reported as
    unassessable so the table can be extended instead of guessing.
    """
    return resolve_cipher_suite(value).known


def is_cipher_value(value: str) -> bool:
    """True when a TShark field value looks like a cipher suite or cipher code."""
    if normalise_cipher_code(value) is not None:
        return True
    text = value.upper()
    return "TLS_" in text or "SSL_" in text or "_WITH_" in text
