from __future__ import annotations

from ..schemas import SessionAnalysis, SessionFeatures


FEATURE_NAMES = [
    "server_port",
    "packet_count",
    "byte_count",
    "duration_ms",
    "retransmission_rate",
    "handshake_failure_count",
    "tls_detected",
    "tls_version_rank",
    "cipher_strength_score",
    "key_exchange_code",
    "forward_secrecy",
    "starttls_advertised",
    "starttls_success",
    "plaintext_authentication",
    "certificate_present",
    "certificate_expired",
    "certificate_self_signed",
    "certificate_key_bits",
    "certificate_signature_strength",
    "hostname_match",
    "chain_complete",
    "sni_present",
    "handshake_complete",
    "repeated_client_hellos",
    "cipher_rarity",
    "certificate_changed",
]


def extract_features(session: SessionAnalysis) -> SessionFeatures:
    """Return the stable feature schema used by training and inference.

    The TShark parser already populates this object. Keeping this function as a
    named boundary makes future live/replay sensors use the same ML contract.
    """
    return session.features
