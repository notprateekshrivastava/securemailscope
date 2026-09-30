from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .version import ANALYZER_VERSION


class ProtocolName(str, Enum):
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EvidenceStatus(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class CertificateStatus(str, Enum):
    VALID = "VALID"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT_YET_VALID"
    SELF_SIGNED = "SELF_SIGNED"
    HOSTNAME_MISMATCH = "HOSTNAME_MISMATCH"
    WEAK_KEY = "WEAK_KEY"
    WEAK_SIGNATURE = "WEAK_SIGNATURE"
    INCOMPLETE_CHAIN = "INCOMPLETE_CHAIN"
    UNKNOWN = "UNKNOWN"


class CertificateInfo(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    present: bool = False
    subject: str | None = None
    issuer: str | None = None
    common_name: str | None = None
    subject_alternative_names: list[str] = Field(default_factory=list)
    serial_number: str | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    days_remaining: int | None = None
    expired: bool | None = None
    not_yet_valid: bool | None = None
    self_signed: bool | None = None
    hostname_match: bool | None = None
    public_key_algorithm: str | None = None
    public_key_bits: int | None = None
    elliptic_curve: str | None = None
    signature_algorithm: str | None = None
    signature_hash_algorithm: str | None = None
    weak_signature: bool = False
    chain_status: str = "UNKNOWN"
    chain_length: int = 0
    chain_complete: bool | None = None
    fingerprint_sha256: str | None = None


class TLSInfo(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    detected: bool = False
    handshake_status: EvidenceStatus = EvidenceStatus.UNKNOWN
    client_hello_seen: bool = False
    server_hello_seen: bool = False
    certificate_seen: bool = False
    tls_version: str | None = None
    version_source: str = "UNKNOWN"  # SERVER_HELLO | RECORD_LAYER | UNKNOWN
    offered_versions: list[str] = Field(default_factory=list)
    cipher_suite: str | None = None
    cipher_source: str = "UNKNOWN"  # SERVER_HELLO | CLIENT_OFFER | UNKNOWN
    offered_cipher_suites: list[str] = Field(default_factory=list)
    key_exchange: str | None = None
    forward_secrecy: bool | None = None
    named_group: str | None = None
    signature_algorithm: str | None = None
    sni: str | None = None
    session_resumed: bool | None = None
    alert_seen: bool = False
    handshake_failures: int = 0
    repeated_client_hellos: int = 0
    handshake_duration_ms: float | None = None


class StartTLSInfo(BaseModel):
    advertised: bool = False
    command_seen: bool = False
    accepted: bool | None = None
    rejected: bool | None = None
    upgrade_successful: bool = False
    implicit_tls: bool = False
    plaintext_authentication_seen: bool = False
    evidence: list[str] = Field(default_factory=list)


class SessionFeatures(BaseModel):
    """Stable, JSON-friendly feature vector used by the ML layer."""

    protocol: str = "UNKNOWN"
    server_port: int = 0
    packet_count: int = 0
    byte_count: int = 0
    duration_ms: float = 0.0
    retransmission_rate: float = 0.0
    handshake_failure_count: int = 0
    tls_detected: int = 0
    tls_version_rank: int = 0
    cipher_strength_score: int = 0
    key_exchange_code: int = 0
    forward_secrecy: int = -1
    starttls_advertised: int = 0
    starttls_success: int = 0
    plaintext_authentication: int = 0
    certificate_present: int = 0
    certificate_expired: int = 0
    certificate_self_signed: int = 0
    certificate_key_bits: int = 0
    certificate_signature_strength: int = 0
    hostname_match: int = -1
    chain_complete: int = -1
    sni_present: int = 0
    handshake_complete: int = 0
    repeated_client_hellos: int = 0
    cipher_rarity: float = 0.0
    certificate_changed: int = 0

    def as_vector(self) -> list[float]:
        return [
            float(self.server_port),
            float(self.packet_count),
            float(self.byte_count),
            float(self.duration_ms),
            float(self.retransmission_rate),
            float(self.handshake_failure_count),
            float(self.tls_detected),
            float(self.tls_version_rank),
            float(self.cipher_strength_score),
            float(self.key_exchange_code),
            float(self.forward_secrecy),
            float(self.starttls_advertised),
            float(self.starttls_success),
            float(self.plaintext_authentication),
            float(self.certificate_present),
            float(self.certificate_expired),
            float(self.certificate_self_signed),
            float(self.certificate_key_bits),
            float(self.certificate_signature_strength),
            float(self.hostname_match),
            float(self.chain_complete),
            float(self.sni_present),
            float(self.handshake_complete),
            float(self.repeated_client_hellos),
            float(self.cipher_rarity),
            float(self.certificate_changed),
        ]


class Finding(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    code: str
    severity: Severity
    title: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    recommendation: str
    score_impact: int = 0
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = "HIGH"
    session_id: str | None = None


class MLAssessment(BaseModel):
    risk_class: str = "UNKNOWN"
    confidence: float | None = None
    anomaly_score: float | None = None
    anomalous: bool = False
    model_version: str = "not_loaded"
    explanation: list[str] = Field(default_factory=list)


class SessionAnalysis(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    session_id: str
    tcp_stream_id: str | None = None
    client_ip: str | None = None
    client_port: int | None = None
    server_ip: str | None = None
    server_port: int | None = None
    protocol: ProtocolName = ProtocolName.UNKNOWN
    protocol_confidence: float = 0.0
    first_frame: int | None = None
    last_frame: int | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    duration_ms: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    retransmission_count: int = 0
    stream_status: EvidenceStatus = EvidenceStatus.UNKNOWN
    starttls: StartTLSInfo = Field(default_factory=StartTLSInfo)
    tls: TLSInfo = Field(default_factory=TLSInfo)
    certificate: CertificateInfo = Field(default_factory=CertificateInfo)
    features: SessionFeatures = Field(default_factory=SessionFeatures)
    findings: list[Finding] = Field(default_factory=list)
    policy_risk_score: int = 0
    posture_score: int = 100
    policy_risk_class: str = "LOW"
    ml: MLAssessment = Field(default_factory=MLAssessment)
    evidence_completeness: float = 0.0


class AnalysisSummary(BaseModel):
    protocols: dict[str, int] = Field(default_factory=dict)
    total_sessions: int = 0
    tls_sessions: int = 0
    plaintext_sessions: int = 0
    starttls_sessions: int = 0
    successful_upgrades: int = 0
    anomalous_sessions: int = 0
    total_findings: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    tls_versions: dict[str, int] = Field(default_factory=dict)
    ciphers: dict[str, int] = Field(default_factory=dict)
    overall_risk_score: int = 0
    overall_posture_score: int = 100
    overall_risk_class: str = "LOW"
    evidence_completeness: float = 0.0


class AnalysisResult(BaseModel):
    analysis_id: str
    created_at: datetime
    source_filename: str
    source_sha256: str
    source_size_bytes: int
    uploaded_by: str = "user"
    analyzer_version: str = ANALYZER_VERSION
    input_type: str = "PCAP"
    status: str = "COMPLETED"
    summary: AnalysisSummary
    sessions: list[SessionAnalysis] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    # Encrypted streams that could not be attributed to a mail protocol. Filled only when
    # no email session was found, and it exists so that an empty result is never presented
    # as a clean result: "0 sessions, posture 100" reads like a healthy capture, when the
    # truth may be "encrypted traffic we could not name".
    unclassified_streams: list[dict[str, Any]] = Field(default_factory=list)
    unclassified_note: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    status: str
    tshark_available: bool
    ml_model_available: bool
    ml_model_status: str = "unknown"
    ml_model_note: str | None = None
    version: str
