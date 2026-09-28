"""
FounderShield AI - Zero-Trust Executive Voice & Wire Fraud Interception Platform
Pydantic v2 Validation Models for FastAPI Backend
"""

from __future__ import annotations
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator
)


# ============================================================================
# ENUMERATIONS
# ============================================================================

class ThreatSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    BENIGN = "BENIGN"


class IncidentStatus(str, Enum):
    INTERCEPTED = "INTERCEPTED"
    CHALLENGE_PENDING = "CHALLENGE_PENDING"
    VERIFIED_CLEARED = "VERIFIED_CLEARED"
    FROZEN_BLOCKED = "FROZEN_BLOCKED"
    HONEYPOT_ROUTED = "HONEYPOT_ROUTED"


class Channel(str, Enum):
    VOICE_CALL = "VOICE_CALL"
    WHATSAPP_AUDIO = "WHATSAPP_AUDIO"
    TELEGRAM_VOICE = "TELEGRAM_VOICE"
    VENDOR_EMAIL = "VENDOR_EMAIL"
    SMS = "SMS"


class HandshakeStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class AudioFormat(str, Enum):
    WAV = "wav"
    MP3 = "mp3"
    OGG = "ogg"
    FLAC = "flac"
    PCM = "pcm"


class MitigationAction(str, Enum):
    ALLOW_CLEAR = "ALLOW_CLEAR"
    CHALLENGE_HANDSHAKE = "CHALLENGE_HANDSHAKE"
    FREEZE_KILLSWITCH = "FREEZE_KILLSWITCH"
    ROUTE_HONEYPOT = "ROUTE_HONEYPOT"


class SpeakerRole(str, Enum):
    HONEYPOT_AGENT = "honeypot_agent"
    SCAMMER = "scammer"
    SYSTEM = "system"


# ============================================================================
# SUB-MODELS & PAYLOAD STRUCTURES
# ============================================================================

class SpectralArtifactItem(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    type: str = Field(
        ...,
        description="Type of synthetic audio artifact detected (e.g., vocoder_synthesis_artifact, phase_incoherence)"
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Confidence percentage for this specific spectral artifact (0.00 - 100.00)"
    )
    frequency_band_hz: Optional[str] = Field(
        default=None,
        description="Acoustic frequency range where distortion was isolated (e.g., '2000Hz - 4500Hz')"
    )
    description: str = Field(
        ...,
        description="Human-readable forensic finding explaining the artifact anomaly"
    )
    timestamp_offset_ms: Optional[int] = Field(
        default=None,
        ge=0,
        description="Offset in milliseconds into the audio stream where artifact occurred"
    )


class DecoyTranscriptMessage(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    message_id: str = Field(..., description="Unique ID for utterance within decoy conversation")
    speaker_role: SpeakerRole = Field(..., description="Role of speaker in honeypot dialogue")
    text: str = Field(..., min_length=1, description="Transcript of the spoken or received text")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of the utterance"
    )
    sentiment: Optional[str] = Field(
        default=None,
        description="Scammer emotional or psychological posture (e.g. urgent, aggressive, cooperative)"
    )
    latency_ms: Optional[int] = Field(
        default=None,
        ge=0,
        description="Response latency time for synthesized reply"
    )


class ExtractedIntel(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    mule_accounts: List[str] = Field(default_factory=list, description="Extracted bank mule account numbers")
    routing_numbers: List[str] = Field(default_factory=list, description="Extracted routing/sort codes")
    swift_bic_codes: List[str] = Field(default_factory=list, description="Extracted SWIFT/BIC codes")
    crypto_wallets: List[str] = Field(default_factory=list, description="Extracted cryptocurrency wallet addresses")
    origin_ips: List[str] = Field(default_factory=list, description="Discovered source IP addresses")
    geo_locations: List[str] = Field(default_factory=list, description="Associated geographic tags or country codes")
    telephony_carriers: List[str] = Field(default_factory=list, description="Telecom carrier metadata")
    voice_model_signatures: List[str] = Field(default_factory=list, description="Detected AI voice generator models")
    target_entities: List[str] = Field(default_factory=list, description="Organizations mentioned by scammer")
    urgency_tactics: List[str] = Field(default_factory=list, description="Social engineering vectors identified")
    notes: Optional[str] = Field(default=None, description="SOC intelligence analyst notes")


# ============================================================================
# DATABASE ENTITY MODELS
# ============================================================================

# --- Executive Models ---

class ExecutiveBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Full executive legal name")
    title: str = Field(..., min_length=1, max_length=255, description="Corporate title (e.g. CEO, CFO, VP Finance)")
    phone_number: str = Field(..., min_length=5, max_length=32, description="E.164 phone number")
    email: str = Field(..., min_length=3, max_length=255, description="Corporate email address")
    voice_biometric_enrolled: bool = Field(default=False, description="Whether reference voice model is trained")
    voice_fingerprint_hash: Optional[str] = Field(
        default=None,
        min_length=64,
        max_length=64,
        description="SHA-256 hash of enrolled voice biometric embedding vector"
    )
    wire_approval_limit_usd: Decimal = Field(
        default=Decimal("5000.00"),
        ge=Decimal("0.00"),
        description="Maximum single wire transfer authorized without step-up biometric check"
    )

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        parts = v.strip().split("@")
        if len(parts) != 2 or not parts[0] or not parts[1] or "." not in parts[1]:
            raise ValueError("Invalid corporate email format")
        domain_parts = parts[1].split(".")
        if any(not part for part in domain_parts) or len(domain_parts[-1]) < 2:
            raise ValueError("Invalid corporate email format")
        return v.lower().strip()


class ExecutiveCreate(ExecutiveBase):
    pass


class ExecutiveUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    phone_number: Optional[str] = Field(None, min_length=5, max_length=32)
    email: Optional[str] = Field(None, min_length=3, max_length=255)
    voice_biometric_enrolled: Optional[bool] = None
    voice_fingerprint_hash: Optional[str] = Field(None, min_length=64, max_length=64)
    wire_approval_limit_usd: Optional[Decimal] = Field(None, ge=Decimal("0.00"))


class ExecutiveResponse(ExecutiveBase):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: UUID
    created_at: datetime
    updated_at: datetime


# --- Policy Rule Models ---

class PolicyRuleBase(BaseModel):
    policy_name: str = Field(default="Default Global Policy", max_length=128)
    max_unverified_wire_usd: Decimal = Field(
        default=Decimal("1000.00"),
        ge=Decimal("0.00"),
        description="Wires above this limit require cryptographic handshake"
    )
    require_biometric_over_usd: Decimal = Field(
        default=Decimal("25000.00"),
        ge=Decimal("0.00"),
        description="Wires above this limit require step-up voice biometric verification"
    )
    auto_honeypot_on_deepfake_confidence: Decimal = Field(
        default=Decimal("85.00"),
        ge=Decimal("0.00"),
        le=Decimal("100.00"),
        description="Confidence threshold above which caller is automatically diverted to honeypot"
    )
    emergency_bank_killswitch_enabled: bool = Field(
        default=False,
        description="When enabled, halts all outgoing wire transaction pipelines immediately"
    )


class PolicyRuleUpdate(BaseModel):
    policy_name: Optional[str] = Field(None, max_length=128)
    max_unverified_wire_usd: Optional[Decimal] = Field(None, ge=Decimal("0.00"))
    require_biometric_over_usd: Optional[Decimal] = Field(None, ge=Decimal("0.00"))
    auto_honeypot_on_deepfake_confidence: Optional[Decimal] = Field(None, ge=Decimal("0.00"), le=Decimal("100.00"))
    emergency_bank_killswitch_enabled: Optional[bool] = None


class PolicyRuleResponse(PolicyRuleBase):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: UUID
    created_at: datetime
    updated_at: datetime


# --- Handshake Models ---

class VerificationHandshakeBase(BaseModel):
    incident_id: UUID
    executive_id: UUID
    challenge_code: str = Field(
        ...,
        min_length=6,
        max_length=6,
        description="6-digit out-of-band cryptographic challenge code"
    )
    status: HandshakeStatus = Field(default=HandshakeStatus.PENDING)
    expires_at: datetime
    verified_at: Optional[datetime] = None
    biometric_proof_hash: Optional[str] = Field(
        default=None,
        min_length=64,
        max_length=64,
        description="SHA-256 hash of voice biometric verification sample"
    )

    @field_validator("challenge_code")
    @classmethod
    def validate_challenge_code(cls, v: str) -> str:
        if not v.isalnum() or len(v) != 6:
            raise ValueError("Challenge code must be exactly 6 alphanumeric characters")
        return v.upper()


class VerificationHandshakeCreate(VerificationHandshakeBase):
    pass


class VerificationHandshakeResponse(VerificationHandshakeBase):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: UUID
    created_at: datetime


# --- Decoy Session Models ---

class DecoySessionBase(BaseModel):
    incident_id: UUID
    caller_id: str = Field(..., max_length=128, description="Caller identifier/number")
    duration_seconds: int = Field(default=0, ge=0, description="Duration honeypot kept scammer engaged")
    scammer_mule_account: Optional[str] = Field(default=None, max_length=100)
    scammer_routing_number: Optional[str] = Field(default=None, max_length=100)
    transcript: List[DecoyTranscriptMessage] = Field(default_factory=list)
    extracted_intel: ExtractedIntel = Field(default_factory=ExtractedIntel)


class DecoySessionCreate(DecoySessionBase):
    pass


class DecoySessionResponse(DecoySessionBase):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: UUID
    created_at: datetime


# --- Security Incident Models ---

class SecurityIncidentBase(BaseModel):
    executive_id: Optional[UUID] = Field(
        default=None,
        description="ID of corporate executive impersonated, if identified"
    )
    channel: Channel = Field(..., description="Communication channel intercepted")
    caller_source_id: str = Field(..., max_length=128, description="Originating caller phone or handle")
    recipient_employee: str = Field(..., max_length=255, description="Employee targeted by fraud attempt")
    requested_amount_usd: Decimal = Field(..., gt=Decimal("0.00"), description="Fraudulent wire amount requested")
    requested_recipient_bank: str = Field(..., max_length=255, description="Mule bank name provided")
    requested_recipient_iban: str = Field(..., max_length=64, description="Mule IBAN/account identifier")
    deepfake_confidence_score: Decimal = Field(
        ...,
        ge=Decimal("0.00"),
        le=Decimal("100.00"),
        description="AI synthetic voice probability score (0.00 - 100.00%)"
    )
    spectral_artifacts_detected: List[SpectralArtifactItem] = Field(default_factory=list)
    threat_severity: ThreatSeverity = Field(..., description="Calculated threat classification")
    status: IncidentStatus = Field(default=IncidentStatus.INTERCEPTED)


class SecurityIncidentCreate(SecurityIncidentBase):
    pass


class SecurityIncidentUpdate(BaseModel):
    status: Optional[IncidentStatus] = None
    resolved_at: Optional[datetime] = None
    threat_severity: Optional[ThreatSeverity] = None


class SecurityIncidentResponse(SecurityIncidentBase):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: UUID
    created_at: datetime
    resolved_at: Optional[datetime] = None
    executive: Optional[ExecutiveResponse] = None
    handshakes: List[VerificationHandshakeResponse] = Field(default_factory=list)
    decoy_sessions: List[DecoySessionResponse] = Field(default_factory=list)


# ============================================================================
# API INGESTION, ANALYSIS & MITIGATION REQUEST/RESPONSE MODELS
# ============================================================================

class AudioAnalyzeRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    caller_source_id: str = Field(..., max_length=128, description="Inbound telephone number, SIP URI, or chat handle")
    claimed_executive_id: Optional[UUID] = Field(
        default=None,
        description="Executive whom the caller claims to be, if identified"
    )
    recipient_employee: str = Field(
        ...,
        max_length=255,
        description="Employee name or ID handling the interaction (e.g., Treasury Manager)"
    )
    channel: Channel = Field(
        default=Channel.VOICE_CALL,
        description="Interception channel"
    )
    audio_payload_base64: Optional[str] = Field(
        default=None,
        description="Raw audio stream or buffer encoded in base64"
    )
    audio_stream_url: Optional[str] = Field(
        default=None,
        description="Direct streaming URL or S3 audio bucket path"
    )
    audio_format: AudioFormat = Field(
        default=AudioFormat.WAV,
        description="Audio container format"
    )
    sample_rate_hz: Optional[int] = Field(
        default=16000,
        gt=0,
        description="Audio sampling rate (e.g., 16000, 44100, 48000)"
    )
    duration_seconds: Optional[float] = Field(
        default=None,
        gt=0,
        description="Audio duration in seconds"
    )
    requested_amount_usd: Decimal = Field(
        ...,
        gt=Decimal("0.00"),
        description="Wire amount demanded during the communication"
    )
    requested_recipient_bank: str = Field(
        ...,
        max_length=255,
        description="Recipient bank name stated in the wire instruction"
    )
    requested_recipient_iban: str = Field(
        ...,
        max_length=64,
        description="Recipient account / IBAN provided in the wire instruction"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Telemetry metadata (e.g. SIP headers, carrier info, PBX trunk)"
    )

    @model_validator(mode="after")
    def check_audio_payload_or_url(self) -> AudioAnalyzeRequest:
        if not self.audio_payload_base64 and not self.audio_stream_url:
            raise ValueError("Either 'audio_payload_base64' or 'audio_stream_url' must be provided.")
        return self


class AudioAnalyzeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    incident_id: UUID = Field(..., description="Generated UUID for the intercepted incident")
    threat_severity: ThreatSeverity = Field(..., description="Overall calculated severity")
    incident_status: IncidentStatus = Field(..., description="Immediate lifecycle status")
    deepfake_confidence_score: Decimal = Field(
        ...,
        ge=Decimal("0.00"),
        le=Decimal("100.00"),
        description="Deepfake synthesis probability (0.00 - 100.00%)"
    )
    voice_biometric_match_score: Optional[Decimal] = Field(
        default=None,
        ge=Decimal("0.00"),
        le=Decimal("100.00"),
        description="Biometric match score against executive baseline (0.00 - 100.00%)"
    )
    voice_biometric_verified: bool = Field(
        default=False,
        description="True if caller voice acoustics positively matched genuine executive profile"
    )
    spectral_artifacts: List[SpectralArtifactItem] = Field(
        default_factory=list,
        description="Forensic artifact breakdown"
    )
    action_recommended: MitigationAction = Field(
        ...,
        description="Interception mitigation action taken or advised"
    )
    handshake_challenge: Optional[VerificationHandshakeResponse] = Field(
        default=None,
        description="Cryptographic challenge details if step-up handshake was triggered"
    )
    decoy_session_id: Optional[UUID] = Field(
        default=None,
        description="Honeypot session ID if scammer was redirected to autonomous decoy"
    )
    killswitch_triggered: bool = Field(
        default=False,
        description="Whether the emergency company-wide wire killswitch was engaged"
    )
    execution_time_ms: int = Field(
        ...,
        ge=0,
        description="Processing latency in milliseconds"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the analysis completion"
    )


class HandshakeVerifyRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    handshake_id: UUID = Field(..., description="ID of the pending verification handshake")
    challenge_code: str = Field(
        ...,
        min_length=6,
        max_length=6,
        description="6-character OTP challenge entered by the genuine executive"
    )
    executive_id: UUID = Field(..., description="Executive confirming the transaction")
    biometric_voice_sample_base64: Optional[str] = Field(
        default=None,
        description="Optional live voice audio confirmation phrase from the executive"
    )
    biometric_proof_hash: Optional[str] = Field(
        default=None,
        min_length=64,
        max_length=64,
        description="Pre-hashed acoustic proof vector"
    )

    @field_validator("challenge_code")
    @classmethod
    def clean_code(cls, v: str) -> str:
        return v.strip().upper()


class HandshakeVerifyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    handshake_id: UUID
    incident_id: UUID
    status: HandshakeStatus
    is_verified: bool
    message: str
    verified_at: Optional[datetime] = None
    unlocked_approval_limit_usd: Optional[Decimal] = None


class DecoyTranscriptEvent(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    session_id: UUID = Field(..., description="Active honeypot decoy session identifier")
    incident_id: UUID = Field(..., description="Parent security incident identifier")
    message_id: str = Field(..., description="Unique ID for this dialogue turn")
    speaker_role: SpeakerRole = Field(..., description="Speaker: honeypot_agent, scammer, or system")
    utterance: str = Field(..., min_length=1, description="Decoded speech content")
    sentiment: Optional[str] = Field(default=None, description="Tone / sentiment analysis")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    audio_snippet_url: Optional[str] = Field(default=None, description="URL of snippet recording")
    incremental_intel: Optional[ExtractedIntel] = Field(
        default=None,
        description="New intelligence extracted from this specific utterance turn"
    )


class KillSwitchRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    enabled: bool = Field(..., description="True to activate company-wide freeze, False to disarm")
    reason: str = Field(
        ...,
        min_length=5,
        max_length=500,
        description="Justification for emergency bank wire freeze"
    )
    authorized_by_user_id: str = Field(
        ...,
        min_length=1,
        description="Identity of executive, CISO, or authorized SOC lead triggering the killswitch"
    )
    emergency_code: str = Field(
        ...,
        min_length=8,
        description="MFA emergency code authorizing bank killswitch override"
    )


class KillSwitchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    success: bool
    emergency_bank_killswitch_enabled: bool
    triggered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    authorized_by_user_id: str
    affected_pending_incidents_count: int = Field(
        default=0,
        ge=0,
        description="Count of currently pending wire incidents frozen by this action"
    )
    message: str
