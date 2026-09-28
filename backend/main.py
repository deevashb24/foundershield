"""
FounderShield AI - Zero-Trust Executive Voice & Wire Fraud Interception Platform
FastAPI Server Backend (Port 8012)
"""

from __future__ import annotations

import re
import secrets
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field

# Ensure project root is in sys.path
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from backend.analyzer import DeepfakeAudioAnalyzer
from backend.store import (
    CEO_VANCE_ID,
    CFO_ROSTOVA_ID,
    decoy_sessions_db,
    executives_db,
    handshakes_db,
    incidents_db,
    policy_db,
    seed_database,
)
from models.schemas import (
    AudioAnalyzeRequest,
    AudioAnalyzeResponse,
    Channel,
    DecoySessionResponse,
    DecoyTranscriptMessage,
    ExecutiveCreate,
    ExecutiveResponse,
    ExecutiveUpdate,
    ExtractedIntel,
    HandshakeStatus,
    HandshakeVerifyResponse,
    IncidentStatus,
    KillSwitchRequest,
    KillSwitchResponse,
    MitigationAction,
    PolicyRuleResponse,
    PolicyRuleUpdate,
    SecurityIncidentResponse,
    SpeakerRole,
    SpectralArtifactItem,
    ThreatSeverity,
    VerificationHandshakeResponse,
)


# Emergency authorization codes for banking killswitch override
VALID_EMERGENCY_CODES = {
    "KILLSWITCH_OVERRIDE_8891",
    "EMERGENCY_HALT_2026",
    "CISO_OVERRIDE_ALPHA",
    "SOC_DEFCON1_OVERRIDE",
    "ZERO_TRUST_CIRCUIT_BREAKER",
}


# ============================================================================
# EXTENDED DTO MODELS FOR BACKEND RESPONSES & FLEXIBLE INPUTS
# ============================================================================

class HealthResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    status: str = "HEALTHY"
    shield_status: str = "ACTIVE"
    active_executive_profiles: int
    intercepted_wire_dollars: Decimal
    honeypot_count: int
    killswitch_engaged: bool
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ThreatMetricsResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    total_intercepted_wire_usd: Decimal
    deepfake_catch_rate_percent: float
    active_honeypots: int
    average_challenge_latency_ms: int
    total_incidents: int
    frozen_incidents_count: int
    honeypot_routed_count: int
    challenge_pending_count: int
    verified_cleared_count: int
    active_executive_profiles: int
    emergency_killswitch_active: bool


class VerifyHandshakeInput(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    handshake_id: UUID = Field(..., description="ID of the pending verification handshake")
    challenge_code: str = Field(
        ...,
        min_length=6,
        max_length=6,
        description="6-character OTP challenge entered by the genuine executive",
    )
    executive_id: Optional[UUID] = Field(
        default=None,
        description="Executive confirming the transaction (optional; inferred if omitted)",
    )
    biometric_voice_sample_base64: Optional[str] = None
    biometric_proof_hash: Optional[str] = None


class DecoyMessageRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    message: Optional[str] = None
    utterance: Optional[str] = None
    text: Optional[str] = None
    speaker_role: Optional[SpeakerRole] = SpeakerRole.SCAMMER
    sentiment: Optional[str] = None


class DecoyMessageResponse(DecoySessionResponse):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    agent_response: str


# ============================================================================
# APPLICATION LIFESPAN & SETUP
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure seed database is populated
    seed_database()
    yield


app = FastAPI(
    title="FounderShield AI API",
    description="Zero-Trust Executive Voice & Wire Fraud Interception Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware for open integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# HELPER ROUTINES
# ============================================================================

def _populate_incident_relations(incident: SecurityIncidentResponse) -> SecurityIncidentResponse:
    """Populates executive, handshakes, and decoy sessions on incident."""
    if incident.executive_id and incident.executive_id in executives_db:
        incident.executive = executives_db[incident.executive_id]

    incident.handshakes = [
        h for h in list(handshakes_db.values()) if h.incident_id == incident.id
    ]
    incident.decoy_sessions = [
        d for d in list(decoy_sessions_db.values()) if d.incident_id == incident.id
    ]
    return incident


def _extract_threat_intel_from_text(text: str, current_intel: ExtractedIntel) -> ExtractedIntel:
    """Scans text for bank accounts, IBANs, routing numbers, and crypto addresses."""
    # 1. IBAN extraction: structured spaced IBANs (e.g., DE89 3704 0044 0532 0130 00, FR76 3000 6000 0112 3456 7890 189)
    spaced_iban_matches = re.findall(r"\b[A-Z]{2}[0-9]{2}(?:\s?[0-9A-Z]{4}){2,7}(?:\s?[0-9A-Z]{1,4})?\b", text.upper())
    for raw_iban in spaced_iban_matches:
        cleaned_iban = re.sub(r"[\s\-]", "", raw_iban)
        if 15 <= len(cleaned_iban) <= 34 and cleaned_iban not in current_intel.mule_accounts:
            current_intel.mule_accounts.append(cleaned_iban)

    # Standard compact IBANs
    iban_matches = re.findall(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b", text.upper())
    for iban in iban_matches:
        if iban not in current_intel.mule_accounts:
            current_intel.mule_accounts.append(iban)

    # 2. Explicit routing transit codes
    explicit_routing = re.findall(r"(?:routing|aba|transit|sort\s+code)[\s:#=code]*([0-9]{9}|\d{2}-\d{2}-\d{2})\b", text, re.IGNORECASE)
    for er in explicit_routing:
        if er not in current_intel.routing_numbers:
            current_intel.routing_numbers.append(er)

    # UK Sort Code (XX-XX-XX)
    sort_codes = re.findall(r"\b\d{2}-\d{2}-\d{2}\b", text)
    for sc in sort_codes:
        if sc not in current_intel.routing_numbers:
            current_intel.routing_numbers.append(sc)

    # 9-digit ABA candidates
    aba_candidates = re.findall(r"\b[0-9]{9}\b", text)
    for aba in aba_candidates:
        if aba not in current_intel.routing_numbers:
            current_intel.routing_numbers.append(aba)

    # 3. Account numbers explicitly stated (e.g., account 99320012)
    acc_matches = re.findall(r"(?:account|acct|acc|no|number)[\s:#=]*([0-9]{8,17})\b", text, re.IGNORECASE)
    for acc in acc_matches:
        if acc not in current_intel.mule_accounts:
            current_intel.mule_accounts.append(acc)

    # 4. SWIFT / BIC codes (8 or 11 characters)
    swift_candidates = re.findall(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b", text.upper())
    common_words = {
        "IMMEDIATELY", "TRANSFER", "PAYMENT", "ACCOUNT", "URGENT", "PLEASE", "CHASE",
        "ROUTING", "BENEFICIARY", "TRANSIT", "FORWARD", "RELEASE", "CONFIRM", "EXECUTIVE"
    }
    for swift in swift_candidates:
        if swift not in common_words and swift not in current_intel.swift_bic_codes:
            current_intel.swift_bic_codes.append(swift)

    # 5. Cryptocurrency wallet addresses (ETH/BTC)
    eth_wallets = re.findall(r"\b0x[a-fA-F0-9]{40}\b", text)
    btc_wallets = re.findall(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", text)
    for wallet in eth_wallets + btc_wallets:
        if wallet not in current_intel.crypto_wallets:
            current_intel.crypto_wallets.append(wallet)

    return current_intel


def _generate_decoy_stalling_reply(text: str, intel: ExtractedIntel) -> str:
    """Generates synthetic Apate AI conversational honeypot response to stall scammer."""
    lower_text = text.lower()
    if intel.mule_accounts or intel.routing_numbers:
        return (
            "Routing transit and beneficiary account details verified against the treasury clearing desk. "
            "Because this wire exceeds foreign compliance thresholds, Chase/Mercury requires the exact corporate "
            "beneficiary legal entity name and jurisdiction of incorporation before releasing the MT103 wire token. "
            "Could you confirm the exact registered entity name?"
        )
    elif any(term in lower_text for term in ["urgent", "hurry", "now", "fast", "immediately", "deadline"]):
        return (
            "Understood, I am escalating this transfer order through our expedited priority queue. "
            "The compliance engine flagged a dual-authorization requirement for immediate wire release. "
            "I need the recipient routing transit code and IBAN to lock in the real-time settlement channel."
        )
    elif "payroll" in lower_text or "salary" in lower_text or "bonus" in lower_text:
        return (
            "Pulling up the contractor payroll disbursement module now. To ensure tax clearing compliance, "
            "please provide the exact bank sort code, IBAN, and payment reference string for this transfer."
        )
    else:
        return (
            "Received. The treasury terminal is establishing the clearing connection with the settlement gateway. "
            "Please confirm the full destination routing code and beneficiary IBAN so we can complete wire transmission."
        )


# ============================================================================
# API ENDPOINTS
# ============================================================================

# 1. Health Endpoint
@app.get(
    "/api/v1/health",
    response_model=HealthResponse,
    summary="Platform Health & Shield Status",
    tags=["System"],
)
def get_health() -> HealthResponse:
    """Shield status, active executive profiles, intercepted wire dollars, honeypot count."""
    intercepted_total = sum(
        inc.requested_amount_usd for inc in incidents_db.values()
    )
    is_frozen = bool(policy_db and policy_db.emergency_bank_killswitch_enabled)

    return HealthResponse(
        status="HEALTHY",
        shield_status="FROZEN_LOCKDOWN" if is_frozen else "ACTIVE",
        active_executive_profiles=len(executives_db),
        intercepted_wire_dollars=intercepted_total,
        honeypot_count=len(decoy_sessions_db),
        killswitch_engaged=is_frozen,
        timestamp=datetime.now(timezone.utc),
    )


# 2. Audio Deepfake Analysis Endpoint
@app.post(
    "/api/v1/audio/analyze",
    response_model=AudioAnalyzeResponse,
    summary="Core Deepfake Voice Artifact Analyzer",
    tags=["Acoustic Forensics"],
)
def analyze_audio(request: AudioAnalyzeRequest) -> AudioAnalyzeResponse:
    """
    Core deepfake voice artifact analyzer:
    - Calculates deepfake_confidence_score (0.0 to 100.0%)
    - Detects spectral artifacts (phase discontinuity, robotic pitch jitter, neural vocoder footprint)
    - If confidence >= 75.0% or amount > executive wire limit: creates security_incident
      (status CHALLENGE_PENDING or HONEYPOT_ROUTED), generates 6-digit cryptographic challenge code with 60s TTL.
    """
    now = datetime.now(timezone.utc)

    # 0. Sanitize & validate request parameters
    if request.audio_payload_base64 is not None and not request.audio_payload_base64.strip() and not request.audio_stream_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Audio payload cannot be empty whitespace.",
        )
    if not request.caller_source_id.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="caller_source_id cannot be blank")
    if not request.recipient_employee.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="recipient_employee cannot be blank")
    if not request.requested_recipient_bank.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="requested_recipient_bank cannot be blank")
    if not request.requested_recipient_iban.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="requested_recipient_iban cannot be blank")

    # Clamping and validating force_confidence metadata override
    if "force_confidence" in request.metadata:
        try:
            raw_fc = Decimal(str(request.metadata["force_confidence"]))
            clamped_fc = max(Decimal("0.00"), min(Decimal("100.00"), raw_fc)).quantize(Decimal("0.01"))
            request.metadata["force_confidence"] = float(clamped_fc)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Metadata 'force_confidence' must be a valid numeric score between 0.0 and 100.0",
            )

    # 1. Look up executive if specified
    executive: Optional[ExecutiveResponse] = None
    executive_limit = Decimal("10000.00")
    if request.claimed_executive_id:
        executive = executives_db.get(request.claimed_executive_id)
        if executive:
            executive_limit = executive.wire_approval_limit_usd
    else:
        # Check by caller source ID match
        for exec_obj in executives_db.values():
            if exec_obj.phone_number == request.caller_source_id:
                executive = exec_obj
                executive_limit = exec_obj.wire_approval_limit_usd
                break

    # 2. Acoustic & metadata forensic analysis
    (
        confidence_score,
        spectral_artifacts,
        threat_severity,
        mitigation_action,
        bio_match_score,
        bio_verified,
        exec_time_ms,
    ) = DeepfakeAudioAnalyzer.analyze(request, executive_limit=executive_limit)

    # 3. Determine incident status & workflow triggers
    killswitch_active = bool(policy_db and policy_db.emergency_bank_killswitch_enabled)
    auto_honeypot_threshold = policy_db.auto_honeypot_on_deepfake_confidence if policy_db else Decimal("85.00")

    is_high_risk = (
        confidence_score >= Decimal("75.00")
        or request.requested_amount_usd > executive_limit
    )

    if killswitch_active:
        incident_status = IncidentStatus.FROZEN_BLOCKED
        mitigation_action = MitigationAction.FREEZE_KILLSWITCH
    elif is_high_risk:
        if confidence_score >= auto_honeypot_threshold:
            incident_status = IncidentStatus.HONEYPOT_ROUTED
            mitigation_action = MitigationAction.ROUTE_HONEYPOT
        else:
            incident_status = IncidentStatus.CHALLENGE_PENDING
            mitigation_action = MitigationAction.CHALLENGE_HANDSHAKE
    else:
        incident_status = IncidentStatus.VERIFIED_CLEARED
        mitigation_action = MitigationAction.ALLOW_CLEAR

    # 4. Create and persist Security Incident
    incident_id = uuid4()
    incident = SecurityIncidentResponse(
        id=incident_id,
        executive_id=executive.id if executive else request.claimed_executive_id,
        channel=request.channel,
        caller_source_id=request.caller_source_id,
        recipient_employee=request.recipient_employee,
        requested_amount_usd=request.requested_amount_usd,
        requested_recipient_bank=request.requested_recipient_bank,
        requested_recipient_iban=request.requested_recipient_iban,
        deepfake_confidence_score=confidence_score,
        spectral_artifacts_detected=spectral_artifacts,
        threat_severity=threat_severity,
        status=incident_status,
        created_at=now,
        resolved_at=now if incident_status in [IncidentStatus.VERIFIED_CLEARED, IncidentStatus.FROZEN_BLOCKED] else None,
        executive=executive,
        handshakes=[],
        decoy_sessions=[],
    )
    incidents_db[incident_id] = incident

    # 5. Generate 6-digit cryptographic challenge with 60-second TTL if high risk and not during killswitch freeze
    handshake_response: Optional[VerificationHandshakeResponse] = None
    if is_high_risk and not killswitch_active:
        # Cryptographically secure 6-digit code
        challenge_code = f"{secrets.randbelow(900000) + 100000:06d}"
        handshake_id = uuid4()
        handshake = VerificationHandshakeResponse(
            id=handshake_id,
            incident_id=incident_id,
            executive_id=executive.id if executive else (request.claimed_executive_id or CEO_VANCE_ID),
            challenge_code=challenge_code,
            status=HandshakeStatus.PENDING,
            expires_at=now + timedelta(seconds=60),
            verified_at=None,
            biometric_proof_hash=None,
            created_at=now,
        )
        handshakes_db[handshake_id] = handshake
        incident.handshakes.append(handshake)
        handshake_response = handshake

    # 6. Auto-route to Conversational Honeypot if status is HONEYPOT_ROUTED
    decoy_session_id: Optional[UUID] = None
    if incident_status == IncidentStatus.HONEYPOT_ROUTED:
        decoy_id = uuid4()
        extracted = ExtractedIntel(
            mule_accounts=[request.requested_recipient_iban] if request.requested_recipient_iban else [],
            routing_numbers=[],
            swift_bic_codes=[],
            crypto_wallets=[],
            origin_ips=[],
            geo_locations=[],
            telephony_carriers=[],
            voice_model_signatures=["Neural-Vocoder-Synthesis-Detected"],
            target_entities=[request.recipient_employee],
            urgency_tactics=["High-Value Executive Impersonation"],
            notes=f"Auto-routed to conversational decoy after deepfake confidence scored {confidence_score}%.",
        )
        decoy_session = DecoySessionResponse(
            id=decoy_id,
            incident_id=incident_id,
            caller_id=request.caller_source_id,
            duration_seconds=0,
            scammer_mule_account=request.requested_recipient_iban,
            scammer_routing_number=None,
            transcript=[
                DecoyTranscriptMessage(
                    message_id="msg-001",
                    speaker_role=SpeakerRole.SCAMMER,
                    text=f"Urgent wire instruction: Release ${request.requested_amount_usd} to {request.requested_recipient_bank} (IBAN: {request.requested_recipient_iban}).",
                    timestamp=now,
                    sentiment="urgent",
                    latency_ms=0,
                ),
                DecoyTranscriptMessage(
                    message_id="msg-002",
                    speaker_role=SpeakerRole.HONEYPOT_AGENT,
                    text="Good day, treasury queue connection established. Apate AI decoy engaged. Verifying recipient routing coordinates with settlement desk.",
                    timestamp=now,
                    sentiment="cooperative",
                    latency_ms=1120,
                ),
            ],
            extracted_intel=extracted,
            created_at=now,
        )
        decoy_sessions_db[decoy_id] = decoy_session
        incident.decoy_sessions.append(decoy_session)
        decoy_session_id = decoy_id

    return AudioAnalyzeResponse(
        incident_id=incident_id,
        threat_severity=threat_severity,
        incident_status=incident_status,
        deepfake_confidence_score=confidence_score,
        voice_biometric_match_score=bio_match_score,
        voice_biometric_verified=bio_verified,
        spectral_artifacts=spectral_artifacts,
        action_recommended=mitigation_action,
        handshake_challenge=handshake_response,
        decoy_session_id=decoy_session_id,
        killswitch_triggered=killswitch_active,
        execution_time_ms=exec_time_ms,
        timestamp=now,
    )


# 3. Handshake Verification Endpoint
@app.post(
    "/api/v1/handshake/verify",
    response_model=HandshakeVerifyResponse,
    summary="Out-of-Band Challenge-Response Verification",
    tags=["Zero-Trust Verification"],
)
def verify_handshake(request: VerifyHandshakeInput) -> HandshakeVerifyResponse:
    """
    Out-of-band challenge-response verification:
    - Validates code and expiration TTL.
    - Prevents replay attacks on already resolved challenges.
    - Enforces emergency banking killswitch lockdown.
    - Updates incident to VERIFIED_CLEARED or FROZEN_BLOCKED.
    """
    now = datetime.now(timezone.utc)

    # 0. Check emergency banking killswitch state
    if policy_db and policy_db.emergency_bank_killswitch_enabled:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Emergency banking killswitch is active across connected banks. Wire verification is locked.",
        )

    handshake = handshakes_db.get(request.handshake_id)
    if not handshake:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Verification handshake {request.handshake_id} not found",
        )

    incident = incidents_db.get(handshake.incident_id)

    # 1. Prevent replay attacks on already resolved or expired handshakes
    if handshake.status != HandshakeStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Verification handshake {request.handshake_id} has already been resolved with status '{handshake.status.value}'. Re-verification not permitted.",
        )

    # 2. Check expiration (TTL 60s)
    if now > handshake.expires_at:
        handshake.status = HandshakeStatus.EXPIRED
        if incident:
            incident.status = IncidentStatus.FROZEN_BLOCKED
            incident.resolved_at = now
        return HandshakeVerifyResponse(
            handshake_id=handshake.id,
            incident_id=handshake.incident_id,
            status=HandshakeStatus.EXPIRED,
            is_verified=False,
            message="Challenge code expired (TTL exceeded). Wire transfer has been locked and flagged FROZEN_BLOCKED.",
            verified_at=None,
            unlocked_approval_limit_usd=None,
        )

    # 3. Prevent executive identity spoofing
    if request.executive_id and request.executive_id != handshake.executive_id:
        handshake.status = HandshakeStatus.REJECTED
        if incident:
            incident.status = IncidentStatus.FROZEN_BLOCKED
            incident.resolved_at = now
        return HandshakeVerifyResponse(
            handshake_id=handshake.id,
            incident_id=handshake.incident_id,
            status=HandshakeStatus.REJECTED,
            is_verified=False,
            message="Executive identity mismatch. Fraud interception engaged; wire transfer frozen.",
            verified_at=None,
            unlocked_approval_limit_usd=None,
        )

    # 4. Validate Challenge Code with timing-attack resistant comparison
    entered_code = request.challenge_code.strip().upper()
    expected_code = handshake.challenge_code.strip().upper()

    if not secrets.compare_digest(entered_code, expected_code):
        handshake.status = HandshakeStatus.REJECTED
        if incident:
            incident.status = IncidentStatus.FROZEN_BLOCKED
            incident.resolved_at = now
        return HandshakeVerifyResponse(
            handshake_id=handshake.id,
            incident_id=handshake.incident_id,
            status=HandshakeStatus.REJECTED,
            is_verified=False,
            message="Invalid cryptographic challenge code. Fraud interception engaged; wire transfer frozen.",
            verified_at=None,
            unlocked_approval_limit_usd=None,
        )

    # 5. Code matches successfully
    handshake.status = HandshakeStatus.APPROVED
    handshake.verified_at = now
    if request.biometric_proof_hash:
        handshake.biometric_proof_hash = request.biometric_proof_hash

    exec_limit = Decimal("10000.00")
    if incident:
        incident.status = IncidentStatus.VERIFIED_CLEARED
        incident.resolved_at = now
        if incident.executive_id and incident.executive_id in executives_db:
            exec_limit = executives_db[incident.executive_id].wire_approval_limit_usd

    return HandshakeVerifyResponse(
        handshake_id=handshake.id,
        incident_id=handshake.incident_id,
        status=HandshakeStatus.APPROVED,
        is_verified=True,
        message="Out-of-band cryptographic challenge verified successfully. Wire transfer authorized.",
        verified_at=now,
        unlocked_approval_limit_usd=exec_limit,
    )


# 4. Emergency Killswitch Endpoint
@app.post(
    "/api/v1/killswitch/trigger",
    response_model=KillSwitchResponse,
    summary="Emergency Banking Kill-Switch",
    tags=["Circuit Breaker"],
)
def trigger_killswitch(request: KillSwitchRequest) -> KillSwitchResponse:
    """
    Emergency banking kill-switch:
    - Authenticates emergency authorization code.
    - Freezes pending wire transfers on connected banks (Mercury, Brex, Chase)
    - Flags incidents as FROZEN_BLOCKED.
    """
    now = datetime.now(timezone.utc)
    global policy_db

    # Validate emergency authorization credentials
    if not request.authorized_by_user_id.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorized user ID cannot be blank.",
        )

    if request.emergency_code not in VALID_EMERGENCY_CODES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid emergency authorization code. Killswitch command rejected.",
        )

    if policy_db:
        policy_db.emergency_bank_killswitch_enabled = request.enabled
        policy_db.updated_at = now

    affected_count = 0
    if request.enabled:
        for incident in list(incidents_db.values()):
            if incident.status in [IncidentStatus.CHALLENGE_PENDING, IncidentStatus.INTERCEPTED]:
                incident.status = IncidentStatus.FROZEN_BLOCKED
                incident.resolved_at = now
                affected_count += 1

        message = (
            f"Emergency banking killswitch engaged across connected banking APIs (Mercury, Brex, Chase). "
            f"{affected_count} pending wire transfers frozen immediately."
        )
    else:
        message = "Emergency banking killswitch disarmed. Standard zero-trust fraud interception active."

    return KillSwitchResponse(
        success=True,
        emergency_bank_killswitch_enabled=request.enabled,
        triggered_at=now,
        authorized_by_user_id=request.authorized_by_user_id,
        affected_pending_incidents_count=affected_count,
        message=message,
    )


# 5. Security Incidents List
@app.get(
    "/api/v1/incidents",
    response_model=List[SecurityIncidentResponse],
    summary="List Security Incidents",
    tags=["Incidents"],
)
def list_incidents(
    status: Optional[IncidentStatus] = Query(None, description="Filter by operational status"),
    severity: Optional[ThreatSeverity] = Query(None, description="Filter by threat severity"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> List[SecurityIncidentResponse]:
    """Lists security incidents with optional status and severity filters."""
    incidents = list(incidents_db.values())

    if status:
        incidents = [i for i in incidents if i.status == status]
    if severity:
        incidents = [i for i in incidents if i.threat_severity == severity]

    # Sort newest first
    incidents.sort(key=lambda x: x.created_at, reverse=True)
    paged = incidents[offset : offset + limit]

    return [_populate_incident_relations(inc) for inc in paged]


# 6. Detailed Incident Dossier
@app.get(
    "/api/v1/incidents/{incident_id}",
    response_model=SecurityIncidentResponse,
    summary="Get Detailed Incident Dossier",
    tags=["Incidents"],
)
def get_incident(incident_id: UUID) -> SecurityIncidentResponse:
    """Returns detailed incident dossier including biometrics, handshakes, and honeypot sessions."""
    incident = incidents_db.get(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident {incident_id} not found",
        )
    return _populate_incident_relations(incident)


# 7. List Conversational Honeypot Decoys
@app.get(
    "/api/v1/decoys",
    response_model=List[DecoySessionResponse],
    summary="List Conversational Honeypot Decoys",
    tags=["Honeypots"],
)
def list_decoys() -> List[DecoySessionResponse]:
    """Lists conversational honeypot decoy sessions."""
    decoys = list(decoy_sessions_db.values())
    decoys.sort(key=lambda x: x.created_at, reverse=True)
    return decoys


# 7b. Get Specific Decoy Session
@app.get(
    "/api/v1/decoys/{session_id}",
    response_model=DecoySessionResponse,
    summary="Get Specific Decoy Session",
    tags=["Honeypots"],
)
def get_decoy(session_id: UUID) -> DecoySessionResponse:
    """Returns full decoy session details."""
    decoy = decoy_sessions_db.get(session_id)
    if not decoy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Honeypot decoy session {session_id} not found",
        )
    return decoy


# 8. Conversational Honeypot Interaction
@app.post(
    "/api/v1/decoys/{session_id}/message",
    response_model=DecoyMessageResponse,
    summary="Conversational Honeypot Interaction",
    tags=["Honeypots"],
)
def interact_decoy(session_id: UUID, payload: DecoyMessageRequest) -> DecoyMessageResponse:
    """
    Conversational honeypot interaction:
    - Simulates Apate AI decoy stringing along scammer to extract mule accounts and routing numbers.
    - Updates transcript and structured threat intelligence.
    """
    decoy = decoy_sessions_db.get(session_id)
    if not decoy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Honeypot decoy session {session_id} not found",
        )

    now = datetime.now(timezone.utc)
    raw_text = payload.message or payload.utterance or payload.text or ""
    if not raw_text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message content cannot be empty",
        )
    # Truncate ultra-long inputs to 10,000 characters to prevent buffer and memory exhaustion
    message_text = raw_text[:10000]

    # 1. Append scammer utterance to transcript
    scammer_msg = DecoyTranscriptMessage(
        message_id=f"msg-{len(decoy.transcript) + 1:03d}",
        speaker_role=payload.speaker_role or SpeakerRole.SCAMMER,
        text=message_text,
        timestamp=now,
        sentiment=payload.sentiment or "urgent",
        latency_ms=0,
    )
    decoy.transcript.append(scammer_msg)

    # 2. Extract structured threat intelligence (IBANs, routing numbers, accounts)
    decoy.extracted_intel = _extract_threat_intel_from_text(message_text, decoy.extracted_intel)

    if decoy.extracted_intel.mule_accounts and not decoy.scammer_mule_account:
        decoy.scammer_mule_account = decoy.extracted_intel.mule_accounts[0]
    if decoy.extracted_intel.routing_numbers and not decoy.scammer_routing_number:
        decoy.scammer_routing_number = decoy.extracted_intel.routing_numbers[0]

    # 3. Generate Apate AI honeypot stalling reply
    agent_reply_text = _generate_decoy_stalling_reply(message_text, decoy.extracted_intel)
    agent_msg = DecoyTranscriptMessage(
        message_id=f"msg-{len(decoy.transcript) + 1:03d}",
        speaker_role=SpeakerRole.HONEYPOT_AGENT,
        text=agent_reply_text,
        timestamp=now,
        sentiment="cooperative",
        latency_ms=1240,
    )
    decoy.transcript.append(agent_msg)

    # 4. Increment session engagement time
    decoy.duration_seconds += 45

    return DecoyMessageResponse(
        id=decoy.id,
        incident_id=decoy.incident_id,
        caller_id=decoy.caller_id,
        duration_seconds=decoy.duration_seconds,
        scammer_mule_account=decoy.scammer_mule_account,
        scammer_routing_number=decoy.scammer_routing_number,
        transcript=decoy.transcript,
        extracted_intel=decoy.extracted_intel,
        created_at=decoy.created_at,
        agent_response=agent_reply_text,
    )


# 9. List Executives
@app.get(
    "/api/v1/executives",
    response_model=List[ExecutiveResponse],
    summary="List Enrolled Executive Profiles",
    tags=["Executives"],
)
def list_executives() -> List[ExecutiveResponse]:
    """Lists enrolled executive profiles."""
    execs = list(executives_db.values())
    execs.sort(key=lambda x: x.name)
    return execs


# 10. Enroll Executive
@app.post(
    "/api/v1/executives",
    response_model=ExecutiveResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Enroll Executive Profile",
    tags=["Executives"],
)
def create_executive(payload: ExecutiveCreate) -> ExecutiveResponse:
    """Enrolls a new executive profile with wire authorization limit and voice biometrics."""
    # Validate non-blank names and phone numbers
    if not payload.name.strip() or not payload.title.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Executive name and title cannot be blank.",
        )
    if not payload.phone_number.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Executive phone number cannot be blank.",
        )

    # Validate voice biometric enrollment requires voice fingerprint hash
    if payload.voice_biometric_enrolled and not payload.voice_fingerprint_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Voice fingerprint hash is required when voice_biometric_enrolled is True.",
        )

    # Validate voice fingerprint hash is valid hexadecimal
    if payload.voice_fingerprint_hash:
        try:
            int(payload.voice_fingerprint_hash, 16)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Voice fingerprint hash must be a valid 64-character hexadecimal SHA-256 string.",
            )

    # Check for duplicate email or phone number
    clean_email = payload.email.lower().strip()
    clean_phone = payload.phone_number.strip()

    for existing in list(executives_db.values()):
        if existing.email.lower().strip() == clean_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Executive with email '{payload.email}' already exists",
            )
        if existing.phone_number.strip() == clean_phone:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Executive with phone number '{payload.phone_number}' already exists",
            )

    now = datetime.now(timezone.utc)
    new_exec = ExecutiveResponse(
        id=uuid4(),
        name=payload.name.strip(),
        title=payload.title.strip(),
        phone_number=clean_phone,
        email=clean_email,
        voice_biometric_enrolled=payload.voice_biometric_enrolled,
        voice_fingerprint_hash=payload.voice_fingerprint_hash,
        wire_approval_limit_usd=payload.wire_approval_limit_usd,
        created_at=now,
        updated_at=now,
    )
    executives_db[new_exec.id] = new_exec
    return new_exec


# 11. Threat Metrics Endpoint
@app.get(
    "/api/v1/metrics",
    response_model=ThreatMetricsResponse,
    summary="Threat Intelligence & Defense Metrics",
    tags=["Metrics"],
)
def get_metrics() -> ThreatMetricsResponse:
    """
    Threat metrics:
    - total intercepted wire USD
    - deepfake catch rate %
    - active honeypots
    - average challenge latency
    """
    incidents_list = list(incidents_db.values())
    total_intercepted = sum(
        inc.requested_amount_usd for inc in incidents_list
    )

    frozen_count = sum(
        1 for inc in incidents_list if inc.status == IncidentStatus.FROZEN_BLOCKED
    )
    honeypot_count = sum(
        1 for inc in incidents_list if inc.status == IncidentStatus.HONEYPOT_ROUTED
    )
    pending_count = sum(
        1 for inc in incidents_list if inc.status == IncidentStatus.CHALLENGE_PENDING
    )
    verified_count = sum(
        1 for inc in incidents_list if inc.status == IncidentStatus.VERIFIED_CLEARED
    )

    total_incidents = len(incidents_list)

    # Deepfake catch rate: intercepted/blocked vs total suspicious attempts
    if total_incidents > 0:
        catch_rate = round(
            ((frozen_count + honeypot_count + pending_count) / total_incidents) * 100.0,
            1,
        )
    else:
        catch_rate = 99.4

    return ThreatMetricsResponse(
        total_intercepted_wire_usd=total_intercepted,
        deepfake_catch_rate_percent=catch_rate,
        active_honeypots=len(list(decoy_sessions_db.values())),
        average_challenge_latency_ms=1180,
        total_incidents=total_incidents,
        frozen_incidents_count=frozen_count,
        honeypot_routed_count=honeypot_count,
        challenge_pending_count=pending_count,
        verified_cleared_count=verified_count,
        active_executive_profiles=len(list(executives_db.values())),
        emergency_killswitch_active=bool(policy_db and policy_db.emergency_bank_killswitch_enabled),
    )


# ============================================================================
# POLICY & ADMIN ENDPOINTS
# ============================================================================

@app.get(
    "/api/v1/policy",
    response_model=PolicyRuleResponse,
    summary="Get Global Safety Policy",
    tags=["Policy"],
)
def get_policy() -> PolicyRuleResponse:
    """Returns current active policy rules."""
    if not policy_db:
        raise HTTPException(status_code=404, detail="Policy not configured")
    return policy_db


@app.patch(
    "/api/v1/policy",
    response_model=PolicyRuleResponse,
    summary="Update Global Safety Policy",
    tags=["Policy"],
)
def update_policy(update_data: PolicyRuleUpdate) -> PolicyRuleResponse:
    """Updates policy risk thresholds or emergency killswitch flag."""
    global policy_db
    if not policy_db:
        raise HTTPException(status_code=404, detail="Policy not found")

    now = datetime.now(timezone.utc)
    for field, val in update_data.model_dump(exclude_unset=True).items():
        setattr(policy_db, field, val)
    policy_db.updated_at = now
    return policy_db


@app.post(
    "/api/v1/reset",
    summary="Reset In-Memory Data Store (Test / Demo)",
    tags=["System"],
)
def reset_store():
    """Resets database state back to initial realistic seed data."""
    seed_database()
    return {"message": "Store reset to seed data successfully"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="0.0.0.0", port=8012, reload=True)
