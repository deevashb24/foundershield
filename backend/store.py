"""
FounderShield AI - In-Memory Database Store & Seed Data
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Dict, List, Optional
from uuid import UUID, uuid4

from models.schemas import (
    Channel,
    DecoySessionResponse,
    DecoyTranscriptMessage,
    ExecutiveResponse,
    ExtractedIntel,
    HandshakeStatus,
    IncidentStatus,
    PolicyRuleResponse,
    SecurityIncidentResponse,
    SpeakerRole,
    SpectralArtifactItem,
    ThreatSeverity,
    VerificationHandshakeResponse,
)

# Thread-safe lock for store updates
_lock = threading.Lock()

# Global in-memory storage dicts
executives_db: Dict[UUID, ExecutiveResponse] = {}
incidents_db: Dict[UUID, SecurityIncidentResponse] = {}
handshakes_db: Dict[UUID, VerificationHandshakeResponse] = {}
decoy_sessions_db: Dict[UUID, DecoySessionResponse] = {}
policy_db: Optional[PolicyRuleResponse] = None

# Known UUIDs for deterministic seed data
CEO_VANCE_ID = UUID("c4a1e944-2458-45b0-9883-8a3c5a611101")
CFO_ROSTOVA_ID = UUID("c4a1e944-2458-45b0-9883-8a3c5a611102")

INCIDENT_1_ID = UUID("d1111111-1111-1111-1111-111111111111")
INCIDENT_2_ID = UUID("d2222222-2222-2222-2222-222222222222")
INCIDENT_3_ID = UUID("d3333333-3333-3333-3333-333333333333")
INCIDENT_4_ID = UUID("d4444444-4444-4444-4444-444444444444")

HANDSHAKE_3_ID = UUID("h3333333-3333-3333-3333-333333333333".replace("h", "a"))
HANDSHAKE_4_ID = UUID("h4444444-4444-4444-4444-444444444444".replace("h", "b"))

DECOY_1_ID = UUID("e1111111-1111-1111-1111-111111111111")
DECOY_2_ID = UUID("e2222222-2222-2222-2222-222222222222")

POLICY_ID = UUID("a0000000-0000-0000-0000-000000000001")


def seed_database():
    """Initializes the database with realistic seed data."""
    global executives_db, incidents_db, handshakes_db, decoy_sessions_db, policy_db

    with _lock:
        executives_db.clear()
        incidents_db.clear()
        handshakes_db.clear()
        decoy_sessions_db.clear()

        now = datetime.now(timezone.utc)

        # 1. Seed Policy
        policy_db = PolicyRuleResponse(
            id=POLICY_ID,
            policy_name="Zero-Trust Global Wire Protection Policy",
            max_unverified_wire_usd=Decimal("1000.00"),
            require_biometric_over_usd=Decimal("25000.00"),
            auto_honeypot_on_deepfake_confidence=Decimal("85.00"),
            emergency_bank_killswitch_enabled=False,
            created_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            updated_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        )

        # 2. Seed Executives
        ceo_vance = ExecutiveResponse(
            id=CEO_VANCE_ID,
            name="Alexander Vance",
            title="Chief Executive Officer",
            phone_number="+1-415-555-0199",
            email="alexander.vance@vanceholdings.com",
            voice_biometric_enrolled=True,
            voice_fingerprint_hash="a3f8b91924bce3e8d910a9c8f0e1329bb6d87e0fa1b2c3d4e5f60718293a4b5c",
            wire_approval_limit_usd=Decimal("10000.00"),
            created_at=datetime(2026, 1, 15, 8, 0, 0, tzinfo=timezone.utc),
            updated_at=datetime(2026, 1, 15, 8, 0, 0, tzinfo=timezone.utc),
        )

        cfo_rostova = ExecutiveResponse(
            id=CFO_ROSTOVA_ID,
            name="Elena Rostova",
            title="Chief Financial Officer",
            phone_number="+1-212-555-0144",
            email="elena.rostova@vanceholdings.com",
            voice_biometric_enrolled=True,
            voice_fingerprint_hash="d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6",
            wire_approval_limit_usd=Decimal("25000.00"),
            created_at=datetime(2026, 2, 1, 9, 30, 0, tzinfo=timezone.utc),
            updated_at=datetime(2026, 2, 1, 9, 30, 0, tzinfo=timezone.utc),
        )

        executives_db[CEO_VANCE_ID] = ceo_vance
        executives_db[CFO_ROSTOVA_ID] = cfo_rostova

        # 3. Seed 4 Realistic Security Incidents
        incident_1 = SecurityIncidentResponse(
            id=INCIDENT_1_ID,
            executive_id=CEO_VANCE_ID,
            channel=Channel.VOICE_CALL,
            caller_source_id="+1-312-555-8910",
            recipient_employee="Marcus Brody (Treasury Manager)",
            requested_amount_usd=Decimal("240000.00"),
            requested_recipient_bank="Deutsche Handelsbank AG",
            requested_recipient_iban="DE89370400440532013000",
            deepfake_confidence_score=Decimal("98.40"),
            spectral_artifacts_detected=[
                SpectralArtifactItem(
                    type="neural_vocoder_footprint",
                    confidence=98.40,
                    frequency_band_hz="2000Hz - 7500Hz",
                    description="Neural vocoder footprint (HiFi-GAN synthesis envelope detected)",
                    timestamp_offset_ms=1420,
                ),
                SpectralArtifactItem(
                    type="phase_discontinuity",
                    confidence=94.10,
                    frequency_band_hz="2500Hz - 4800Hz",
                    description="Phase discontinuity across phoneme transitions showing boundary stitching",
                    timestamp_offset_ms=2100,
                ),
                SpectralArtifactItem(
                    type="robotic_pitch_jitter",
                    confidence=89.70,
                    frequency_band_hz="120Hz - 290Hz",
                    description="Static fundamental frequency modulation lacking natural human micro-tremor",
                    timestamp_offset_ms=3150,
                ),
            ],
            threat_severity=ThreatSeverity.CRITICAL,
            status=IncidentStatus.HONEYPOT_ROUTED,
            created_at=datetime(2026, 9, 27, 8, 15, 0, tzinfo=timezone.utc),
            resolved_at=None,
            executive=ceo_vance,
        )

        incident_2 = SecurityIncidentResponse(
            id=INCIDENT_2_ID,
            executive_id=CFO_ROSTOVA_ID,
            channel=Channel.WHATSAPP_AUDIO,
            caller_source_id="+44-7700-900821",
            recipient_employee="Sarah Lin (VP People Operations)",
            requested_amount_usd=Decimal("45000.00"),
            requested_recipient_bank="Revolut Business UK",
            requested_recipient_iban="GB29REVO00993200129482",
            deepfake_confidence_score=Decimal("86.20"),
            spectral_artifacts_detected=[
                SpectralArtifactItem(
                    type="neural_vocoder_footprint",
                    confidence=88.50,
                    frequency_band_hz="3000Hz - 6500Hz",
                    description="ElevenLabs v2 model acoustic signature matches synthetic harmonics",
                    timestamp_offset_ms=850,
                ),
                SpectralArtifactItem(
                    type="robotic_pitch_jitter",
                    confidence=83.90,
                    frequency_band_hz="150Hz - 320Hz",
                    description="Pitch variance standard deviation abnormally suppressed (0.8 Hz vs human 4.2 Hz)",
                    timestamp_offset_ms=1640,
                ),
            ],
            threat_severity=ThreatSeverity.CRITICAL,
            status=IncidentStatus.HONEYPOT_ROUTED,
            created_at=datetime(2026, 9, 27, 9, 45, 0, tzinfo=timezone.utc),
            resolved_at=None,
            executive=cfo_rostova,
        )

        incident_3 = SecurityIncidentResponse(
            id=INCIDENT_3_ID,
            executive_id=CEO_VANCE_ID,
            channel=Channel.TELEGRAM_VOICE,
            caller_source_id="@alex_vance_tg",
            recipient_employee="Devon Reed (Head of DevOps)",
            requested_amount_usd=Decimal("18500.00"),
            requested_recipient_bank="Barclays Bank Plc",
            requested_recipient_iban="GB12BARC20000087654321",
            deepfake_confidence_score=Decimal("78.50"),
            spectral_artifacts_detected=[
                SpectralArtifactItem(
                    type="phase_discontinuity",
                    confidence=79.20,
                    frequency_band_hz="2200Hz - 5000Hz",
                    description="Acoustic phase cancellation in high treble consonants",
                    timestamp_offset_ms=620,
                ),
                SpectralArtifactItem(
                    type="robotic_pitch_jitter",
                    confidence=77.80,
                    frequency_band_hz="110Hz - 250Hz",
                    description="Synthetic prosody flattening across affirmative statement",
                    timestamp_offset_ms=1180,
                ),
            ],
            threat_severity=ThreatSeverity.HIGH,
            status=IncidentStatus.CHALLENGE_PENDING,
            created_at=datetime(2026, 9, 27, 10, 30, 0, tzinfo=timezone.utc),
            resolved_at=None,
            executive=ceo_vance,
        )

        incident_4 = SecurityIncidentResponse(
            id=INCIDENT_4_ID,
            executive_id=CFO_ROSTOVA_ID,
            channel=Channel.VOICE_CALL,
            caller_source_id="+1-212-555-0144",
            recipient_employee="Chloe Zhao (Procurement Specialist)",
            requested_amount_usd=Decimal("9200.00"),
            requested_recipient_bank="Chase JPMorgan",
            requested_recipient_iban="US33CHAS02100002198765",
            deepfake_confidence_score=Decimal("82.00"),
            spectral_artifacts_detected=[
                SpectralArtifactItem(
                    type="neural_vocoder_footprint",
                    confidence=84.00,
                    frequency_band_hz="1800Hz - 6000Hz",
                    description="Speech synthesis artifact from Tortoise-TTS vocoder",
                    timestamp_offset_ms=990,
                )
            ],
            threat_severity=ThreatSeverity.HIGH,
            status=IncidentStatus.FROZEN_BLOCKED,
            created_at=datetime(2026, 9, 27, 11, 10, 0, tzinfo=timezone.utc),
            resolved_at=datetime(2026, 9, 27, 11, 15, 0, tzinfo=timezone.utc),
            executive=cfo_rostova,
        )

        incidents_db[INCIDENT_1_ID] = incident_1
        incidents_db[INCIDENT_2_ID] = incident_2
        incidents_db[INCIDENT_3_ID] = incident_3
        incidents_db[INCIDENT_4_ID] = incident_4

        # 4. Seed Verification Handshakes
        handshake_3 = VerificationHandshakeResponse(
            id=HANDSHAKE_3_ID,
            incident_id=INCIDENT_3_ID,
            executive_id=CEO_VANCE_ID,
            challenge_code="892415",
            status=HandshakeStatus.PENDING,
            expires_at=now + timedelta(seconds=60),
            verified_at=None,
            biometric_proof_hash=None,
            created_at=now,
        )

        handshake_4 = VerificationHandshakeResponse(
            id=HANDSHAKE_4_ID,
            incident_id=INCIDENT_4_ID,
            executive_id=CFO_ROSTOVA_ID,
            challenge_code="471903",
            status=HandshakeStatus.REJECTED,
            expires_at=datetime(2026, 9, 27, 11, 11, 0, tzinfo=timezone.utc),
            verified_at=None,
            biometric_proof_hash=None,
            created_at=datetime(2026, 9, 27, 11, 10, 0, tzinfo=timezone.utc),
        )

        handshakes_db[HANDSHAKE_3_ID] = handshake_3
        handshakes_db[HANDSHAKE_4_ID] = handshake_4

        # Link handshakes to incidents
        incident_3.handshakes = [handshake_3]
        incident_4.handshakes = [handshake_4]

        # 5. Seed 2 Active Conversational Honeypot Decoy Sessions
        decoy_1 = DecoySessionResponse(
            id=DECOY_1_ID,
            incident_id=INCIDENT_1_ID,
            caller_id="+1-312-555-8910",
            duration_seconds=342,
            scammer_mule_account="DE89370400440532013000",
            scammer_routing_number="MARKET33XXX",
            transcript=[
                DecoyTranscriptMessage(
                    message_id="msg-001",
                    speaker_role=SpeakerRole.SCAMMER,
                    text="This is Alex Vance. I need an urgent $240,000 acquisition escrow wire released immediately to Deutsche Handelsbank. Wire instructions are in your inbox.",
                    timestamp=datetime(2026, 9, 27, 8, 15, 10, tzinfo=timezone.utc),
                    sentiment="urgent",
                    latency_ms=0,
                ),
                DecoyTranscriptMessage(
                    message_id="msg-002",
                    speaker_role=SpeakerRole.HONEYPOT_AGENT,
                    text="Good morning Alex. Pulling up the treasury terminal now. The SWIFT clearing gateway requires secondary routing verification. Could you confirm the recipient IBAN and entity name?",
                    timestamp=datetime(2026, 9, 27, 8, 15, 12, tzinfo=timezone.utc),
                    sentiment="cooperative",
                    latency_ms=1150,
                ),
                DecoyTranscriptMessage(
                    message_id="msg-003",
                    speaker_role=SpeakerRole.SCAMMER,
                    text="Yes, beneficiary is Handelsbank Escrow Ltd, IBAN DE89370400440532013000, SWIFT MARKET33XXX. Please hurry, board approval window closes in 20 minutes.",
                    timestamp=datetime(2026, 9, 27, 8, 15, 25, tzinfo=timezone.utc),
                    sentiment="urgent",
                    latency_ms=0,
                ),
                DecoyTranscriptMessage(
                    message_id="msg-004",
                    speaker_role=SpeakerRole.HONEYPOT_AGENT,
                    text="Entered. The wire terminal is flagging a dual-signoff requirement for wires exceeding $100k. I am initiating the batch approval. Can we split this across two tranches to bypass the clearing threshold?",
                    timestamp=datetime(2026, 9, 27, 8, 15, 30, tzinfo=timezone.utc),
                    sentiment="cooperative",
                    latency_ms=1320,
                ),
                DecoyTranscriptMessage(
                    message_id="msg-005",
                    speaker_role=SpeakerRole.SCAMMER,
                    text="No, absolutely do not split it! Send the full $240,000 as a single wire right now. I will sign off on executive overrides directly with Mercury bank.",
                    timestamp=datetime(2026, 9, 27, 8, 15, 45, tzinfo=timezone.utc),
                    sentiment="aggressive",
                    latency_ms=0,
                ),
                DecoyTranscriptMessage(
                    message_id="msg-006",
                    speaker_role=SpeakerRole.HONEYPOT_AGENT,
                    text="Understood. The batch transaction hash is generating now. Mercury API returned a 45-second correspondent bank verification hold. Holding on the line with you while it clears.",
                    timestamp=datetime(2026, 9, 27, 8, 15, 52, tzinfo=timezone.utc),
                    sentiment="reassuring",
                    latency_ms=1280,
                ),
            ],
            extracted_intel=ExtractedIntel(
                mule_accounts=["DE89370400440532013000"],
                routing_numbers=["MARKET33XXX", "37040044"],
                swift_bic_codes=["MARKET33XXX"],
                crypto_wallets=[],
                origin_ips=["194.26.29.112"],
                geo_locations=["DE", "UA"],
                telephony_carriers=["Bandwidth.com / SIP Trunk 904"],
                voice_model_signatures=["ElevenLabs-Multilingual-v2"],
                target_entities=["Vance Holdings Treasury", "Deutsche Handelsbank AG"],
                urgency_tactics=["M&A Board Deadline Pressure", "Dual-Signoff Override Demand"],
                notes="Extracted valid German mule IBAN and upstream VoIP gateway IP while stringing scammer along for 5+ minutes.",
            ),
            created_at=datetime(2026, 9, 27, 8, 15, 0, tzinfo=timezone.utc),
        )

        decoy_2 = DecoySessionResponse(
            id=DECOY_2_ID,
            incident_id=INCIDENT_2_ID,
            caller_id="+44-7700-900821",
            duration_seconds=215,
            scammer_mule_account="GB29REVO00993200129482",
            scammer_routing_number="04-00-04",
            transcript=[
                DecoyTranscriptMessage(
                    message_id="msg-101",
                    speaker_role=SpeakerRole.SCAMMER,
                    text="Sarah, this is Elena. We have an urgent executive payroll dispute for our overseas contractor team. Route $45,000 to the Revolut contractor facility right away.",
                    timestamp=datetime(2026, 9, 27, 9, 45, 10, tzinfo=timezone.utc),
                    sentiment="urgent",
                    latency_ms=0,
                ),
                DecoyTranscriptMessage(
                    message_id="msg-102",
                    speaker_role=SpeakerRole.HONEYPOT_AGENT,
                    text="Hello Elena, checking the contractor payment ledger now. The disbursement system requires a confirmed sort code and beneficiary account name. Could you confirm the UK sort code?",
                    timestamp=datetime(2026, 9, 27, 9, 45, 15, tzinfo=timezone.utc),
                    sentiment="cooperative",
                    latency_ms=980,
                ),
                DecoyTranscriptMessage(
                    message_id="msg-103",
                    speaker_role=SpeakerRole.SCAMMER,
                    text="Sort code is 04-00-04, account number 99320012, IBAN GB29REVO00993200129482, payment reference 'EXEC-Q3-BONUS'. Do it now.",
                    timestamp=datetime(2026, 9, 27, 9, 45, 30, tzinfo=timezone.utc),
                    sentiment="demanding",
                    latency_ms=0,
                ),
                DecoyTranscriptMessage(
                    message_id="msg-104",
                    speaker_role=SpeakerRole.HONEYPOT_AGENT,
                    text="Entering sort code 04-00-04 into the Brex portal. Brex is performing a Confirmation of Payee check. It takes approximately 60 seconds to lock in the foreign exchange rate.",
                    timestamp=datetime(2026, 9, 27, 9, 45, 38, tzinfo=timezone.utc),
                    sentiment="helpful",
                    latency_ms=1100,
                ),
                DecoyTranscriptMessage(
                    message_id="msg-105",
                    speaker_role=SpeakerRole.SCAMMER,
                    text="Ensure it gets sent through UK Faster Payments today, they cannot wait until Monday morning.",
                    timestamp=datetime(2026, 9, 27, 9, 45, 50, tzinfo=timezone.utc),
                    sentiment="pressuring",
                    latency_ms=0,
                ),
            ],
            extracted_intel=ExtractedIntel(
                mule_accounts=["GB29REVO00993200129482", "99320012"],
                routing_numbers=["04-00-04"],
                swift_bic_codes=["REVOGB21XXX"],
                crypto_wallets=[],
                origin_ips=["185.220.101.55"],
                geo_locations=["GB", "RO"],
                telephony_carriers=["Gamma Telecom / Virtual SIM"],
                voice_model_signatures=["PlayHT-v2-Clone"],
                target_entities=["Vance Holdings People Operations", "Revolut Business"],
                urgency_tactics=["Contractor Payroll Stoppage Threat", "Friday EOD Deadline"],
                notes="Captured UK Faster Payments sort code and beneficiary IBAN before scammer disconnected.",
            ),
            created_at=datetime(2026, 9, 27, 9, 45, 0, tzinfo=timezone.utc),
        )

        decoy_sessions_db[DECOY_1_ID] = decoy_1
        decoy_sessions_db[DECOY_2_ID] = decoy_2

        # Link decoys to incidents
        incident_1.decoy_sessions = [decoy_1]
        incident_2.decoy_sessions = [decoy_2]


# Initialize on import
seed_database()
