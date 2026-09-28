"""
FounderShield AI - Comprehensive Unit & Integration Test Suite
Testing:
1. Audio Deepfake & Spectral Forensics Analysis
2. Out-of-band Challenge-Response Verification
3. Banking Emergency Killswitch
4. Conversational Honeypot & Mule Extraction
5. Executive Enrolment & Risk Limits
6. Incident Dossiers & Threat Metrics
7. Policy Administration & Validation Rules
"""

from __future__ import annotations

import base64
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

# Ensure project root is in sys.path
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from backend.main import app
from backend.store import (
    CEO_VANCE_ID,
    CFO_ROSTOVA_ID,
    DECOY_1_ID,
    DECOY_2_ID,
    INCIDENT_1_ID,
    INCIDENT_3_ID,
    handshakes_db,
    seed_database,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_db_state():
    """Reset database to initial realistic seed state before each test."""
    seed_database()
    yield


# ============================================================================
# 1. HEALTH & METRICS TESTS
# ============================================================================

def test_health_endpoint():
    """Validates health check returns shield status, executive count, intercepted dollars, and honeypot count."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "HEALTHY"
    assert data["shield_status"] == "ACTIVE"
    assert data["active_executive_profiles"] == 2
    assert float(data["intercepted_wire_dollars"]) >= 312700.00
    assert data["honeypot_count"] == 2
    assert data["killswitch_engaged"] is False


def test_metrics_endpoint():
    """Validates threat metrics endpoint."""
    response = client.get("/api/v1/metrics")
    assert response.status_code == 200
    data = response.json()

    assert float(data["total_intercepted_wire_usd"]) >= 312700.00
    assert data["deepfake_catch_rate_percent"] >= 90.0
    assert data["active_honeypots"] == 2
    assert data["average_challenge_latency_ms"] > 0
    assert data["total_incidents"] == 4
    assert data["active_executive_profiles"] == 2
    assert data["emergency_killswitch_active"] is False


# ============================================================================
# 2. AUDIO DEEPFAKE ANALYSIS TESTS
# ============================================================================

def test_audio_analysis_high_risk_triggers_challenge():
    """
    Submitting audio demanding $15,000 (exceeding CEO Vance's $10k limit)
    with synthetic audio payload triggers CHALLENGE_PENDING and generates 6-digit challenge code.
    """
    payload = {
        "caller_source_id": "+1-415-555-0199",
        "claimed_executive_id": str(CEO_VANCE_ID),
        "recipient_employee": "Marcus Brody (Treasury Manager)",
        "channel": "VOICE_CALL",
        "audio_payload_base64": base64.b64encode(b"RIFF_FAKE_AUDIO_SAMPLE_DATA_STREAM").decode("utf-8"),
        "requested_amount_usd": "15000.00",
        "requested_recipient_bank": "Deutsche Handelsbank AG",
        "requested_recipient_iban": "DE89370400440532013000",
        "metadata": {"force_confidence": 78.5},
    }

    response = client.post("/api/v1/audio/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["incident_id"] is not None
    assert float(data["deepfake_confidence_score"]) == 78.5
    assert data["incident_status"] == "CHALLENGE_PENDING"
    assert data["action_recommended"] == "CHALLENGE_HANDSHAKE"

    # Spectral artifacts detected
    artifacts = data["spectral_artifacts"]
    artifact_types = [a["type"] for a in artifacts]
    assert "neural_vocoder_footprint" in artifact_types
    assert "phase_discontinuity" in artifact_types
    assert "robotic_pitch_jitter" in artifact_types

    # Cryptographic challenge generated with 6-digit code
    handshake = data["handshake_challenge"]
    assert handshake is not None
    assert len(handshake["challenge_code"]) == 6
    assert handshake["challenge_code"].isalnum()
    assert handshake["status"] == "PENDING"


def test_audio_analysis_critical_auto_honeypot_routing():
    """
    Submitting audio with deepfake score >= 85% routes to autonomous honeypot.
    """
    payload = {
        "caller_source_id": "+1-312-555-8910",
        "claimed_executive_id": str(CEO_VANCE_ID),
        "recipient_employee": "Marcus Brody",
        "channel": "VOICE_CALL",
        "audio_payload_base64": base64.b64encode(b"CRITICAL_SYNTHESIS_STREAM").decode("utf-8"),
        "requested_amount_usd": "180000.00",
        "requested_recipient_bank": "Barclays International",
        "requested_recipient_iban": "GB29REVO00993200129482",
        "metadata": {"force_confidence": 94.2},
    }

    response = client.post("/api/v1/audio/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["incident_status"] == "HONEYPOT_ROUTED"
    assert data["action_recommended"] == "ROUTE_HONEYPOT"
    assert data["threat_severity"] == "CRITICAL"
    assert data["decoy_session_id"] is not None


def test_audio_analysis_legitimate_audio_clears():
    """Authentic audio under wire limit is cleared without challenge."""
    payload = {
        "caller_source_id": "+1-415-555-0199",
        "claimed_executive_id": str(CEO_VANCE_ID),
        "recipient_employee": "Office Admin",
        "channel": "VOICE_CALL",
        "audio_payload_base64": base64.b64encode(b"AUTHENTIC_AUDIO_SAMPLE").decode("utf-8"),
        "requested_amount_usd": "500.00",
        "requested_recipient_bank": "Chase JPMorgan",
        "requested_recipient_iban": "US33CHAS02100002198765",
        "metadata": {"is_authentic": True},
    }

    response = client.post("/api/v1/audio/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert float(data["deepfake_confidence_score"]) < 10.0
    assert data["incident_status"] == "VERIFIED_CLEARED"
    assert data["action_recommended"] == "ALLOW_CLEAR"
    assert data["voice_biometric_verified"] is True
    assert data["handshake_challenge"] is None


def test_audio_analysis_stream_url():
    """Validates analyze endpoint works with audio_stream_url."""
    payload = {
        "caller_source_id": "+1-312-555-8910",
        "claimed_executive_id": str(CEO_VANCE_ID),
        "recipient_employee": "Marcus Brody",
        "channel": "VOICE_CALL",
        "audio_stream_url": "https://s3.amazonaws.com/foundershield-audio/samples/sample-001.wav",
        "requested_amount_usd": "60000.00",
        "requested_recipient_bank": "Deutsche Handelsbank AG",
        "requested_recipient_iban": "DE89370400440532013000",
    }

    response = client.post("/api/v1/audio/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["incident_id"] is not None
    assert len(data["spectral_artifacts"]) >= 3


# ============================================================================
# 3. HANDSHAKE CHALLENGE VERIFICATION TESTS
# ============================================================================

def test_handshake_verify_successful():
    """Correct challenge code verifies handshake and marks incident VERIFIED_CLEARED."""
    handshake = next(h for h in handshakes_db.values() if h.status == "PENDING")

    verify_payload = {
        "handshake_id": str(handshake.id),
        "challenge_code": handshake.challenge_code,
        "executive_id": str(handshake.executive_id),
    }

    response = client.post("/api/v1/handshake/verify", json=verify_payload)
    assert response.status_code == 200
    data = response.json()

    assert data["is_verified"] is True
    assert data["status"] == "APPROVED"
    assert data["verified_at"] is not None

    # Check incident status updated
    inc_res = client.get(f"/api/v1/incidents/{handshake.incident_id}")
    assert inc_res.status_code == 200
    assert inc_res.json()["status"] == "VERIFIED_CLEARED"


def test_handshake_verify_invalid_code_freezes():
    """Incorrect challenge code rejects handshake and marks incident FROZEN_BLOCKED."""
    handshake = next(h for h in handshakes_db.values() if h.status == "PENDING")

    verify_payload = {
        "handshake_id": str(handshake.id),
        "challenge_code": "000000",  # Deliberately wrong
    }

    response = client.post("/api/v1/handshake/verify", json=verify_payload)
    assert response.status_code == 200
    data = response.json()

    assert data["is_verified"] is False
    assert data["status"] == "REJECTED"

    # Incident flagged as frozen
    inc_res = client.get(f"/api/v1/incidents/{handshake.incident_id}")
    assert inc_res.json()["status"] == "FROZEN_BLOCKED"


def test_handshake_verify_expired():
    """Expired challenge fails verification and freezes incident."""
    handshake = next(h for h in handshakes_db.values() if h.status == "PENDING")
    # Artificially expire handshake
    handshake.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)

    verify_payload = {
        "handshake_id": str(handshake.id),
        "challenge_code": handshake.challenge_code,
    }

    response = client.post("/api/v1/handshake/verify", json=verify_payload)
    assert response.status_code == 200
    data = response.json()

    assert data["is_verified"] is False
    assert data["status"] == "EXPIRED"


def test_handshake_not_found():
    """Unknown handshake ID returns 404."""
    fake_id = uuid4()
    response = client.post(
        "/api/v1/handshake/verify",
        json={"handshake_id": str(fake_id), "challenge_code": "123456"},
    )
    assert response.status_code == 404


# ============================================================================
# 4. EMERGENCY BANKING KILLSWITCH TESTS
# ============================================================================

def test_banking_killswitch_trigger_and_disarm():
    """Killswitch trigger freezes all pending wire transfers across Mercury, Brex, Chase."""
    # 1. Engage killswitch
    payload = {
        "enabled": True,
        "reason": "Suspected nation-state voice clone attack wave on treasury team",
        "authorized_by_user_id": "CISO_SEC_OPS_01",
        "emergency_code": "KILLSWITCH_OVERRIDE_8891",
    }

    response = client.post("/api/v1/killswitch/trigger", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["success"] is True
    assert data["emergency_bank_killswitch_enabled"] is True
    assert data["affected_pending_incidents_count"] >= 1

    # Verify health status changed to lockdown
    health_res = client.get("/api/v1/health")
    assert health_res.json()["shield_status"] == "FROZEN_LOCKDOWN"
    assert health_res.json()["killswitch_engaged"] is True

    # 2. Disarm killswitch
    disarm_payload = {
        "enabled": False,
        "reason": "Threat contained by SOC. Resuming normal operations.",
        "authorized_by_user_id": "CISO_SEC_OPS_01",
        "emergency_code": "KILLSWITCH_OVERRIDE_8891",
    }
    disarm_res = client.post("/api/v1/killswitch/trigger", json=disarm_payload)
    assert disarm_res.status_code == 200
    assert disarm_res.json()["emergency_bank_killswitch_enabled"] is False

    health_res2 = client.get("/api/v1/health")
    assert health_res2.json()["shield_status"] == "ACTIVE"


# ============================================================================
# 5. CONVERSATIONAL HONEYPOT INTERACTION TESTS
# ============================================================================

def test_honeypot_interaction_extracts_mule_intel():
    """
    Simulates Apate AI decoy stringing along scammer to extract mule accounts and routing numbers.
    """
    scammer_input = {
        "message": "Send the funds right away to routing code 021000021 and IBAN US33CHAS02100002198765, account 928371928491!",
        "speaker_role": "scammer",
        "sentiment": "urgent",
    }

    response = client.post(f"/api/v1/decoys/{DECOY_1_ID}/message", json=scammer_input)
    assert response.status_code == 200
    data = response.json()

    assert data["agent_response"] is not None
    assert len(data["agent_response"]) > 20

    # Mule extraction checks
    intel = data["extracted_intel"]
    assert "US33CHAS02100002198765" in intel["mule_accounts"]
    assert "021000021" in intel["routing_numbers"]

    # Verify transcript grew by 2 (scammer msg + honeypot response)
    transcript = data["transcript"]
    assert transcript[-2]["speaker_role"] == "scammer"
    assert transcript[-1]["speaker_role"] == "honeypot_agent"
    assert data["duration_seconds"] > 342


def test_list_and_get_decoys():
    """Tests listing all decoy sessions and getting individual decoy."""
    list_res = client.get("/api/v1/decoys")
    assert list_res.status_code == 200
    decoys = list_res.json()
    assert len(decoys) == 2

    # Get single decoy
    one_res = client.get(f"/api/v1/decoys/{DECOY_2_ID}")
    assert one_res.status_code == 200
    assert one_res.json()["caller_id"] == "+44-7700-900821"


# ============================================================================
# 6. EXECUTIVE MANAGEMENT TESTS
# ============================================================================

def test_list_and_create_executives():
    """Tests listing enrolled executives and enrolling a new executive profile."""
    # List initial executives
    get_res = client.get("/api/v1/executives")
    assert get_res.status_code == 200
    execs = get_res.json()
    assert len(execs) == 2
    names = [e["name"] for e in execs]
    assert "Alexander Vance" in names
    assert "Elena Rostova" in names

    # Enroll a new executive
    new_exec = {
        "name": "David Stirling",
        "title": "VP Engineering",
        "phone_number": "+1-415-555-0812",
        "email": "david.stirling@vanceholdings.com",
        "voice_biometric_enrolled": True,
        "voice_fingerprint_hash": "e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2",
        "wire_approval_limit_usd": "50000.00",
    }
    create_res = client.post("/api/v1/executives", json=new_exec)
    assert create_res.status_code == 201
    created_data = create_res.json()
    assert created_data["name"] == "David Stirling"
    assert float(created_data["wire_approval_limit_usd"]) == 50000.00

    # Ensure list now has 3
    get_res2 = client.get("/api/v1/executives")
    assert len(get_res2.json()) == 3


def test_duplicate_executive_rejected():
    """Attempting to enroll executive with duplicate email or phone returns 400."""
    dup_exec = {
        "name": "Alex Impersonator",
        "title": "Advisor",
        "phone_number": "+1-415-555-0199",  # Same as Alexander Vance
        "email": "alex.new@vanceholdings.com",
        "wire_approval_limit_usd": "1000.00",
    }
    res = client.post("/api/v1/executives", json=dup_exec)
    assert res.status_code == 400


# ============================================================================
# 7. INCIDENTS DOSSIER AND FILTERING TESTS
# ============================================================================

def test_list_and_filter_incidents():
    """Tests listing incidents and filtering by status and severity."""
    # All incidents
    all_res = client.get("/api/v1/incidents")
    assert all_res.status_code == 200
    assert len(all_res.json()) >= 4

    # Filter by HONEYPOT_ROUTED
    honeypot_res = client.get("/api/v1/incidents?status=HONEYPOT_ROUTED")
    assert honeypot_res.status_code == 200
    for inc in honeypot_res.json():
        assert inc["status"] == "HONEYPOT_ROUTED"

    # Filter by CRITICAL severity
    crit_res = client.get("/api/v1/incidents?severity=CRITICAL")
    assert crit_res.status_code == 200
    for inc in crit_res.json():
        assert inc["threat_severity"] == "CRITICAL"


def test_get_incident_dossier():
    """Tests retrieving full incident dossier including executive and decoy sessions."""
    res = client.get(f"/api/v1/incidents/{INCIDENT_1_ID}")
    assert res.status_code == 200
    data = res.json()

    assert data["id"] == str(INCIDENT_1_ID)
    assert float(data["requested_amount_usd"]) == 240000.00
    assert data["executive"]["name"] == "Alexander Vance"
    assert len(data["decoy_sessions"]) >= 1
    assert len(data["spectral_artifacts_detected"]) >= 3


def test_incident_not_found():
    """Retrieving non-existent incident returns 404."""
    res = client.get(f"/api/v1/incidents/{uuid4()}")
    assert res.status_code == 404


# ============================================================================
# 8. POLICY ADMINISTRATION TESTS
# ============================================================================

def test_get_and_update_policy():
    """Tests reading and updating security policy."""
    get_res = client.get("/api/v1/policy")
    assert get_res.status_code == 200
    policy = get_res.json()
    assert float(policy["max_unverified_wire_usd"]) == 1000.00

    patch_res = client.patch(
        "/api/v1/policy",
        json={"max_unverified_wire_usd": "2500.00"},
    )
    assert patch_res.status_code == 200
    assert float(patch_res.json()["max_unverified_wire_usd"]) == 2500.00
