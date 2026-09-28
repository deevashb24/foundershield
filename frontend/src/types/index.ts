export type ThreatSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "BENIGN";

export type IncidentStatus =
  | "INTERCEPTED"
  | "CHALLENGE_PENDING"
  | "VERIFIED_CLEARED"
  | "FROZEN_BLOCKED"
  | "HONEYPOT_ROUTED";

export type Channel =
  | "VOICE_CALL"
  | "WHATSAPP_AUDIO"
  | "TELEGRAM_VOICE"
  | "VENDOR_EMAIL"
  | "SMS";

export type HandshakeStatus = "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";

export type MitigationAction =
  | "ALLOW_CLEAR"
  | "CHALLENGE_HANDSHAKE"
  | "FREEZE_KILLSWITCH"
  | "ROUTE_HONEYPOT";

export type SpeakerRole = "honeypot_agent" | "scammer" | "system";

export interface SpectralArtifactItem {
  type: string;
  confidence: number;
  frequencyBandHz?: string;
  frequency_band_hz?: string;
  description: string;
  timestampOffsetMs?: number;
  timestamp_offset_ms?: number;
}

export interface DecoyTranscriptMessage {
  messageId?: string;
  message_id?: string;
  speakerRole?: SpeakerRole;
  speaker_role?: SpeakerRole;
  text: string;
  timestamp: string;
  sentiment?: "urgent" | "aggressive" | "cooperative" | "suspicious" | "neutral" | "reassuring";
  latencyMs?: number;
  latency_ms?: number;
}

export interface ExtractedIntel {
  muleAccounts?: string[];
  mule_accounts?: string[];
  routingNumbers?: string[];
  routing_numbers?: string[];
  swiftBicCodes?: string[];
  swift_bic_codes?: string[];
  cryptoWallets?: string[];
  crypto_wallets?: string[];
  originIps?: string[];
  origin_ips?: string[];
  geoLocations?: string[];
  geo_locations?: string[];
  telephonyCarriers?: string[];
  telephony_carriers?: string[];
  voiceModelSignatures?: string[];
  voice_model_signatures?: string[];
  targetEntities?: string[];
  target_entities?: string[];
  urgencyTactics?: string[];
  urgency_tactics?: string[];
  notes?: string;
}

export interface ExecutiveDTO {
  id: string;
  name: string;
  title: string;
  phoneNumber?: string;
  phone_number?: string;
  email: string;
  voiceBiometricEnrolled?: boolean;
  voice_biometric_enrolled?: boolean;
  voiceFingerprintHash?: string | null;
  voice_fingerprint_hash?: string | null;
  wireApprovalLimitUsd?: number;
  wire_approval_limit_usd?: number;
  createdAt?: string;
  created_at?: string;
  updatedAt?: string;
  updated_at?: string;
}

export interface VerificationHandshakeDTO {
  id: string;
  incidentId?: string;
  incident_id?: string;
  executiveId?: string;
  executive_id?: string;
  challengeCode?: string;
  challenge_code?: string;
  status: HandshakeStatus;
  expiresAt?: string;
  expires_at?: string;
  verifiedAt?: string | null;
  verified_at?: string | null;
  biometricProofHash?: string | null;
  biometric_proof_hash?: string | null;
  createdAt?: string;
  created_at?: string;
}

export interface DecoySessionDTO {
  id: string;
  incidentId?: string;
  incident_id?: string;
  callerId?: string;
  caller_id?: string;
  durationSeconds?: number;
  duration_seconds?: number;
  scammerMuleAccount?: string | null;
  scammer_mule_account?: string | null;
  scammerRoutingNumber?: string | null;
  scammer_routing_number?: string | null;
  transcript: DecoyTranscriptMessage[];
  extractedIntel: ExtractedIntel;
  extracted_intel?: ExtractedIntel;
  createdAt?: string;
  created_at?: string;
}

export interface SecurityIncidentResponse {
  id: string;
  executiveId?: string | null;
  executive_id?: string | null;
  executive?: ExecutiveDTO | null;
  channel: Channel;
  callerSourceId?: string;
  caller_source_id?: string;
  recipientEmployee?: string;
  recipient_employee?: string;
  requestedAmountUsd?: number;
  requested_amount_usd?: number;
  requestedRecipientBank?: string;
  requested_recipient_bank?: string;
  requestedRecipientIban?: string;
  requested_recipient_iban?: string;
  deepfakeConfidenceScore?: number;
  deepfake_confidence_score?: number;
  spectralArtifactsDetected?: SpectralArtifactItem[];
  spectral_artifacts_detected?: SpectralArtifactItem[];
  threatSeverity: ThreatSeverity;
  threat_severity?: ThreatSeverity;
  status: IncidentStatus;
  createdAt?: string;
  created_at?: string;
  resolvedAt?: string | null;
  resolved_at?: string | null;
  handshakes?: VerificationHandshakeDTO[];
  decoySessions?: DecoySessionDTO[];
  decoy_sessions?: DecoySessionDTO[];
}

export interface ThreatMetricsResponse {
  total_intercepted_wire_usd: number;
  deepfake_catch_rate_percent: number;
  active_honeypots: number;
  average_challenge_latency_ms: number;
  total_incidents: number;
  frozen_incidents_count: number;
  honeypot_routed_count: number;
  challenge_pending_count: number;
  verified_cleared_count: number;
  active_executive_profiles: number;
  emergency_killswitch_active: boolean;
}

export interface HealthResponse {
  status: string;
  shield_status: string;
  active_executive_profiles: number;
  intercepted_wire_dollars: number;
  honeypot_count: number;
  killswitch_engaged: boolean;
  timestamp: string;
}

export interface AudioAnalyzeRequest {
  caller_source_id: string;
  claimed_executive_id?: string | null;
  recipient_employee: string;
  channel?: Channel;
  audio_payload_base64?: string | null;
  audio_stream_url?: string | null;
  audio_format?: string;
  sample_rate_hz?: number;
  duration_seconds?: number;
  requested_amount_usd: number | string;
  requested_recipient_bank: string;
  requested_recipient_iban: string;
  metadata?: Record<string, any>;
}

export interface AudioAnalyzeResponse {
  incident_id: string;
  threat_severity: ThreatSeverity;
  incident_status: IncidentStatus;
  deepfake_confidence_score: number;
  voice_biometric_match_score?: number | null;
  voice_biometric_verified: boolean;
  spectral_artifacts: SpectralArtifactItem[];
  action_recommended: MitigationAction;
  handshake_challenge?: VerificationHandshakeDTO | null;
  decoy_session_id?: string | null;
  killswitch_triggered: boolean;
  execution_time_ms: number;
  timestamp: string;
}

export interface VerifyHandshakeInput {
  handshake_id: string;
  challenge_code: string;
  executive_id?: string | null;
  biometric_voice_sample_base64?: string | null;
  biometric_proof_hash?: string | null;
}

export interface HandshakeVerifyResponse {
  handshake_id: string;
  incident_id: string;
  status: HandshakeStatus;
  is_verified: boolean;
  message: string;
  verified_at?: string | null;
  unlocked_approval_limit_usd?: number | null;
}

export interface KillSwitchRequest {
  enabled: boolean;
  reason: string;
  authorized_by_user_id: string;
  emergency_code: string;
}

export interface KillSwitchResponse {
  success: boolean;
  emergency_bank_killswitch_enabled: boolean;
  triggered_at: string;
  authorized_by_user_id: string;
  affected_pending_incidents_count: number;
  message: string;
}

export interface DecoyMessageRequest {
  message?: string;
  utterance?: string;
  text?: string;
  speaker_role?: SpeakerRole;
  sentiment?: string;
}

export interface DecoyMessageResponse extends DecoySessionDTO {
  agent_response: string;
}

export interface ExecutiveCreate {
  name: string;
  title: string;
  phone_number: string;
  email: string;
  voice_biometric_enrolled: boolean;
  voice_fingerprint_hash?: string | null;
  wire_approval_limit_usd: number;
}

