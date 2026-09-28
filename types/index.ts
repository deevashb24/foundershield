import type { InferSelectModel, InferInsertModel } from "drizzle-orm";
import type {
  executives,
  securityIncidents,
  verificationHandshakes,
  decoySessions,
  policyRules,
  SpectralArtifactItem,
  SpectralArtifacts,
  DecoyTranscriptMessage,
  ExtractedIntel
} from "../db/schema.js";

// Re-export core JSONB structures from schema
export type {
  SpectralArtifactItem,
  SpectralArtifacts,
  DecoyTranscriptMessage,
  ExtractedIntel
};

/**
 * ============================================================================
 * CORE ENUMS & CONSTANTS
 * ============================================================================
 */

export const ThreatSeverities = {
  CRITICAL: "CRITICAL",
  HIGH: "HIGH",
  MEDIUM: "MEDIUM",
  LOW: "LOW",
  BENIGN: "BENIGN"
} as const;
export type ThreatSeverity = (typeof ThreatSeverities)[keyof typeof ThreatSeverities];

export const IncidentStatuses = {
  INTERCEPTED: "INTERCEPTED",
  CHALLENGE_PENDING: "CHALLENGE_PENDING",
  VERIFIED_CLEARED: "VERIFIED_CLEARED",
  FROZEN_BLOCKED: "FROZEN_BLOCKED",
  HONEYPOT_ROUTED: "HONEYPOT_ROUTED"
} as const;
export type IncidentStatus = (typeof IncidentStatuses)[keyof typeof IncidentStatuses];

export const Channels = {
  VOICE_CALL: "VOICE_CALL",
  WHATSAPP_AUDIO: "WHATSAPP_AUDIO",
  TELEGRAM_VOICE: "TELEGRAM_VOICE",
  VENDOR_EMAIL: "VENDOR_EMAIL",
  SMS: "SMS"
} as const;
export type Channel = (typeof Channels)[keyof typeof Channels];

export const HandshakeStatuses = {
  PENDING: "PENDING",
  APPROVED: "APPROVED",
  REJECTED: "REJECTED",
  EXPIRED: "EXPIRED"
} as const;
export type HandshakeStatus = (typeof HandshakeStatuses)[keyof typeof HandshakeStatuses];

export const AudioFormats = {
  WAV: "wav",
  MP3: "mp3",
  OGG: "ogg",
  FLAC: "flac",
  PCM: "pcm"
} as const;
export type AudioFormat = (typeof AudioFormats)[keyof typeof AudioFormats];

export const MitigationActions = {
  ALLOW_CLEAR: "ALLOW_CLEAR",
  CHALLENGE_HANDSHAKE: "CHALLENGE_HANDSHAKE",
  FREEZE_KILLSWITCH: "FREEZE_KILLSWITCH",
  ROUTE_HONEYPOT: "ROUTE_HONEYPOT"
} as const;
export type MitigationAction = (typeof MitigationActions)[keyof typeof MitigationActions];

export const SpeakerRoles = {
  HONEYPOT_AGENT: "honeypot_agent",
  SCAMMER: "scammer",
  SYSTEM: "system"
} as const;
export type SpeakerRole = (typeof SpeakerRoles)[keyof typeof SpeakerRoles];

/**
 * ============================================================================
 * DRIZZLE ORM INFERRED DATABASE MODELS
 * ============================================================================
 */

export type Executive = InferSelectModel<typeof executives>;
export type NewExecutive = InferInsertModel<typeof executives>;

export type SecurityIncident = InferSelectModel<typeof securityIncidents>;
export type NewSecurityIncident = InferInsertModel<typeof securityIncidents>;

export type VerificationHandshake = InferSelectModel<typeof verificationHandshakes>;
export type NewVerificationHandshake = InferInsertModel<typeof verificationHandshakes>;

export type DecoySession = InferSelectModel<typeof decoySessions>;
export type NewDecoySession = InferInsertModel<typeof decoySessions>;

export type PolicyRule = InferSelectModel<typeof policyRules>;
export type NewPolicyRule = InferInsertModel<typeof policyRules>;

/**
 * ============================================================================
 * DATA TRANSFER OBJECTS (DTOs)
 * ============================================================================
 */

export interface ExecutiveDTO {
  id: string;
  name: string;
  title: string;
  phoneNumber: string;
  email: string;
  voiceBiometricEnrolled: boolean;
  voiceFingerprintHash?: string | null;
  wireApprovalLimitUsd: number;
  createdAt: string;
  updatedAt: string;
}

export interface VerificationHandshakeDTO {
  id: string;
  incidentId: string;
  executiveId: string;
  challengeCode: string;
  status: HandshakeStatus;
  expiresAt: string;
  verifiedAt?: string | null;
  biometricProofHash?: string | null;
  createdAt: string;
}

export interface DecoySessionDTO {
  id: string;
  incidentId: string;
  callerId: string;
  durationSeconds: number;
  scammerMuleAccount?: string | null;
  scammerRoutingNumber?: string | null;
  transcript: DecoyTranscriptMessage[];
  extractedIntel: ExtractedIntel;
  createdAt: string;
}

export interface PolicyRuleDTO {
  id: string;
  policyName: string;
  maxUnverifiedWireUsd: number;
  requireBiometricOverUsd: number;
  autoHoneypotOnDeepfakeConfidence: number;
  emergencyBankKillswitchEnabled: boolean;
  createdAt: string;
  updatedAt: string;
}

/**
 * ============================================================================
 * API REQUEST & RESPONSE INTERFACES
 * ============================================================================
 */

/**
 * AudioAnalyzeRequest:
 * Payload sent to inspect incoming executive calls or audio messages in real-time.
 */
export interface AudioAnalyzeRequest {
  callerSourceId: string;
  claimedExecutiveId?: string;
  recipientEmployee: string;
  channel: Channel;
  audioPayloadBase64?: string;
  audioStreamUrl?: string;
  audioFormat: AudioFormat;
  sampleRateHz?: number;
  durationSeconds?: number;
  requestedAmountUsd: number;
  requestedRecipientBank: string;
  requestedRecipientIban: string;
  metadata?: Record<string, unknown>;
}

/**
 * AudioAnalyzeResponse:
 * Result of deepfake detection pipeline, spectral analysis, and automated triage.
 */
export interface AudioAnalyzeResponse {
  incidentId: string;
  threatSeverity: ThreatSeverity;
  incidentStatus: IncidentStatus;
  deepfakeConfidenceScore: number; // 0.00 to 100.00
  voiceBiometricMatchScore?: number; // 0.00 to 100.00
  voiceBiometricVerified: boolean;
  spectralArtifacts: SpectralArtifactItem[];
  actionRecommended: MitigationAction;
  handshakeDetails?: VerificationHandshakeDTO;
  decoySessionId?: string;
  killswitchTriggered: boolean;
  executionTimeMs: number;
  timestamp: string;
}

/**
 * HandshakeVerifyRequest:
 * Cryptographic challenge verification submitted by the executive.
 */
export interface HandshakeVerifyRequest {
  handshakeId: string;
  challengeCode: string;
  executiveId: string;
  biometricVoiceSampleBase64?: string;
  biometricProofHash?: string;
}

/**
 * HandshakeVerifyResponse:
 * Confirmation of identity and wire approval clearance.
 */
export interface HandshakeVerifyResponse {
  handshakeId: string;
  incidentId: string;
  status: HandshakeStatus;
  isVerified: boolean;
  message: string;
  verifiedAt?: string;
  unlockedApprovalLimitUsd?: number;
}

/**
 * DecoyTranscriptEvent:
 * Streaming event representing an utterance exchanged in a decoy honeypot session.
 */
export interface DecoyTranscriptEvent {
  sessionId: string;
  incidentId: string;
  messageId: string;
  speakerRole: SpeakerRole;
  utterance: string;
  sentiment?: "urgent" | "aggressive" | "cooperative" | "suspicious" | "neutral";
  timestamp: string;
  audioSnippetUrl?: string;
  incrementalIntel?: Partial<ExtractedIntel>;
}

/**
 * KillSwitchRequest:
 * Emergency trigger to halt all wire transactions company-wide.
 */
export interface KillSwitchRequest {
  enabled: boolean;
  reason: string;
  authorizedByUserId: string;
  emergencyCode: string;
}

/**
 * KillSwitchResponse:
 * Result of the emergency bank wire freeze activation.
 */
export interface KillSwitchResponse {
  success: boolean;
  emergencyBankKillswitchEnabled: boolean;
  triggeredAt: string;
  authorizedByUserId: string;
  affectedPendingIncidentsCount: number;
  message: string;
}

/**
 * SecurityIncidentResponse:
 * Rich incident view for the SOC security dashboard with nested relations.
 */
export interface SecurityIncidentResponse {
  id: string;
  executiveId?: string | null;
  executive?: ExecutiveDTO | null;
  channel: Channel;
  callerSourceId: string;
  recipientEmployee: string;
  requestedAmountUsd: number;
  requestedRecipientBank: string;
  requestedRecipientIban: string;
  deepfakeConfidenceScore: number;
  spectralArtifactsDetected: SpectralArtifactItem[];
  threatSeverity: ThreatSeverity;
  status: IncidentStatus;
  createdAt: string;
  resolvedAt?: string | null;
  handshakes: VerificationHandshakeDTO[];
  decoySessions: DecoySessionDTO[];
}
