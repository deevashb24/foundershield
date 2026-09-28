import {
  pgTable,
  pgEnum,
  uuid,
  varchar,
  boolean,
  numeric,
  integer,
  timestamp,
  jsonb,
  index,
  uniqueIndex
} from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";

/**
 * ============================================================================
 * ENUMS
 * ============================================================================
 */

export const threatSeverityEnum = pgEnum("threat_severity", [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "BENIGN"
]);

export const incidentStatusEnum = pgEnum("incident_status", [
  "INTERCEPTED",
  "CHALLENGE_PENDING",
  "VERIFIED_CLEARED",
  "FROZEN_BLOCKED",
  "HONEYPOT_ROUTED"
]);

export const channelEnum = pgEnum("channel_type", [
  "VOICE_CALL",
  "WHATSAPP_AUDIO",
  "TELEGRAM_VOICE",
  "VENDOR_EMAIL",
  "SMS"
]);

export const handshakeStatusEnum = pgEnum("handshake_status", [
  "PENDING",
  "APPROVED",
  "REJECTED",
  "EXPIRED"
]);

/**
 * ============================================================================
 * SUB-SCHEMAS / JSONB INTERFACES
 * ============================================================================
 */

export interface SpectralArtifactItem {
  type:
    | "vocoder_synthesis_artifact"
    | "phase_incoherence"
    | "unnatural_pitch_contour"
    | "spectral_loss_discontinuity"
    | "frequency_cutoff"
    | "jitter_shimmer_anomaly"
    | "neural_compression_fingerprint";
  confidence: number; // 0.00 - 100.00
  frequencyBandHz?: string; // e.g. "2000Hz - 4500Hz"
  description: string;
  timestampOffsetMs?: number;
}

export type SpectralArtifacts = SpectralArtifactItem[];

export interface DecoyTranscriptMessage {
  messageId: string;
  speakerRole: "honeypot_agent" | "scammer" | "system";
  text: string;
  timestamp: string; // ISO 8601 string
  sentiment?: "urgent" | "aggressive" | "cooperative" | "suspicious" | "neutral";
  latencyMs?: number;
}

export interface ExtractedIntel {
  muleAccounts?: string[];
  routingNumbers?: string[];
  swiftBicCodes?: string[];
  cryptoWallets?: string[];
  originIps?: string[];
  geoLocations?: string[];
  telephonyCarriers?: string[];
  voiceModelSignatures?: string[];
  targetEntities?: string[];
  urgencyTactics?: string[];
  notes?: string;
}

/**
 * ============================================================================
 * DATABASE TABLES
 * ============================================================================
 */

/**
 * Executives Table:
 * Registered corporate officers with voice biometrics and wire limits.
 */
export const executives = pgTable(
  "executives",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    name: varchar("name", { length: 255 }).notNull(),
    title: varchar("title", { length: 255 }).notNull(),
    phoneNumber: varchar("phone_number", { length: 32 }).notNull().unique(),
    email: varchar("email", { length: 255 }).notNull().unique(),
    voiceBiometricEnrolled: boolean("voice_biometric_enrolled").default(false).notNull(),
    voiceFingerprintHash: varchar("voice_fingerprint_hash", { length: 64 }), // SHA-256 hash of baseline acoustic embeddings
    wireApprovalLimitUsd: numeric("wire_approval_limit_usd", { precision: 12, scale: 2 })
      .default("5000.00")
      .notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull()
  },
  (table) => [
    uniqueIndex("executives_email_idx").on(table.email),
    uniqueIndex("executives_phone_idx").on(table.phoneNumber),
    index("executives_title_idx").on(table.title)
  ]
);

/**
 * Security Incidents Table:
 * Records of intercepted high-risk communications, audio analysis scores, and triage status.
 */
export const securityIncidents = pgTable(
  "security_incidents",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    executiveId: uuid("executive_id").references(() => executives.id, { onDelete: "set null" }),
    channel: channelEnum("channel").notNull(),
    callerSourceId: varchar("caller_source_id", { length: 128 }).notNull(), // Phone number, SIP URI, or handle
    recipientEmployee: varchar("recipient_employee", { length: 255 }).notNull(),
    requestedAmountUsd: numeric("requested_amount_usd", { precision: 12, scale: 2 }).notNull(),
    requestedRecipientBank: varchar("requested_recipient_bank", { length: 255 }).notNull(),
    requestedRecipientIban: varchar("requested_recipient_iban", { length: 64 }).notNull(),
    deepfakeConfidenceScore: numeric("deepfake_confidence_score", { precision: 5, scale: 2 }).notNull(), // 0.00 to 100.00
    spectralArtifactsDetected: jsonb("spectral_artifacts_detected")
      .$type<SpectralArtifacts>()
      .default([])
      .notNull(),
    threatSeverity: threatSeverityEnum("threat_severity").notNull(),
    status: incidentStatusEnum("status").default("INTERCEPTED").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    resolvedAt: timestamp("resolved_at", { withTimezone: true })
  },
  (table) => [
    index("incidents_executive_id_idx").on(table.executiveId),
    index("incidents_status_idx").on(table.status),
    index("incidents_severity_idx").on(table.threatSeverity),
    index("incidents_caller_source_idx").on(table.callerSourceId),
    index("incidents_created_at_idx").on(table.createdAt)
  ]
);

/**
 * Verification Handshakes Table:
 * Out-of-band cryptographically secure challenge codes sent directly to the actual executive.
 */
export const verificationHandshakes = pgTable(
  "verification_handshakes",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    incidentId: uuid("incident_id")
      .references(() => securityIncidents.id, { onDelete: "cascade" })
      .notNull(),
    executiveId: uuid("executive_id")
      .references(() => executives.id, { onDelete: "cascade" })
      .notNull(),
    challengeCode: varchar("challenge_code", { length: 6 }).notNull(), // 6-digit cryptographic challenge
    status: handshakeStatusEnum("status").default("PENDING").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    verifiedAt: timestamp("verified_at", { withTimezone: true }),
    biometricProofHash: varchar("biometric_proof_hash", { length: 64 }), // Optional SHA-256 of verified out-of-band audio proof
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull()
  },
  (table) => [
    index("handshakes_incident_id_idx").on(table.incidentId),
    index("handshakes_executive_id_idx").on(table.executiveId),
    index("handshakes_challenge_code_idx").on(table.challengeCode),
    index("handshakes_status_idx").on(table.status)
  ]
);

/**
 * Decoy Sessions Table:
 * Autonomous LLM honeypot agent sessions engaging deepfake scammers to collect mule intelligence.
 */
export const decoySessions = pgTable(
  "decoy_sessions",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    incidentId: uuid("incident_id")
      .references(() => securityIncidents.id, { onDelete: "cascade" })
      .notNull(),
    callerId: varchar("caller_id", { length: 128 }).notNull(),
    durationSeconds: integer("duration_seconds").default(0).notNull(),
    scammerMuleAccount: varchar("scammer_mule_account", { length: 100 }),
    scammerRoutingNumber: varchar("scammer_routing_number", { length: 100 }),
    transcript: jsonb("transcript")
      .$type<DecoyTranscriptMessage[]>()
      .default([])
      .notNull(),
    extractedIntel: jsonb("extracted_intel")
      .$type<ExtractedIntel>()
      .default({})
      .notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull()
  },
  (table) => [
    index("decoy_sessions_incident_id_idx").on(table.incidentId),
    index("decoy_sessions_caller_id_idx").on(table.callerId),
    index("decoy_sessions_created_at_idx").on(table.createdAt)
  ]
);

/**
 * Policy Rules Table:
 * Enterprise security guardrails controlling wire limits, biometric enforcement, and automated actions.
 */
export const policyRules = pgTable(
  "policy_rules",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    policyName: varchar("policy_name", { length: 128 }).default("Default Global Policy").notNull(),
    maxUnverifiedWireUsd: numeric("max_unverified_wire_usd", { precision: 12, scale: 2 })
      .default("1000.00")
      .notNull(),
    requireBiometricOverUsd: numeric("require_biometric_over_usd", { precision: 12, scale: 2 })
      .default("25000.00")
      .notNull(),
    autoHoneypotOnDeepfakeConfidence: numeric("auto_honeypot_on_deepfake_confidence", {
      precision: 5,
      scale: 2
    })
      .default("85.00")
      .notNull(),
    emergencyBankKillswitchEnabled: boolean("emergency_bank_killswitch_enabled")
      .default(false)
      .notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull()
  },
  (table) => [
    index("policy_rules_killswitch_idx").on(table.emergencyBankKillswitchEnabled)
  ]
);

/**
 * ============================================================================
 * RELATIONS DEFINITIONS
 * ============================================================================
 */

export const executivesRelations = relations(executives, ({ many }) => ({
  securityIncidents: many(securityIncidents),
  verificationHandshakes: many(verificationHandshakes)
}));

export const securityIncidentsRelations = relations(securityIncidents, ({ one, many }) => ({
  executive: one(executives, {
    fields: [securityIncidents.executiveId],
    references: [executives.id]
  }),
  verificationHandshakes: many(verificationHandshakes),
  decoySessions: many(decoySessions)
}));

export const verificationHandshakesRelations = relations(verificationHandshakes, ({ one }) => ({
  incident: one(securityIncidents, {
    fields: [verificationHandshakes.incidentId],
    references: [securityIncidents.id]
  }),
  executive: one(executives, {
    fields: [verificationHandshakes.executiveId],
    references: [executives.id]
  })
}));

export const decoySessionsRelations = relations(decoySessions, ({ one }) => ({
  incident: one(securityIncidents, {
    fields: [decoySessions.incidentId],
    references: [securityIncidents.id]
  })
}));
