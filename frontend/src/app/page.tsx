"use client";

import React, { useState, useEffect, useCallback } from "react";
import Header from "@/components/Header";
import ThreatMetricsOverview from "@/components/ThreatMetricsOverview";
import LiveIncidentRadar from "@/components/LiveIncidentRadar";
import AudioSpectrogramViewer from "@/components/AudioSpectrogramViewer";
import BiometricChallengeConsole from "@/components/BiometricChallengeConsole";
import HoneypotDecoyConsole from "@/components/HoneypotDecoyConsole";
import ExecutiveRegistryTable, { EnrollExecutiveFormData } from "@/components/ExecutiveRegistryTable";
import {
  fetchHealth,
  fetchMetrics,
  fetchIncidents,
  fetchIncident,
  fetchDecoys,
  fetchExecutives,
  analyzeAudio,
  verifyHandshake,
  triggerKillswitch,
  sendDecoyMessage,
  enrollExecutive,
} from "@/lib/api";
import {
  mockIncidents,
  mockMetrics,
  mockExecutives,
  mockDecoys,
  mockHandshakes,
} from "@/lib/mockData";
import {
  SecurityIncidentResponse,
  DecoySessionDTO,
  VerificationHandshakeDTO,
  ThreatMetricsResponse,
  ExecutiveDTO,
  HealthResponse,
} from "@/types";
import { cn } from "@/lib/utils";
import { AlertCircle, CheckCircle, Info, X } from "lucide-react";

export default function SOCDashboardPage() {
  // Main data state
  const [incidents, setIncidents] = useState<SecurityIncidentResponse[]>(mockIncidents);
  const [metrics, setMetrics] = useState<ThreatMetricsResponse>(mockMetrics);
  const [executives, setExecutives] = useState<ExecutiveDTO[]>(mockExecutives);
  const [decoys, setDecoys] = useState<DecoySessionDTO[]>(mockDecoys);
  const [health, setHealth] = useState<HealthResponse | null>(null);

  // Active selections and view toggles
  const [selectedIncident, setSelectedIncident] = useState<SecurityIncidentResponse>(mockIncidents[0]);
  const [activeConsoleTab, setActiveConsoleTab] = useState<"DECOY_HONEYPOT" | "BIOMETRIC_CHALLENGE">("DECOY_HONEYPOT");
  const [killswitchActive, setKillswitchActive] = useState<boolean>(false);

  // Async loading indicators
  const [isSimulatingAudio, setIsSimulatingAudio] = useState<boolean>(false);
  const [isVerifyingOtp, setIsVerifyingOtp] = useState<boolean>(false);
  const [isSendingDecoyMessage, setIsSendingDecoyMessage] = useState<boolean>(false);
  const [isEnrollingExecutive, setIsEnrollingExecutive] = useState<boolean>(false);

  // Toast / Tactical Notice
  const [operatorNotice, setOperatorNotice] = useState<{
    message: string;
    type: "success" | "warning" | "danger" | "info";
  } | null>(null);

  const showNotice = (message: string, type: "success" | "warning" | "danger" | "info" = "info") => {
    setOperatorNotice({ message, type });
    setTimeout(() => {
      setOperatorNotice((prev) => (prev?.message === message ? null : prev));
    }, 6000);
  };

  // Derive active decoy session and handshake
  const activeDecoySession: DecoySessionDTO =
    (selectedIncident?.decoySessions && selectedIncident.decoySessions[0]) ||
    (selectedIncident?.decoy_sessions && selectedIncident.decoy_sessions[0]) ||
    decoys.find((d) => (d.incidentId || d.incident_id) === selectedIncident?.id) ||
    decoys[0] ||
    mockDecoys[0];

  const activeHandshake: VerificationHandshakeDTO =
    (selectedIncident?.handshakes && selectedIncident.handshakes[0]) ||
    mockHandshakes.find((h) => (h.incidentId || h.incident_id) === selectedIncident?.id) ||
    mockHandshakes[0];

  // 1. Core Data Synchronization Function
  const loadAllData = useCallback(async () => {
    try {
      const [healthRes, metricsRes, incidentsRes, decoysRes, execsRes] = await Promise.all([
        fetchHealth(),
        fetchMetrics(),
        fetchIncidents(),
        fetchDecoys(),
        fetchExecutives(),
      ]);

      if (healthRes) {
        setHealth(healthRes);
        setKillswitchActive(healthRes.killswitch_engaged);
      }
      if (metricsRes) {
        setMetrics(metricsRes);
      }
      if (decoysRes && decoysRes.length > 0) {
        setDecoys(decoysRes);
      }
      if (execsRes && execsRes.length > 0) {
        setExecutives(execsRes);
      }
      if (incidentsRes && incidentsRes.length > 0) {
        setIncidents(incidentsRes);
        setSelectedIncident((prev) => {
          const match = incidentsRes.find((i) => i.id === prev?.id);
          return match || incidentsRes[0];
        });
      }
    } catch (err) {
      console.error("SOC Background Sync Encountered Error:", err);
    }
  }, []);

  // 2. Poll every 8 seconds for real-time telemetry updates
  useEffect(() => {
    loadAllData();
    const interval = setInterval(loadAllData, 8000);
    return () => clearInterval(interval);
  }, [loadAllData]);

  // ============================================================================
  // EVENT-DRIVEN ACTION HANDLERS
  // ============================================================================

  // Action: Toggle Emergency Banking Killswitch
  const handleToggleKillswitch = async (active: boolean) => {
    setKillswitchActive(active);

    // Optimistic UI updates
    setMetrics((prev) => ({
      ...prev,
      emergency_killswitch_active: active,
      frozen_incidents_count: active ? prev.total_incidents : prev.frozen_incidents_count,
    }));

    if (active) {
      setIncidents((prev) =>
        prev.map((inc) => ({
          ...inc,
          status: "FROZEN_BLOCKED",
        }))
      );
      showNotice("EMERGENCY KILLSWITCH ENGAGED: Outbound wires halted across Mercury, Brex, and Chase APIs.", "danger");
    } else {
      showNotice("Killswitch Disarmed: Resuming standard zero-trust acoustic defense interception.", "info");
    }

    try {
      const res = await triggerKillswitch({
        enabled: active,
        reason: active
          ? "Operator triggered emergency banking killswitch from FounderShield command console"
          : "Operator disarmed emergency circuit breaker",
        authorized_by_user_id: "soc-lead-alpha",
        emergency_code: "KILLSWITCH_OVERRIDE_8891",
      });

      if (res?.message) {
        showNotice(res.message, active ? "danger" : "info");
      }
    } catch (err) {
      console.error("Killswitch trigger error:", err);
    } finally {
      await loadAllData();
    }
  };

  // Action: Simulate Inbound Deepfake Wire Call (POST /api/v1/audio/analyze)
  const handleSimulateInboundCall = async () => {
    setIsSimulatingAudio(true);
    const simulatedAmount = 185000.0;
    const claimedExec = executives[0] || mockExecutives[0];

    try {
      const res = await analyzeAudio({
        caller_source_id: claimedExec.phoneNumber || claimedExec.phone_number || "+1-415-555-0199",
        claimed_executive_id: claimedExec.id,
        recipient_employee: "Marcus Brody (Treasury Manager)",
        channel: "VOICE_CALL",
        requested_amount_usd: simulatedAmount,
        requested_recipient_bank: "Deutsche Handelsbank AG",
        requested_recipient_iban: "DE89370400440532013099",
        audio_payload_base64: "UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA=",
        metadata: {
          force_confidence: 98.4,
          simulated_scenario: "CEO Impersonation Foreign Acquisition Wire",
        },
      });

      if (res) {
        showNotice(
          `INBOUND DEEPFAKE INTERCEPTED: Demanded $${simulatedAmount.toLocaleString()} wire. Acoustic Confidence: ${res.deepfake_confidence_score}%. Action: ${res.action_recommended}`,
          "warning"
        );

        await loadAllData();

        // Find the newly created incident or fetch directly
        if (res.incident_id) {
          const detail = await fetchIncident(res.incident_id);
          if (detail) {
            setSelectedIncident(detail);
            if (detail.status === "CHALLENGE_PENDING") {
              setActiveConsoleTab("BIOMETRIC_CHALLENGE");
            } else {
              setActiveConsoleTab("DECOY_HONEYPOT");
            }
          }
        }
      }
    } catch (err) {
      console.error("Failed to simulate deepfake audio:", err);
      showNotice("Inbound wire simulation completed via local defensive telemetry.", "info");
      await loadAllData();
    } finally {
      setIsSimulatingAudio(false);
    }
  };

  // Action: Verify Out-of-Band Challenge Code (POST /api/v1/handshake/verify)
  const handleVerifyOtp = async (code: string) => {
    if (!activeHandshake?.id) return;
    setIsVerifyingOtp(true);

    try {
      const res = await verifyHandshake({
        handshake_id: activeHandshake.id,
        challenge_code: code,
        executive_id: selectedIncident?.executive_id || activeHandshake.executiveId,
      });

      if (res.is_verified) {
        showNotice(
          `OTP Validated: Executive biometric proof confirmed. Wire transfer CLEARED for limit $${res.unlocked_approval_limit_usd?.toLocaleString() || "25,000"}.`,
          "success"
        );
        setSelectedIncident((prev) => ({
          ...prev,
          status: "VERIFIED_CLEARED",
        }));
      } else {
        showNotice(`OTP Verification Failed: Challenge code mismatch. Incident flagged FROZEN_BLOCKED.`, "danger");
        setSelectedIncident((prev) => ({
          ...prev,
          status: "FROZEN_BLOCKED",
        }));
      }
      await loadAllData();
    } catch (err) {
      console.error("OTP verification error:", err);
    } finally {
      setIsVerifyingOtp(false);
    }
  };

  // Action: Force Approve (Override Clearance)
  const handleForceApprove = async () => {
    const validCode = activeHandshake.challengeCode || activeHandshake.challenge_code || "892415";
    await handleVerifyOtp(validCode);
  };

  // Action: Reject Challenge & Freeze Wire
  const handleRejectChallenge = async () => {
    await handleVerifyOtp("000000"); // intentional failure to lock wire
  };

  // Action: Honeypot Decoy Message Interaction (POST /api/v1/decoys/{session_id}/message)
  const handleSendDecoyMessage = async (messageText: string) => {
    if (!activeDecoySession?.id) return;
    setIsSendingDecoyMessage(true);

    try {
      const res = await sendDecoyMessage(activeDecoySession.id, {
        message: messageText,
        speaker_role: "scammer",
        sentiment: "urgent",
      });

      if (res) {
        // Update decoy in state
        setDecoys((prev) =>
          prev.map((d) => (d.id === activeDecoySession.id ? res : d))
        );

        if (res.scammer_mule_account || res.scammerMuleAccount) {
          const mule = res.scammer_mule_account || res.scammerMuleAccount;
          showNotice(`Scammer Intel Extracted: Mule Account/IBAN [${mule}] logged into threat ledger.`, "success");
        }
      }
      await loadAllData();
    } catch (err) {
      console.error("Decoy interaction error:", err);
    } finally {
      setIsSendingDecoyMessage(false);
    }
  };

  // Action: Enroll Executive Profile (POST /api/v1/executives)
  const handleEnrollExecutive = async (formData: EnrollExecutiveFormData) => {
    setIsEnrollingExecutive(true);

    try {
      const res = await enrollExecutive({
        name: formData.name,
        title: formData.title,
        phone_number: formData.phoneNumber,
        email: formData.email,
        voice_biometric_enrolled: formData.voiceBiometricEnrolled,
        voice_fingerprint_hash: formData.voiceFingerprintHash || null,
        wire_approval_limit_usd: formData.wireApprovalLimitUsd,
      });

      if (res) {
        showNotice(
          `Executive Enrolled: ${res.name} (${res.title}) added with $${Number(res.wireApprovalLimitUsd || res.wire_approval_limit_usd).toLocaleString()} limit.`,
          "success"
        );
      }
      await loadAllData();
    } catch (err) {
      console.error("Executive enrollment error:", err);
    } finally {
      setIsEnrollingExecutive(false);
    }
  };

  // Incident Navigation & Quick Status Actions
  const handleSelectIncident = async (incident: SecurityIncidentResponse) => {
    setSelectedIncident(incident);
    if (incident.status === "CHALLENGE_PENDING") {
      setActiveConsoleTab("BIOMETRIC_CHALLENGE");
    } else {
      setActiveConsoleTab("DECOY_HONEYPOT");
    }

    try {
      const detail = await fetchIncident(incident.id);
      if (detail) {
        setSelectedIncident(detail);
      }
    } catch {
      // Fallback keeps current incident
    }
  };

  const handleTriggerChallenge = (incidentId: string) => {
    setIncidents((prev) =>
      prev.map((inc) =>
        inc.id === incidentId
          ? {
              ...inc,
              status: "CHALLENGE_PENDING",
            }
          : inc
      )
    );
    setActiveConsoleTab("BIOMETRIC_CHALLENGE");
    showNotice(`Biometric OTP Handshake dispatched for Incident ${incidentId.slice(0, 8)}`, "info");
  };

  const handleDivertHoneypot = (incidentId: string) => {
    setIncidents((prev) =>
      prev.map((inc) =>
        inc.id === incidentId
          ? {
              ...inc,
              status: "HONEYPOT_ROUTED",
            }
          : inc
      )
    );
    setActiveConsoleTab("DECOY_HONEYPOT");
    showNotice(`Incident ${incidentId.slice(0, 8)} diverted to Apate AI Conversational Honeypot`, "info");
  };

  const handleFreezeIncident = (incidentId: string) => {
    setIncidents((prev) =>
      prev.map((inc) =>
        inc.id === incidentId
          ? {
              ...inc,
              status: "FROZEN_BLOCKED",
            }
          : inc
      )
    );
    showNotice(`Incident ${incidentId.slice(0, 8)} arrested: Outbound wire transfers blocked at bank API.`, "danger");
  };

  return (
    <div className="min-h-screen bg-[#07080b] flex flex-col font-sans">
      {/* 1. Command Center Header */}
      <Header
        killswitchActive={killswitchActive}
        onToggleKillswitch={handleToggleKillswitch}
        interceptedCount={metrics.total_incidents}
        systemStatusText={
          health?.shield_status === "FROZEN_LOCKDOWN"
            ? "CIRCUIT BREAKER: ALL TRANSFERS ARRESTED"
            : "FOUNDERSHIELD DEFENSE PROTOCOL ACTIVE"
        }
      />

      {/* Floating Tactical Notice Banner */}
      {operatorNotice && (
        <div
          className={cn(
            "fixed bottom-14 right-6 z-50 max-w-md p-4 rounded-xl border shadow-2xl flex items-start gap-3 animate-in fade-in slide-in-from-bottom-5 font-mono text-xs backdrop-blur-xl transition-all duration-300",
            operatorNotice.type === "danger"
              ? "bg-[#1f0f14]/95 border-[#f43f5e] text-rose-200 glow-crimson-sm"
              : operatorNotice.type === "warning"
              ? "bg-[#1f1a0f]/95 border-[#f59e0b] text-amber-200 glow-amber-sm"
              : operatorNotice.type === "success"
              ? "bg-[#0f1f18]/95 border-[#10b981] text-emerald-200 glow-emerald-sm"
              : "bg-[#0f1823]/95 border-[#06b6d4] text-cyan-200 glow-cyan-sm"
          )}
        >
          {operatorNotice.type === "danger" && <AlertCircle className="h-4 w-4 shrink-0 text-[#f43f5e] mt-0.5 animate-pulse" />}
          {operatorNotice.type === "warning" && <AlertCircle className="h-4 w-4 shrink-0 text-[#f59e0b] mt-0.5" />}
          {operatorNotice.type === "success" && <CheckCircle className="h-4 w-4 shrink-0 text-[#10b981] mt-0.5" />}
          {operatorNotice.type === "info" && <Info className="h-4 w-4 shrink-0 text-[#06b6d4] mt-0.5" />}
          <div className="flex-1 leading-relaxed">
            <span className="font-bold uppercase tracking-wider block text-[10px] text-slate-400 mb-0.5">
              SOC DEFENSIVE TELEMETRY EVENT
            </span>
            <span className="font-sans text-xs text-white">{operatorNotice.message}</span>
          </div>
          <button
            onClick={() => setOperatorNotice(null)}
            className="text-slate-400 hover:text-white cursor-pointer shrink-0 transition-colors p-0.5"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Main Command Body */}
      <main className="flex-1 max-w-[1920px] w-full mx-auto p-4 lg:p-6 space-y-5">
        {/* 2. High-Density Threat Metrics Overview Cards */}
        <section aria-label="Threat Metrics Overview">
          <ThreatMetricsOverview
            totalInterceptedUsd={metrics.total_intercepted_wire_usd}
            catchRatePercent={metrics.deepfake_catch_rate_percent}
            activeHoneypots={metrics.active_honeypots}
            avgLatencySeconds={
              metrics.average_challenge_latency_ms
                ? Number((metrics.average_challenge_latency_ms / 1000).toFixed(1))
                : 14.2
            }
            totalIncidents={metrics.total_incidents}
            frozenIncidentsCount={metrics.frozen_incidents_count}
            honeypotRoutedCount={metrics.honeypot_routed_count}
            challengePendingCount={metrics.challenge_pending_count}
            killswitchActive={killswitchActive}
          />
        </section>

        {/* 3. Primary Multi-Pane SOC Tactical Grid */}
        <section className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
          {/* Left Column (5 Cols): Live Incident Radar */}
          <div className="xl:col-span-5 h-[760px]">
            <LiveIncidentRadar
              incidents={incidents}
              selectedIncidentId={selectedIncident.id}
              onSelectIncident={handleSelectIncident}
              onTriggerChallenge={handleTriggerChallenge}
              onDivertHoneypot={handleDivertHoneypot}
              onFreezeIncident={handleFreezeIncident}
              onSimulateInboundCall={handleSimulateInboundCall}
              isSimulating={isSimulatingAudio}
            />
          </div>

          {/* Right Column (7 Cols): Forensics & Active Mitigation Consoles */}
          <div className="xl:col-span-7 space-y-5">
            {/* Top Right: Audio Spectrogram & Neural Vocoder Visualizer */}
            <div className="h-[430px]">
              <AudioSpectrogramViewer
                selectedIncident={selectedIncident}
                onAnalyzeNewAudio={handleSimulateInboundCall}
              />
            </div>

            {/* Bottom Right: Interactive Active Mitigation Tabs (Decoy Honeypot vs Biometric Challenge) */}
            <div className="rounded-lg cyber-card overflow-hidden flex flex-col min-h-[460px] shadow-2xl">
              {/* Tab Navigation Header */}
              <div className="p-2.5 bg-[#151923]/90 border-b border-[#1f2433] flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setActiveConsoleTab("DECOY_HONEYPOT")}
                    className={cn(
                      "px-3.5 py-1.5 rounded-lg text-xs font-mono font-bold tracking-wide uppercase transition-all cursor-pointer flex items-center gap-2",
                      activeConsoleTab === "DECOY_HONEYPOT"
                        ? "bg-[#8b5cf6] text-white shadow-md glow-violet-sm"
                        : "text-slate-400 hover:text-slate-200 hover:bg-[#1f2433]"
                    )}
                  >
                    <span>Apate AI Honeypot Transcript</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-black/40 text-white font-normal">
                      Mule Intel
                    </span>
                  </button>

                  <button
                    onClick={() => setActiveConsoleTab("BIOMETRIC_CHALLENGE")}
                    className={cn(
                      "px-3.5 py-1.5 rounded-lg text-xs font-mono font-bold tracking-wide uppercase transition-all cursor-pointer flex items-center gap-2",
                      activeConsoleTab === "BIOMETRIC_CHALLENGE"
                        ? "bg-[#f59e0b] text-black shadow-md glow-amber-sm"
                        : "text-slate-400 hover:text-slate-200 hover:bg-[#1f2433]"
                    )}
                  >
                    <span>Out-of-Band Biometric Challenge</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-black/25 text-black font-semibold">
                      60s OTP
                    </span>
                  </button>
                </div>

                <div className="text-[11px] font-mono text-slate-400 pr-2 hidden sm:block">
                  Targeted Incident:{" "}
                  <span className="text-white font-bold font-mono">
                    {selectedIncident.id.slice(0, 8)}...
                  </span>
                </div>
              </div>

              {/* Tab Panes */}
              <div className="flex-1 p-0">
                {activeConsoleTab === "DECOY_HONEYPOT" ? (
                  <HoneypotDecoyConsole
                    decoySession={activeDecoySession}
                    onSendMessage={handleSendDecoyMessage}
                    isSending={isSendingDecoyMessage}
                  />
                ) : (
                  <BiometricChallengeConsole
                    handshake={activeHandshake}
                    executive={
                      selectedIncident.executive ||
                      executives.find((e) => e.id === selectedIncident.executive_id) ||
                      executives[0]
                    }
                    onVerifyCode={handleVerifyOtp}
                    onForceAuthorize={handleForceApprove}
                    onRejectChallenge={handleRejectChallenge}
                    isVerifying={isVerifyingOtp}
                  />
                )}
              </div>
            </div>
          </div>
        </section>

        {/* 4. Executive Registry & Zero-Trust Wire Ceiling Table */}
        <section aria-label="Executive Registry & Biometrics">
          <ExecutiveRegistryTable
            executives={executives}
            onEnrollExecutive={handleEnrollExecutive}
            isEnrolling={isEnrollingExecutive}
          />
        </section>
      </main>

      {/* Command Center Footer Bar */}
      <footer className="w-full border-t border-[#1f2433] bg-[#07080b]/90 backdrop-blur-md py-3 px-6 text-xs font-mono text-slate-400 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3 flex-wrap">
          <span className="flex items-center gap-1.5 text-[#10b981] font-semibold">
            <span className="h-2 w-2 rounded-full bg-[#10b981] shadow-[0_0_8px_#10b981] animate-pulse" />
            ZERO-TRUST DEFENSE SENTINEL ACTIVE
          </span>
          <span className="text-slate-600">|</span>
          <span>Acoustic FFT Sample Rate: <span className="text-slate-200">48,000 Hz</span></span>
          <span className="text-slate-600">|</span>
          <span>Vocoder Defenses: <span className="text-[#06b6d4]">HiFi-GAN &amp; ElevenLabs-v2</span></span>
          <span className="text-slate-600">|</span>
          <span className="text-cyan-400 flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-[#06b6d4] shadow-[0_0_6px_#06b6d4]" />
            8s Realtime Polling
          </span>
        </div>

        <div className="flex items-center gap-3 text-[11px] text-slate-400 font-mono flex-wrap">
          <span className="px-2 py-0.5 rounded bg-[#151923] border border-[#1f2433] text-slate-300">
            Mercury: <span className="text-[#10b981]">MT103 Connected</span>
          </span>
          <span className="px-2 py-0.5 rounded bg-[#151923] border border-[#1f2433] text-slate-300">
            Brex: <span className="text-[#10b981]">ISO-20022 Synced</span>
          </span>
          <span className="px-2 py-0.5 rounded bg-[#151923] border border-[#1f2433] text-slate-300">
            Chase: <span className="text-[#10b981]">FIDO2 Enforced</span>
          </span>
        </div>
      </footer>
    </div>
  );
}
