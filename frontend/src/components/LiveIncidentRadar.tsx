"use client";

import React, { useState } from "react";
import {
  ShieldAlert,
  PhoneCall,
  MessageSquare,
  Send,
  AlertOctagon,
  Clock,
  ArrowRight,
  Fingerprint,
  Bot,
  Ban,
  Search,
  CheckCircle,
  ExternalLink,
  ChevronRight,
  Filter,
  Radio,
  Zap,
  Copy,
  Check,
} from "lucide-react";
import { SecurityIncidentResponse, ThreatSeverity, IncidentStatus, Channel } from "@/types";
import { cn, formatCurrency, truncateHash, formatTimeAgo } from "@/lib/utils";
import { mockIncidents } from "@/lib/mockData";

export interface LiveIncidentRadarProps {
  incidents?: SecurityIncidentResponse[];
  selectedIncidentId?: string | null;
  onSelectIncident?: (incident: SecurityIncidentResponse) => void;
  onTriggerChallenge?: (incidentId: string) => void;
  onDivertHoneypot?: (incidentId: string) => void;
  onFreezeIncident?: (incidentId: string) => void;
  onSimulateInboundCall?: () => void;
  isSimulating?: boolean;
}

export const LiveIncidentRadar: React.FC<LiveIncidentRadarProps> = ({
  incidents = mockIncidents,
  selectedIncidentId,
  onSelectIncident,
  onTriggerChallenge,
  onDivertHoneypot,
  onFreezeIncident,
  onSimulateInboundCall,
  isSimulating = false,
}) => {
  const [filterStatus, setFilterStatus] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [copiedIbanId, setCopiedIbanId] = useState<string | null>(null);

  const filteredIncidents = incidents.filter((inc) => {
    // Status filter
    if (filterStatus !== "ALL" && inc.status !== filterStatus) {
      return false;
    }
    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const execName = (inc.executive?.name || "").toLowerCase();
      const caller = (inc.callerSourceId || inc.caller_source_id || "").toLowerCase();
      const bank = (inc.requestedRecipientBank || inc.requested_recipient_bank || "").toLowerCase();
      const iban = (inc.requestedRecipientIban || inc.requested_recipient_iban || "").toLowerCase();
      const employee = (inc.recipientEmployee || inc.recipient_employee || "").toLowerCase();
      return (
        execName.includes(q) ||
        caller.includes(q) ||
        bank.includes(q) ||
        iban.includes(q) ||
        employee.includes(q)
      );
    }
    return true;
  });

  const getChannelBadge = (channel: Channel) => {
    switch (channel) {
      case "VOICE_CALL":
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-blue-950/60 text-blue-300 border border-blue-800/40">
            <PhoneCall className="h-2.5 w-2.5" />
            VOICE CALL
          </span>
        );
      case "WHATSAPP_AUDIO":
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/40">
            <MessageSquare className="h-2.5 w-2.5" />
            WHATSAPP AUDIO
          </span>
        );
      case "TELEGRAM_VOICE":
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-sky-950/60 text-sky-300 border border-sky-800/40">
            <Send className="h-2.5 w-2.5" />
            TELEGRAM VOICE
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
            {channel}
          </span>
        );
    }
  };

  const getSeverityBadge = (severity: ThreatSeverity) => {
    switch (severity) {
      case "CRITICAL":
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-[#f43f5e]/15 text-[#f43f5e] border border-[#f43f5e]/40 shadow-sm">
            <span className="h-1.5 w-1.5 rounded-full bg-[#f43f5e] animate-ping" />
            CRITICAL
          </span>
        );
      case "HIGH":
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-[#f59e0b]/15 text-[#f59e0b] border border-[#f59e0b]/40">
            <span className="h-1.5 w-1.5 rounded-full bg-[#f59e0b]" />
            HIGH
          </span>
        );
      case "MEDIUM":
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-yellow-950/60 text-yellow-400 border border-yellow-800/40">
            <span className="h-1.5 w-1.5 rounded-full bg-yellow-400" />
            MEDIUM
          </span>
        );
      default:
        return (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
            {severity}
          </span>
        );
    }
  };

  const getStatusBadge = (status: IncidentStatus) => {
    switch (status) {
      case "HONEYPOT_ROUTED":
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-[#8b5cf6]/20 text-[#8b5cf6] border border-[#8b5cf6]/40 font-semibold animate-pulse shadow-sm">
            <Bot className="h-3 w-3" />
            HONEYPOT ROUTED
          </span>
        );
      case "CHALLENGE_PENDING":
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-[#f59e0b]/20 text-[#f59e0b] border border-[#f59e0b]/40 font-semibold shadow-sm">
            <Fingerprint className="h-3 w-3 text-[#f59e0b]" />
            CHALLENGE PENDING
          </span>
        );
      case "FROZEN_BLOCKED":
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-[#f43f5e]/20 text-[#f43f5e] border border-[#f43f5e]/40 font-semibold shadow-sm">
            <Ban className="h-3 w-3 text-[#f43f5e]" />
            FROZEN / BLOCKED
          </span>
        );
      case "VERIFIED_CLEARED":
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-[#10b981]/20 text-[#10b981] border border-[#10b981]/40 font-semibold shadow-sm">
            <CheckCircle className="h-3 w-3 text-[#10b981]" />
            VERIFIED CLEARED
          </span>
        );
      default:
        return (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
            {status}
          </span>
        );
    }
  };

  const handleCopyIban = (iban: string, incidentId: string) => {
    navigator.clipboard.writeText(iban);
    setCopiedIbanId(incidentId);
    setTimeout(() => setCopiedIbanId(null), 2000);
  };

  return (
    <div className="rounded-lg cyber-card flex flex-col h-full overflow-hidden shadow-2xl">
      {/* Header bar with filters */}
      <div className="p-3.5 border-b border-[#1f2433] bg-[#151923]/80 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="relative flex items-center justify-center h-5 w-5">
            <div className="absolute inset-0 rounded-full border border-[#f43f5e]/40 animate-ping" />
            <div className="h-2 w-2 rounded-full bg-[#f43f5e] shadow-[0_0_8px_#f43f5e]" />
          </div>
          <div>
            <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white flex items-center gap-2">
              LIVE WIRE INTERCEPTION RADAR
              <span className="text-[10px] px-2 py-0.5 rounded bg-[#1f2433] text-slate-300 font-mono font-normal">
                {filteredIncidents.length} STREAMING
              </span>
            </h3>
          </div>
        </div>

        {/* Action Button: Simulate Call */}
        {onSimulateInboundCall && (
          <button
            onClick={onSimulateInboundCall}
            disabled={isSimulating}
            className="px-3 py-1.5 text-xs font-mono font-bold rounded bg-[#f43f5e] hover:bg-[#e11d48] disabled:opacity-50 text-white flex items-center gap-1.5 transition-all cursor-pointer shadow-md glow-crimson-sm"
            title="Simulate Inbound Deepfake Wire Call"
          >
            <PhoneCall className={cn("h-3.5 w-3.5", isSimulating ? "animate-spin" : "")} />
            <span>{isSimulating ? "Analyzing Spectral FFT..." : "Simulate Inbound Deepfake"}</span>
          </button>
        )}
      </div>

      {/* Filter Tabs & Search Bar */}
      <div className="p-3 border-b border-[#1f2433] bg-[#07080b]/50 space-y-2.5">
        <div className="flex items-center gap-1.5 flex-wrap">
          {[
            { key: "ALL", label: "All Streams", count: incidents.length },
            { key: "HONEYPOT_ROUTED", label: "Honeypot", count: incidents.filter((i) => i.status === "HONEYPOT_ROUTED").length },
            { key: "CHALLENGE_PENDING", label: "Challenge", count: incidents.filter((i) => i.status === "CHALLENGE_PENDING").length },
            { key: "FROZEN_BLOCKED", label: "Frozen", count: incidents.filter((i) => i.status === "FROZEN_BLOCKED").length },
          ].map((tab) => (
            <button
              key={tab.key}
              onClick={() => setFilterStatus(tab.key)}
              className={cn(
                "px-2.5 py-1 text-[10px] font-mono uppercase tracking-wider rounded transition-all cursor-pointer flex items-center gap-1.5",
                filterStatus === tab.key
                  ? "bg-[#06b6d4] text-black font-bold shadow-sm glow-cyan-sm"
                  : "bg-[#151923] hover:bg-[#1f2433] text-slate-400 hover:text-slate-200 border border-[#1f2433]"
              )}
            >
              <span>{tab.label}</span>
              <span className={cn(
                "px-1 py-0.2 rounded text-[9px]",
                filterStatus === tab.key ? "bg-black/30 text-black font-bold" : "bg-black/40 text-slate-400"
              )}>
                {tab.count}
              </span>
            </button>
          ))}
        </div>

        {/* Search input with shortcut token */}
        <div className="relative">
          <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search by executive, employee, bank, or mule IBAN..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#151923] border border-[#1f2433] rounded pl-8 pr-12 py-1.5 text-xs font-mono text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-[#06b6d4] focus:shadow-[0_0_10px_rgba(6,182,212,0.25)] transition-all"
          />
          <span className="absolute right-2.5 top-2 text-[9px] font-mono text-slate-500 bg-[#0f1118] px-1.5 py-0.5 rounded border border-[#1f2433]">
            /
          </span>
        </div>
      </div>

      {/* Stream list */}
      <div className="divide-y divide-[#1f2433] overflow-y-auto max-h-[640px] flex-1">
        {filteredIncidents.length === 0 ? (
          <div className="p-12 text-center text-slate-500 text-xs font-mono">
            No security incidents match the selected filter.
          </div>
        ) : (
          filteredIncidents.map((incident) => {
            const isSelected = selectedIncidentId === incident.id;
            const score = incident.deepfakeConfidenceScore ?? incident.deepfake_confidence_score ?? 0;
            const amount = incident.requestedAmountUsd ?? incident.requested_amount_usd ?? 0;
            const bank = incident.requestedRecipientBank ?? incident.requested_recipient_bank ?? "Unknown Bank";
            const iban = incident.requestedRecipientIban ?? incident.requested_recipient_iban ?? "";
            const caller = incident.callerSourceId ?? incident.caller_source_id ?? "";
            const targetEmployee = incident.recipientEmployee ?? incident.recipient_employee ?? "";
            const createdAt = incident.createdAt ?? incident.created_at ?? "";

            return (
              <div
                key={incident.id}
                onClick={() => onSelectIncident?.(incident)}
                className={cn(
                  "p-4 transition-all duration-200 cursor-pointer group relative",
                  isSelected
                    ? "bg-[#151923] border-l-4 border-l-[#06b6d4] shadow-[inset_4px_0_16px_rgba(6,182,212,0.12)]"
                    : "border-l-4 border-l-transparent hover:bg-[#151923]/60"
                )}
              >
                {/* Top Row: Severity, Channel, Status, Time */}
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    {getSeverityBadge(incident.threatSeverity ?? incident.threat_severity ?? "HIGH")}
                    {getChannelBadge(incident.channel)}
                    {getStatusBadge(incident.status)}
                  </div>
                  <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-400">
                    <Clock className="h-3 w-3 text-slate-500" />
                    <span>{formatTimeAgo(createdAt)}</span>
                  </div>
                </div>

                {/* Main Row: Executive Persona & Wire Amount */}
                <div className="mt-3 flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-white font-mono tracking-tight">
                        Targeting: {incident.executive?.name || "Executive Impersonation"}
                      </span>
                      <span className="text-[11px] text-slate-400 font-mono">
                        [{incident.executive?.title || "C-Suite"}]
                      </span>
                    </div>
                    <div className="text-xs text-slate-400 mt-1 font-mono flex items-center gap-1.5 flex-wrap">
                      <span className="text-slate-500">Vector:</span>
                      <span className="text-slate-300 font-semibold">{caller}</span>
                      <span className="text-slate-600">&rarr;</span>
                      <span className="text-slate-500">Target:</span>
                      <span className="text-slate-300">{targetEmployee}</span>
                    </div>
                  </div>

                  <div className="text-right">
                    <div className="text-lg font-extrabold font-mono text-[#f43f5e] tracking-tight drop-shadow-sm">
                      {formatCurrency(amount)}
                    </div>
                    <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                      Bank: <span className="text-slate-200 font-semibold">{bank}</span>
                    </div>
                  </div>
                </div>

                {/* Forensic Deepfake Gauge & Mule IBAN bar */}
                <div className="mt-3 pt-2.5 border-t border-[#1f2433]/80 flex flex-wrap items-center justify-between gap-3 bg-[#07080b]/50 p-2.5 rounded border border-[#1f2433]">
                  {/* Gauge */}
                  <div className="flex items-center gap-3">
                    <div className="flex items-center gap-1.5">
                      <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                        SYNTHETIC VOICE CONFIDENCE:
                      </span>
                      <span
                        className={cn(
                          "font-mono font-extrabold text-xs px-2 py-0.5 rounded shadow-sm",
                          score >= 85
                            ? "bg-[#f43f5e]/20 text-[#f43f5e] border border-[#f43f5e]/40"
                            : score >= 70
                            ? "bg-[#f59e0b]/20 text-[#f59e0b] border border-[#f59e0b]/40"
                            : "bg-[#10b981]/20 text-[#10b981] border border-[#10b981]/40"
                        )}
                      >
                        {score.toFixed(1)}%
                      </span>
                    </div>
                    {/* Visual Meter */}
                    <div className="w-20 sm:w-28 bg-[#1f2433] h-1.5 rounded-full overflow-hidden">
                      <div
                        className={cn(
                          "h-full rounded-full transition-all duration-300",
                          score >= 85
                            ? "bg-[#f43f5e] shadow-[0_0_6px_#f43f5e]"
                            : score >= 70
                            ? "bg-[#f59e0b] shadow-[0_0_6px_#f59e0b]"
                            : "bg-[#10b981] shadow-[0_0_6px_#10b981]"
                        )}
                        style={{ width: `${score}%` }}
                      />
                    </div>
                  </div>

                  {/* Destination IBAN pill */}
                  <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-400">
                    <span className="text-[10px] uppercase">MULE IBAN:</span>
                    <div className="flex items-center gap-1 bg-[#151923] px-2 py-0.5 rounded border border-[#1f2433]">
                      <span className="text-slate-200 font-mono text-xs select-all">
                        {iban ? truncateHash(iban, 8, 6) : "Pending Extraction"}
                      </span>
                      {iban && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleCopyIban(iban, incident.id);
                          }}
                          className="text-[#06b6d4] hover:text-white cursor-pointer ml-0.5"
                          title="Copy Full Mule IBAN"
                        >
                          {copiedIbanId === incident.id ? (
                            <Check className="h-3 w-3 text-[#10b981]" />
                          ) : (
                            <Copy className="h-3 w-3" />
                          )}
                        </button>
                      )}
                    </div>
                  </div>
                </div>

                {/* Quick Actions */}
                <div className="mt-3 flex items-center justify-end gap-2">
                  {incident.status === "CHALLENGE_PENDING" && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onTriggerChallenge?.(incident.id);
                      }}
                      className="px-2.5 py-1 text-[11px] font-mono font-semibold rounded bg-[#f59e0b]/15 hover:bg-[#f59e0b]/25 text-[#f59e0b] border border-[#f59e0b]/40 flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm"
                    >
                      <Fingerprint className="h-3 w-3" />
                      Dispatch OTP Challenge
                    </button>
                  )}

                  {incident.status !== "HONEYPOT_ROUTED" && incident.status !== "FROZEN_BLOCKED" && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onDivertHoneypot?.(incident.id);
                      }}
                      className="px-2.5 py-1 text-[11px] font-mono font-semibold rounded bg-[#8b5cf6]/15 hover:bg-[#8b5cf6]/25 text-[#8b5cf6] border border-[#8b5cf6]/40 flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm"
                    >
                      <Bot className="h-3 w-3" />
                      Divert to Honeypot
                    </button>
                  )}

                  {incident.status !== "FROZEN_BLOCKED" && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onFreezeIncident?.(incident.id);
                      }}
                      className="px-2.5 py-1 text-[11px] font-mono font-semibold rounded bg-[#f43f5e]/15 hover:bg-[#f43f5e]/25 text-[#f43f5e] border border-[#f43f5e]/40 flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm"
                    >
                      <Ban className="h-3 w-3" />
                      Arrest Wire
                    </button>
                  )}

                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onSelectIncident?.(incident);
                    }}
                    className="px-2.5 py-1 text-[11px] font-mono rounded bg-[#1f2433] hover:bg-[#2c3347] text-slate-200 border border-[#2c3347] flex items-center gap-1 transition-colors cursor-pointer shadow-sm"
                  >
                    <span>Inspect</span>
                    <ChevronRight className="h-3 w-3" />
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

export default LiveIncidentRadar;
