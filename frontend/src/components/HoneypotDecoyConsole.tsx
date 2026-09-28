"use client";

import React, { useState } from "react";
import {
  Bot,
  UserX,
  Radio,
  Send,
  Sparkles,
  Clock,
  Landmark,
  MapPin,
  Globe,
  ShieldAlert,
  Server,
  Terminal,
  Zap,
  CheckCircle2,
  Copy,
  Check,
} from "lucide-react";
import { DecoySessionDTO, DecoyTranscriptMessage, ExtractedIntel } from "@/types";
import { cn } from "@/lib/utils";
import { mockDecoys } from "@/lib/mockData";

export interface HoneypotDecoyConsoleProps {
  decoySession?: DecoySessionDTO | null;
  onSendMessage?: (message: string) => void;
  isSending?: boolean;
}

const quickPromptChips = [
  "Confirm SWIFT MT103 routing code",
  "Simulate 45-second Mercury compliance delay",
  "Request company registration certificate",
  "Offer to split transfer across two tranches",
];

export const HoneypotDecoyConsole: React.FC<HoneypotDecoyConsoleProps> = ({
  decoySession = mockDecoys[0],
  onSendMessage,
  isSending = false,
}) => {
  const currentSession = decoySession || mockDecoys[0];
  const [messages, setMessages] = useState<DecoyTranscriptMessage[]>(currentSession.transcript || []);
  const [inputText, setInputText] = useState<string>("");
  const [copiedIban, setCopiedIban] = useState<boolean>(false);

  // Sync messages whenever parent provides updated decoySession
  React.useEffect(() => {
    if (decoySession?.transcript) {
      setMessages(decoySession.transcript);
    }
  }, [decoySession]);

  const intel: ExtractedIntel =
    currentSession.extractedIntel || currentSession.extracted_intel || mockDecoys[0].extractedIntel;

  const durationSec = currentSession.durationSeconds || currentSession.duration_seconds || 342;
  const minutes = Math.floor(durationSec / 60);
  const seconds = durationSec % 60;

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim()) return;

    const textToSend = inputText.trim();
    setInputText("");

    if (onSendMessage) {
      onSendMessage(textToSend);
    } else {
      const newScammerMsg: DecoyTranscriptMessage = {
        messageId: `msg-${messages.length + 1}`,
        speakerRole: "scammer",
        text: textToSend,
        timestamp: new Date().toISOString(),
        sentiment: "urgent",
        latencyMs: 0,
      };

      setMessages((prev) => [...prev, newScammerMsg]);

      // Simulate Apate AI response after 1.2s
      setTimeout(() => {
        const newAgentMsg: DecoyTranscriptMessage = {
          messageId: `msg-${messages.length + 2}`,
          speakerRole: "honeypot_agent",
          text: "Routing transit details registered in treasury settlement ledger. Mercury compliance requires the beneficial owner legal passport copy or corporate tax ID to complete MT103 transmission.",
          timestamp: new Date().toISOString(),
          sentiment: "cooperative",
          latencyMs: 1200,
        };
        setMessages((prev) => [...prev, newAgentMsg]);
      }, 1200);
    }
  };

  const handleCopyMule = (iban: string) => {
    navigator.clipboard.writeText(iban);
    setCopiedIban(true);
    setTimeout(() => setCopiedIban(false), 2000);
  };

  const muleAccount = currentSession.scammerMuleAccount || currentSession.scammer_mule_account || "DE89370400440532013000";
  const routing = currentSession.scammerRoutingNumber || currentSession.scammer_routing_number || "MARKET33XXX";

  return (
    <div className="rounded-lg cyber-card flex flex-col h-full overflow-hidden shadow-2xl">
      {/* Header Bar */}
      <div className="p-3.5 border-b border-[#1f2433] bg-[#151923]/80 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="h-6 w-6 rounded bg-[#8b5cf6]/15 border border-[#8b5cf6]/30 flex items-center justify-center">
            <Bot className="h-3.5 w-3.5 text-[#8b5cf6]" />
          </div>
          <div>
            <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white flex items-center gap-2">
              APATE AUTONOMOUS AI HONEYPOT
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#8b5cf6]/20 text-[#8b5cf6] border border-[#8b5cf6]/40 animate-pulse glow-violet-sm font-semibold">
                SCAMMER STALLED: {minutes}m {seconds}s
              </span>
            </h3>
            <p className="text-[11px] font-mono text-slate-400">
              Trunk: <span className="text-slate-200 font-semibold">{currentSession.callerId || "+1-312-555-8910"}</span> &bull; Strategy: <span className="text-[#8b5cf6] font-semibold">Active Mule Account Extraction</span>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#07080b] border border-[#1f2433] text-slate-300">
            <Radio className="h-3 w-3 text-[#10b981] animate-ping" />
            <span>SIP RECORDING ACTIVE</span>
          </span>
        </div>
      </div>

      <div className="p-4 space-y-4 flex-1 flex flex-col overflow-hidden">
        {/* Extracted Intelligence Pills / Forensic Telemetry */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2.5 p-3 rounded-lg bg-[#07080b]/70 border border-[#1f2433]">
          {/* Mule IBAN */}
          <div className="p-2.5 rounded bg-[#151923] border border-[#1f2433] transition-all hover:border-[#f43f5e]/40">
            <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
              <span className="uppercase tracking-wider">MULE IBAN / ACCOUNT</span>
              <button
                onClick={() => handleCopyMule(muleAccount)}
                className="text-[#06b6d4] hover:text-white cursor-pointer"
                title="Copy Mule IBAN"
              >
                {copiedIban ? <Check className="h-3 w-3 text-[#10b981]" /> : <Copy className="h-3 w-3" />}
              </button>
            </div>
            <div className="text-xs font-mono font-extrabold text-[#f43f5e] truncate mt-1 select-all tracking-tight">
              {muleAccount}
            </div>
          </div>

          {/* SWIFT / Routing */}
          <div className="p-2.5 rounded bg-[#151923] border border-[#1f2433] transition-all hover:border-[#f59e0b]/40">
            <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">ROUTING / SWIFT CODE</div>
            <div className="text-xs font-mono font-extrabold text-[#f59e0b] truncate mt-1">
              {routing}
            </div>
          </div>

          {/* Origin IP & Telephony */}
          <div className="p-2.5 rounded bg-[#151923] border border-[#1f2433] transition-all hover:border-[#06b6d4]/40">
            <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">CARRIER / IP GATEWAY</div>
            <div className="text-xs font-mono font-bold text-slate-200 truncate mt-1">
              {(intel.originIps || ["194.26.29.112"])[0]} <span className="text-slate-400 font-normal">(SIP-904)</span>
            </div>
          </div>

          {/* Scammer Tactics */}
          <div className="p-2.5 rounded bg-[#151923] border border-[#1f2433] transition-all hover:border-[#8b5cf6]/40">
            <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">DETECTED SOCIAL ENG</div>
            <div className="text-xs font-mono font-bold text-[#8b5cf6] truncate mt-1">
              {(intel.urgencyTactics || ["M&A Board Deadline Pressure"])[0]}
            </div>
          </div>
        </div>

        {/* Live Interactive Transcript Stream */}
        <div className="flex-1 rounded-lg bg-[#07080b] border border-[#1f2433] p-3.5 overflow-y-auto space-y-3 min-h-[260px] max-h-[380px]">
          {messages.map((msg, idx) => {
            const isScammer = msg.speakerRole === "scammer" || msg.speaker_role === "scammer";
            return (
              <div
                key={idx}
                className={cn(
                  "flex flex-col max-w-[85%] rounded-lg p-3 text-xs font-mono shadow-md transition-all",
                  isScammer
                    ? "self-start bg-[#1a0f14] border border-[#f43f5e]/40 text-rose-100 mr-auto shadow-[0_0_12px_rgba(244,63,94,0.08)]"
                    : "self-end bg-[#121020] border border-[#8b5cf6]/40 text-violet-100 ml-auto shadow-[0_0_12px_rgba(139,92,246,0.08)]"
                )}
              >
                <div className="flex items-center justify-between gap-3 text-[10px] border-b border-white/10 pb-1 mb-1.5">
                  <span
                    className={cn(
                      "font-bold uppercase tracking-wider flex items-center gap-1.5",
                      isScammer ? "text-[#f43f5e]" : "text-[#8b5cf6]"
                    )}
                  >
                    {isScammer ? <UserX className="h-3 w-3" /> : <Bot className="h-3 w-3" />}
                    {isScammer ? "THREAT ACTOR (SYNTHETIC VOICE SPOOF)" : "APATE AI (HONEYPOT TREASURY PERSONA)"}
                  </span>
                  <span className="text-slate-400 font-mono text-[9px]">
                    {msg.sentiment ? `[${msg.sentiment.toUpperCase()}]` : ""} {msg.latencyMs ? `+${msg.latencyMs}ms` : ""}
                  </span>
                </div>
                <p className="leading-relaxed text-[11px] whitespace-pre-wrap font-sans">
                  {msg.text}
                </p>
              </div>
            );
          })}
        </div>

        {/* Quick Suggestion Chips */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-[10px] font-mono">
          <span className="text-slate-400 shrink-0 flex items-center gap-1">
            <Sparkles className="h-3 w-3 text-[#8b5cf6]" />
            DECOY PLAYBOOKS:
          </span>
          {quickPromptChips.map((chip, idx) => (
            <button
              key={idx}
              onClick={() => setInputText(chip)}
              className="px-2.5 py-1 rounded bg-[#151923] hover:bg-[#1f2433] text-slate-300 border border-[#1f2433] hover:border-[#8b5cf6]/60 whitespace-nowrap transition-colors cursor-pointer"
            >
              {chip}
            </button>
          ))}
        </div>

        {/* Inject Decoy Prompt Test Input */}
        <form onSubmit={handleSend} className="flex gap-2">
          <div className="relative flex-1">
            <Terminal className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Inject operator response or custom stall prompt into honeypot call..."
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              className="w-full bg-[#151923] border border-[#1f2433] rounded pl-8 pr-3 py-2 text-xs font-mono text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-[#8b5cf6] focus:shadow-[0_0_12px_rgba(139,92,246,0.25)] transition-all"
            />
          </div>
          <button
            type="submit"
            disabled={isSending || !inputText.trim()}
            className="px-4 py-2 bg-[#8b5cf6] hover:bg-[#7c3aed] disabled:opacity-40 text-white text-xs font-mono font-bold rounded transition-all cursor-pointer flex items-center gap-1.5 shadow-md glow-violet-sm"
          >
            <Send className="h-3 w-3" />
            Inject Prompt
          </button>
        </form>
      </div>
    </div>
  );
};

export default HoneypotDecoyConsole;
