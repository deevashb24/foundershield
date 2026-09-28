"use client";

import React from "react";
import {
  ShieldAlert,
  Cpu,
  Bot,
  Zap,
  ArrowUpRight,
  Radio,
  Clock,
  ShieldCheck,
  TrendingUp,
} from "lucide-react";
import { cn, formatCurrency } from "@/lib/utils";

export interface ThreatMetricsOverviewProps {
  totalInterceptedUsd?: number;
  catchRatePercent?: number;
  activeHoneypots?: number;
  avgLatencySeconds?: number;
  totalIncidents?: number;
  frozenIncidentsCount?: number;
  honeypotRoutedCount?: number;
  challengePendingCount?: number;
  killswitchActive?: boolean;
}

export const ThreatMetricsOverview: React.FC<ThreatMetricsOverviewProps> = ({
  totalInterceptedUsd = 312700.0,
  catchRatePercent = 99.2,
  activeHoneypots = 2,
  avgLatencySeconds = 14.2,
  totalIncidents = 4,
  frozenIncidentsCount = 1,
  honeypotRoutedCount = 2,
  challengePendingCount = 1,
  killswitchActive = false,
}) => {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 w-full">
      {/* CARD 1: Total Intercepted Wire Fraud */}
      <div className="relative overflow-hidden rounded-lg cyber-card p-4 transition-all duration-300 hover:border-[#f43f5e]/60 hover:shadow-[0_0_24px_rgba(244,63,94,0.15)] group">
        {/* Subtle top-right ambient glow corner */}
        <div className="absolute top-0 right-0 h-20 w-20 bg-[#f43f5e]/10 rounded-bl-full pointer-events-none blur-xl transition-opacity group-hover:opacity-100" />
        
        {/* Corner Bracket Accent */}
        <div className="absolute top-1 left-1 w-2 h-2 border-t border-l border-white/20 pointer-events-none" />
        <div className="absolute top-1 right-1 w-2 h-2 border-t border-r border-white/20 pointer-events-none" />

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-mono font-medium text-slate-400">
            <div className="h-6 w-6 rounded bg-[#f43f5e]/15 border border-[#f43f5e]/30 flex items-center justify-center">
              <ShieldAlert className="h-3.5 w-3.5 text-[#f43f5e]" />
            </div>
            <span className="uppercase tracking-wider text-[11px] font-semibold text-slate-300">
              TOTAL FRAUD INTERCEPTED
            </span>
          </div>
          <span className="flex items-center gap-1 text-[11px] font-mono text-[#10b981] bg-[#10b981]/15 px-2 py-0.5 rounded border border-[#10b981]/30 font-semibold shadow-sm">
            <ArrowUpRight className="h-3 w-3" />
            +18.4%
          </span>
        </div>

        <div className="mt-3">
          <div className="text-2xl sm:text-3xl font-extrabold font-mono text-white tracking-tight drop-shadow-sm">
            {formatCurrency(totalInterceptedUsd)}
          </div>
          <div className="mt-1 flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>{totalIncidents} Wire Vectors Intercepted</span>
            <span className="text-[#f43f5e] font-bold font-mono">100% CAPITAL SHIELDED</span>
          </div>
        </div>

        {/* Tactical Segmented Status Bar */}
        <div className="mt-3.5 space-y-1.5">
          <div className="w-full bg-[#07080b] h-1.5 rounded-full overflow-hidden flex border border-[#1f2433]">
            <div
              className="bg-[#8b5cf6] h-full transition-all duration-500"
              style={{ width: `${(honeypotRoutedCount / totalIncidents) * 100}%` }}
              title="Diverted to Honeypots"
            />
            <div
              className="bg-[#f59e0b] h-full transition-all duration-500"
              style={{ width: `${(challengePendingCount / totalIncidents) * 100}%` }}
              title="Pending Biometric Challenge"
            />
            <div
              className="bg-[#f43f5e] h-full transition-all duration-500"
              style={{ width: `${(frozenIncidentsCount / totalIncidents) * 100}%` }}
              title="Frozen by Killswitch"
            />
          </div>
          <div className="flex items-center justify-between text-[9px] font-mono text-slate-500">
            <span className="text-[#8b5cf6] flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-[#8b5cf6]" />
              {honeypotRoutedCount} Honeypot
            </span>
            <span className="text-[#f59e0b] flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-[#f59e0b]" />
              {challengePendingCount} Challenge
            </span>
            <span className="text-[#f43f5e] flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-[#f43f5e]" />
              {frozenIncidentsCount} Frozen
            </span>
          </div>
        </div>
      </div>

      {/* CARD 2: Synthetic Voice Catch Rate */}
      <div className="relative overflow-hidden rounded-lg cyber-card p-4 transition-all duration-300 hover:border-[#06b6d4]/60 hover:shadow-[0_0_24px_rgba(6,182,212,0.15)] group">
        <div className="absolute top-0 right-0 h-20 w-20 bg-[#06b6d4]/10 rounded-bl-full pointer-events-none blur-xl transition-opacity group-hover:opacity-100" />
        
        {/* Corner Bracket Accent */}
        <div className="absolute top-1 left-1 w-2 h-2 border-t border-l border-white/20 pointer-events-none" />
        <div className="absolute top-1 right-1 w-2 h-2 border-t border-r border-white/20 pointer-events-none" />

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-mono font-medium text-slate-400">
            <div className="h-6 w-6 rounded bg-[#06b6d4]/15 border border-[#06b6d4]/30 flex items-center justify-center">
              <Cpu className="h-3.5 w-3.5 text-[#06b6d4]" />
            </div>
            <span className="uppercase tracking-wider text-[11px] font-semibold text-slate-300">
              SYNTHETIC VOICE CATCH RATE
            </span>
          </div>
          <span className="text-[10px] font-mono text-[#06b6d4] bg-[#06b6d4]/15 px-2 py-0.5 rounded border border-[#06b6d4]/30 font-semibold tracking-wider">
            SPECTRAL FFT
          </span>
        </div>

        <div className="mt-3">
          <div className="text-2xl sm:text-3xl font-extrabold font-mono text-white tracking-tight flex items-baseline gap-2">
            <span>{catchRatePercent.toFixed(1)}%</span>
            <span className="text-xs font-mono text-slate-400 font-normal">detection accuracy</span>
          </div>
          <div className="mt-1 flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Neural Vocoder Footprint</span>
            <span className="text-[#06b6d4] font-bold font-mono">&lt; 0.04% FPR</span>
          </div>
        </div>

        {/* Telemetry Progress Bar */}
        <div className="mt-3.5 space-y-1.5">
          <div className="w-full bg-[#07080b] h-1.5 rounded-full overflow-hidden border border-[#1f2433]">
            <div
              className="bg-gradient-to-r from-[#06b6d4] to-[#10b981] h-full rounded-full transition-all duration-500 shadow-[0_0_8px_rgba(6,182,212,0.8)]"
              style={{ width: `${catchRatePercent}%` }}
            />
          </div>
          <div className="flex items-center justify-between text-[9px] font-mono text-slate-500">
            <span>HiFi-GAN / ElevenLabs Resynthesis</span>
            <span className="text-[#10b981] font-semibold">99.98% Confidence</span>
          </div>
        </div>
      </div>

      {/* CARD 3: Active Decoy Honeypots */}
      <div className="relative overflow-hidden rounded-lg cyber-card p-4 transition-all duration-300 hover:border-[#8b5cf6]/60 hover:shadow-[0_0_24px_rgba(139,92,246,0.15)] group">
        <div className="absolute top-0 right-0 h-20 w-20 bg-[#8b5cf6]/10 rounded-bl-full pointer-events-none blur-xl transition-opacity group-hover:opacity-100" />
        
        {/* Corner Bracket Accent */}
        <div className="absolute top-1 left-1 w-2 h-2 border-t border-l border-white/20 pointer-events-none" />
        <div className="absolute top-1 right-1 w-2 h-2 border-t border-r border-white/20 pointer-events-none" />

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-mono font-medium text-slate-400">
            <div className="h-6 w-6 rounded bg-[#8b5cf6]/15 border border-[#8b5cf6]/30 flex items-center justify-center">
              <Bot className="h-3.5 w-3.5 text-[#8b5cf6]" />
            </div>
            <span className="uppercase tracking-wider text-[11px] font-semibold text-slate-300">
              ACTIVE DECOY HONEYPOTS
            </span>
          </div>
          <span className="flex items-center gap-1.5 text-[10px] font-mono text-[#8b5cf6] bg-[#8b5cf6]/15 px-2 py-0.5 rounded border border-[#8b5cf6]/30 font-semibold animate-pulse">
            <Radio className="h-2.5 w-2.5" />
            HARVESTING
          </span>
        </div>

        <div className="mt-3">
          <div className="text-2xl sm:text-3xl font-extrabold font-mono text-white tracking-tight flex items-baseline gap-2">
            <span>{activeHoneypots}</span>
            <span className="text-xs font-mono text-slate-400 font-normal">live decoy sessions</span>
          </div>
          <div className="mt-1 flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Apate Autonomous AI</span>
            <span className="text-[#8b5cf6] font-bold font-mono">Mule IBANs Extracted</span>
          </div>
        </div>

        {/* Audio waveform activity ticks */}
        <div className="mt-3.5 space-y-1.5">
          <div className="flex items-center gap-1 h-2 bg-[#07080b] p-0.5 rounded border border-[#1f2433]">
            {[35, 75, 95, 60, 85, 100, 45, 90, 70, 80, 50, 95, 65, 85, 40].map((h, i) => (
              <div
                key={i}
                className="flex-1 bg-[#8b5cf6] rounded-full animate-pulse transition-all shadow-[0_0_4px_#8b5cf6]"
                style={{
                  height: `${h}%`,
                  animationDelay: `${i * 90}ms`,
                  opacity: 0.6 + (h / 250),
                }}
              />
            ))}
          </div>
          <div className="flex items-center justify-between text-[9px] font-mono text-slate-500">
            <span>Avg Stall Time: 5m 42s</span>
            <span className="text-[#8b5cf6]">German & Dutch Mules</span>
          </div>
        </div>
      </div>

      {/* CARD 4: Avg Verification Latency */}
      <div className="relative overflow-hidden rounded-lg cyber-card p-4 transition-all duration-300 hover:border-[#10b981]/60 hover:shadow-[0_0_24px_rgba(16,185,129,0.15)] group">
        <div className="absolute top-0 right-0 h-20 w-20 bg-[#10b981]/10 rounded-bl-full pointer-events-none blur-xl transition-opacity group-hover:opacity-100" />
        
        {/* Corner Bracket Accent */}
        <div className="absolute top-1 left-1 w-2 h-2 border-t border-l border-white/20 pointer-events-none" />
        <div className="absolute top-1 right-1 w-2 h-2 border-t border-r border-white/20 pointer-events-none" />

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-mono font-medium text-slate-400">
            <div className="h-6 w-6 rounded bg-[#10b981]/15 border border-[#10b981]/30 flex items-center justify-center">
              <Zap className="h-3.5 w-3.5 text-[#10b981]" />
            </div>
            <span className="uppercase tracking-wider text-[11px] font-semibold text-slate-300">
              AVG VERIFICATION LATENCY
            </span>
          </div>
          <span className="text-[10px] font-mono text-[#10b981] bg-[#10b981]/15 px-2 py-0.5 rounded border border-[#10b981]/30 font-semibold tracking-wider">
            FIDO2 PUSH
          </span>
        </div>

        <div className="mt-3">
          <div className="text-2xl sm:text-3xl font-extrabold font-mono text-white tracking-tight flex items-baseline gap-2">
            <span>{avgLatencySeconds}s</span>
            <span className="text-xs font-mono text-slate-400 font-normal">out-of-band challenge</span>
          </div>
          <div className="mt-1 flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>60s TTL Window</span>
            <span className="text-[#10b981] font-bold font-mono">Zero Executive Friction</span>
          </div>
        </div>

        {/* Latency gauge indicator */}
        <div className="mt-3.5 space-y-1.5">
          <div className="w-full bg-[#07080b] h-1.5 rounded-full overflow-hidden border border-[#1f2433]">
            <div
              className="bg-[#10b981] h-full rounded-full transition-all duration-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]"
              style={{ width: `${Math.min((avgLatencySeconds / 60) * 100, 100)}%` }}
            />
          </div>
          <div className="flex items-center justify-between text-[9px] font-mono text-slate-500">
            <span>Challenge Speed &lt; 15s</span>
            <span className="text-[#10b981]">Dual-Key Clearance</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatMetricsOverview;
