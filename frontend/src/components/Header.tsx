"use client";

import React, { useState, useEffect } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Power,
  Activity,
  Landmark,
  Radio,
  Clock,
  Lock,
  Unlock,
  AlertTriangle,
  RefreshCw,
  Terminal,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";

export interface BankStatusItem {
  id: string;
  name: string;
  status: "active" | "frozen" | "syncing";
  latencyMs: number;
  protocol: string;
}

export interface HeaderProps {
  killswitchActive?: boolean;
  onToggleKillswitch?: (active: boolean) => void;
  systemStatusText?: string;
  bankStatuses?: BankStatusItem[];
  interceptedCount?: number;
  lastSyncTime?: string;
}

const defaultBanks: BankStatusItem[] = [
  { id: "mercury", name: "Mercury", status: "active", latencyMs: 14, protocol: "MT103 / FedNow" },
  { id: "brex", name: "Brex", status: "active", latencyMs: 19, protocol: "Realtime Wire API" },
  { id: "chase", name: "Chase Treasury", status: "active", latencyMs: 24, protocol: "SWIFT ISO-20022" },
];

export const Header: React.FC<HeaderProps> = ({
  killswitchActive = false,
  onToggleKillswitch,
  systemStatusText = "FOUNDERSHIELD DEFENSE PROTOCOL ACTIVE",
  bankStatuses = defaultBanks,
  interceptedCount = 4,
  lastSyncTime,
}) => {
  const [currentTime, setCurrentTime] = useState<string>("");
  const [isConfirmingKillswitch, setIsConfirmingKillswitch] = useState<boolean>(false);
  const [internalKillswitch, setInternalKillswitch] = useState<boolean>(killswitchActive);

  useEffect(() => {
    setInternalKillswitch(killswitchActive);
  }, [killswitchActive]);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(
        now.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC")
      );
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleKillswitchClick = () => {
    if (!internalKillswitch) {
      // Need confirmation to arm killswitch
      setIsConfirmingKillswitch(true);
    } else {
      // Disarm directly
      const newState = false;
      setInternalKillswitch(newState);
      onToggleKillswitch?.(newState);
    }
  };

  const confirmArmKillswitch = () => {
    const newState = true;
    setInternalKillswitch(newState);
    setIsConfirmingKillswitch(false);
    onToggleKillswitch?.(newState);
  };

  return (
    <header className="w-full border-b border-[#1f2433] bg-[#07080b]/95 backdrop-blur-md sticky top-0 z-50 transition-colors duration-300">
      {/* Top Tactical Telemetry Coordinate Ribbon */}
      <div className="w-full bg-[#0a0d14] border-b border-[#1f2433]/70 px-4 py-0.5 text-[10px] font-mono text-slate-400 flex items-center justify-between select-none">
        <div className="flex items-center gap-3 tracking-wider">
          <span className="flex items-center gap-1 text-[#06b6d4]">
            <Terminal className="h-3 w-3" />
            <span>NODE::SOC-ALPHA</span>
          </span>
          <span className="text-slate-600">/</span>
          <span>LAT 37.7749° N &bull; LON -122.4194° W</span>
          <span className="text-slate-600">/</span>
          <span className="text-slate-300">ZERO-TRUST ACOUSTIC DEFENSE SENTRY</span>
          <span className="text-slate-600 hidden sm:inline">/</span>
          <span className="text-[#10b981] hidden sm:inline flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-[#10b981] shadow-[0_0_6px_#10b981]" />
            ENCLAVE: HSM-2 HARDENED
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[9px] uppercase tracking-widest text-slate-400 font-semibold hidden md:inline">
            DEFCON 2 READINESS
          </span>
          <span className="text-[#06b6d4] font-mono">BUILD 3.4.1</span>
        </div>
      </div>

      {/* Top Banner Alert when Killswitch Active */}
      {internalKillswitch && (
        <div className="bg-[#f43f5e] text-white px-4 py-2 text-xs font-mono font-bold flex items-center justify-between animate-pulse shadow-[0_0_20px_rgba(244,63,94,0.6)]">
          <div className="flex items-center gap-2.5">
            <AlertTriangle className="h-4 w-4 shrink-0 animate-bounce" />
            <span className="tracking-wide">
              EMERGENCY BANK WIRE FREEZE ENGAGED &bull; ALL OUTBOUND TRANSFERS ARRESTED ACROSS MERCURY, BREX, AND CHASE
            </span>
          </div>
          <button
            onClick={() => {
              setInternalKillswitch(false);
              onToggleKillswitch?.(false);
            }}
            className="bg-black/40 hover:bg-black/60 px-3 py-1 rounded text-[11px] uppercase tracking-wider underline cursor-pointer transition-colors"
          >
            Disarm Circuit Breaker
          </button>
        </div>
      )}

      {/* Main Header Bar */}
      <div className="max-w-[1920px] mx-auto px-4 lg:px-6 py-2.5 flex flex-wrap items-center justify-between gap-4">
        {/* Brand / SOC Protocol Status */}
        <div className="flex items-center gap-3.5">
          <div className="relative flex items-center justify-center h-10 w-10 rounded-lg bg-[#151923] border border-[#1f2433] shadow-inner group">
            <ShieldAlert
              className={cn(
                "h-6 w-6 transition-all duration-300",
                internalKillswitch ? "text-[#f43f5e] drop-shadow-[0_0_8px_#f43f5e]" : "text-[#06b6d4] drop-shadow-[0_0_8px_rgba(6,182,212,0.6)]"
              )}
            />
            <span
              className={cn(
                "absolute -top-1 -right-1 h-3 w-3 rounded-full border-2 border-[#07080b]",
                internalKillswitch
                  ? "bg-[#f43f5e] animate-ping"
                  : "bg-[#10b981] shadow-[0_0_8px_#10b981] animate-pulse"
              )}
            />
          </div>

          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold tracking-wider text-white text-base font-sans">
                FOUNDER<span className="text-[#06b6d4]">SHIELD</span>{" "}
                <span className="text-[#f43f5e] text-xs font-mono font-bold tracking-widest px-1 py-0.2 rounded bg-[#f43f5e]/15 border border-[#f43f5e]/30">
                  AI
                </span>
              </span>
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-[#151923] text-[#8b5cf6] border border-[#2c3347] font-semibold tracking-wide shadow-sm">
                COMMAND CENTER
              </span>
            </div>
            <div className="flex items-center gap-2 text-xs font-mono mt-0.5">
              <span
                className={cn(
                  "inline-flex items-center gap-1.5 font-bold tracking-tight text-[11px]",
                  internalKillswitch ? "text-[#f43f5e]" : "text-[#10b981]"
                )}
              >
                <span
                  className={cn(
                    "h-1.5 w-1.5 rounded-full",
                    internalKillswitch
                      ? "bg-[#f43f5e] animate-ping"
                      : "bg-[#10b981] shadow-[0_0_6px_#10b981]"
                  )}
                />
                {internalKillswitch ? "CIRCUIT BREAKER: ALL TRANSFERS ARRESTED" : systemStatusText}
              </span>
            </div>
          </div>
        </div>

        {/* Connected Bank Telemetry */}
        <div className="hidden xl:flex items-center gap-3 bg-[#0f1118] px-3.5 py-1.5 rounded-lg border border-[#1f2433] shadow-sm">
          <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400 mr-1">
            <Landmark className="h-3.5 w-3.5 text-[#06b6d4]" />
            <span className="text-[11px] font-semibold tracking-wide text-slate-300">
              BANKING INTEGRATIONS:
            </span>
          </div>

          {bankStatuses.map((bank) => (
            <div
              key={bank.id}
              className="flex items-center gap-2 text-[11px] font-mono px-2.5 py-1 rounded bg-[#151923] border border-[#1f2433] transition-colors hover:border-[#2c3347]"
              title={`${bank.name} - ${bank.protocol} (${bank.latencyMs}ms)`}
            >
              <span
                className={cn(
                  "h-1.5 w-1.5 rounded-full shrink-0",
                  internalKillswitch
                    ? "bg-[#f43f5e] shadow-[0_0_6px_#f43f5e]"
                    : bank.status === "active"
                    ? "bg-[#10b981] shadow-[0_0_6px_#10b981]"
                    : "bg-[#f59e0b] shadow-[0_0_6px_#f59e0b]"
                )}
              />
              <span className="text-slate-200 font-medium">{bank.name}</span>
              <span className="text-[10px] text-slate-400 font-mono">
                {internalKillswitch ? "FROZEN" : `${bank.latencyMs}ms`}
              </span>
              <span className="text-[9px] px-1 py-0.2 rounded bg-black/40 text-slate-400 border border-[#1f2433]">
                {bank.protocol.split("/")[0].trim()}
              </span>
            </div>
          ))}
        </div>

        {/* Operational Time & Killswitch Action */}
        <div className="flex items-center gap-3.5">
          <div className="hidden md:flex items-center gap-2 text-xs font-mono text-slate-300 bg-[#0f1118] px-3 py-1.5 rounded-lg border border-[#1f2433]">
            <Clock className="h-3.5 w-3.5 text-[#06b6d4]" />
            <span className="text-slate-200 tracking-tight">{currentTime || "SYNCING UTC CLOCK..."}</span>
          </div>

          {/* Emergency Killswitch Toggle Button */}
          <div className="relative">
            <button
              onClick={handleKillswitchClick}
              className={cn(
                "flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono font-bold tracking-wide uppercase transition-all duration-200 cursor-pointer shadow-md select-none",
                internalKillswitch
                  ? "bg-[#f43f5e] hover:bg-[#e11d48] text-white glow-crimson border border-[#f43f5e] animate-beacon"
                  : "bg-[#151923] hover:bg-[#1a202c] text-rose-300 border border-rose-900/60 hover:border-rose-500 hover:shadow-[0_0_15px_rgba(244,63,94,0.3)]"
              )}
            >
              <Power className={cn("h-4 w-4", internalKillswitch ? "animate-pulse" : "text-[#f43f5e]")} />
              <span>
                {internalKillswitch ? "KILLSWITCH ARMED" : "EMERGENCY FREEZE"}
              </span>
            </button>

            {/* Arm Confirmation Dialog Popover */}
            {isConfirmingKillswitch && (
              <div className="absolute right-0 top-12 w-84 p-4 bg-[#151923] border border-[#f43f5e] rounded-lg shadow-2xl z-50 animate-in fade-in zoom-in-95 duration-150 glow-crimson-sm">
                <div className="flex items-start gap-3">
                  <div className="h-8 w-8 rounded bg-[#f43f5e]/15 border border-[#f43f5e]/40 flex items-center justify-center shrink-0">
                    <AlertTriangle className="h-4 w-4 text-[#f43f5e]" />
                  </div>
                  <div>
                    <h4 className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                      ARM GLOBAL WIRE KILLSWITCH?
                    </h4>
                    <p className="text-[11px] text-slate-300 mt-1 leading-relaxed font-sans">
                      This will immediately halt all pending wire transfers and trigger lockdown across Mercury, Brex, and Chase APIs.
                    </p>
                  </div>
                </div>
                <div className="mt-3.5 flex items-center justify-end gap-2 pt-2.5 border-t border-[#1f2433]">
                  <button
                    onClick={() => setIsConfirmingKillswitch(false)}
                    className="px-3 py-1.5 text-xs font-mono rounded bg-[#0f1118] text-slate-300 hover:text-white border border-[#1f2433] transition-colors cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={confirmArmKillswitch}
                    className="px-3.5 py-1.5 text-xs font-mono font-bold rounded bg-[#f43f5e] hover:bg-[#e11d48] text-white shadow transition-all cursor-pointer glow-crimson-sm"
                  >
                    CONFIRM FREEZE
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;
