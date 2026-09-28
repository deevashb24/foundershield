"use client";

import React, { useState, useEffect } from "react";
import {
  Fingerprint,
  ShieldCheck,
  ShieldAlert,
  Clock,
  Send,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Smartphone,
  AlertTriangle,
  RefreshCw,
  Lock,
  KeyRound,
  Radio,
} from "lucide-react";
import { VerificationHandshakeDTO, HandshakeStatus, ExecutiveDTO } from "@/types";
import { cn, truncateHash } from "@/lib/utils";
import { mockHandshakes, mockExecutives } from "@/lib/mockData";

export interface BiometricChallengeConsoleProps {
  handshake?: VerificationHandshakeDTO | null;
  executive?: ExecutiveDTO | null;
  onVerifyCode?: (code: string) => void;
  onForceAuthorize?: () => void;
  onRejectChallenge?: () => void;
  onResendChallenge?: () => void;
  isVerifying?: boolean;
}

export const BiometricChallengeConsole: React.FC<BiometricChallengeConsoleProps> = ({
  handshake = mockHandshakes[0],
  executive: propExecutive,
  onVerifyCode,
  onForceAuthorize,
  onRejectChallenge,
  onResendChallenge,
  isVerifying = false,
}) => {
  const currentHandshake = handshake || mockHandshakes[0];
  const executive = propExecutive || mockExecutives[0];
  const [secondsRemaining, setSecondsRemaining] = useState<number>(48);
  const [enteredCode, setEnteredCode] = useState<string>("");
  const [copied, setCopied] = useState<boolean>(false);
  const [copiedHash, setCopiedHash] = useState<boolean>(false);
  const [simulatedStatus, setSimulatedStatus] = useState<HandshakeStatus>(currentHandshake.status);

  // Sync state if handshake prop changes
  useEffect(() => {
    if (handshake) {
      setSimulatedStatus(handshake.status);
    }
  }, [handshake]);

  // 60-second TTL countdown timer simulation
  useEffect(() => {
    if (simulatedStatus !== "PENDING") return;
    const interval = setInterval(() => {
      setSecondsRemaining((prev) => {
        if (prev <= 1) {
          setSimulatedStatus("EXPIRED");
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [simulatedStatus]);

  const handleCopyCode = () => {
    const code = currentHandshake.challengeCode || currentHandshake.challenge_code || "892415";
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleCopyHash = (h: string) => {
    navigator.clipboard.writeText(h);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const handleSubmitVerify = (e: React.FormEvent) => {
    e.preventDefault();
    if (!enteredCode || enteredCode.length < 6) return;
    onVerifyCode?.(enteredCode);
    const expected = currentHandshake.challengeCode || currentHandshake.challenge_code || "892415";
    if (enteredCode.trim().toUpperCase() === expected) {
      setSimulatedStatus("APPROVED");
    } else {
      setSimulatedStatus("REJECTED");
    }
  };

  const handleForceApprove = () => {
    setSimulatedStatus("APPROVED");
    onForceAuthorize?.();
  };

  const handleReject = () => {
    setSimulatedStatus("REJECTED");
    onRejectChallenge?.();
  };

  const handleResend = () => {
    setSecondsRemaining(60);
    setSimulatedStatus("PENDING");
    onResendChallenge?.();
  };

  const displayCode = currentHandshake.challengeCode || currentHandshake.challenge_code || "892415";
  const voiceHash = executive.voiceFingerprintHash || "a3f8b91924bce3e8d910a9c8f0e1329bb6d87e0fa1b2c3d4e5f60718293a4b5c";

  return (
    <div className="rounded-lg cyber-card flex flex-col h-full overflow-hidden shadow-2xl">
      {/* Header bar */}
      <div className="p-3.5 border-b border-[#1f2433] bg-[#151923]/80 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="h-6 w-6 rounded bg-[#f59e0b]/15 border border-[#f59e0b]/30 flex items-center justify-center">
            <Fingerprint className="h-3.5 w-3.5 text-[#f59e0b]" />
          </div>
          <div>
            <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white">
              OUT-OF-BAND BIOMETRIC CHALLENGE PROTOCOL
            </h3>
            <p className="text-[11px] font-mono text-slate-400">
              Zero-Trust Cryptographic Nonce &bull; 60s TTL Window Enforced
            </p>
          </div>
        </div>

        {/* Handshake Status Badge */}
        <div>
          {simulatedStatus === "PENDING" && (
            <span className="inline-flex items-center gap-1.5 text-xs font-mono font-bold px-3 py-1 rounded bg-[#f59e0b]/20 text-[#f59e0b] border border-[#f59e0b]/40 animate-pulse glow-amber-sm">
              <Clock className="h-3.5 w-3.5" />
              CHALLENGE ACTIVE ({secondsRemaining}s)
            </span>
          )}
          {simulatedStatus === "APPROVED" && (
            <span className="inline-flex items-center gap-1.5 text-xs font-mono font-bold px-3 py-1 rounded bg-[#10b981]/20 text-[#10b981] border border-[#10b981]/40 glow-emerald-sm">
              <CheckCircle2 className="h-3.5 w-3.5" />
              APPROVED &amp; CLEARED
            </span>
          )}
          {simulatedStatus === "REJECTED" && (
            <span className="inline-flex items-center gap-1.5 text-xs font-mono font-bold px-3 py-1 rounded bg-[#f43f5e]/20 text-[#f43f5e] border border-[#f43f5e]/40 glow-crimson-sm">
              <XCircle className="h-3.5 w-3.5" />
              CHALLENGE REJECTED &amp; LOCKED
            </span>
          )}
          {simulatedStatus === "EXPIRED" && (
            <span className="inline-flex items-center gap-1.5 text-xs font-mono font-bold px-3 py-1 rounded bg-slate-800 text-slate-400 border border-slate-700">
              <Clock className="h-3.5 w-3.5" />
              TTL EXPIRED (BLOCKED)
            </span>
          )}
        </div>
      </div>

      <div className="p-4 space-y-4 flex-1 overflow-y-auto">
        {/* Target Executive Info Banner */}
        <div className="rounded-lg bg-[#07080b]/70 border border-[#1f2433] p-3.5 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg bg-[#151923] border border-[#1f2433] flex items-center justify-center text-slate-200 font-bold font-mono text-sm shadow-inner">
              {executive.name
                .split(" ")
                .map((n) => n[0])
                .join("")}
            </div>
            <div>
              <div className="font-bold text-white text-sm">
                {executive.name} <span className="text-slate-400 text-xs font-normal">[{executive.title}]</span>
              </div>
              <div className="text-slate-400 text-[11px] mt-0.5 flex items-center gap-2 flex-wrap">
                <span>Enrolled Phone: <span className="text-slate-200 font-mono font-semibold">{executive.phoneNumber}</span></span>
                <span className="text-slate-600">&bull;</span>
                <span className="text-[#10b981] flex items-center gap-1">
                  <span className="h-1.5 w-1.5 rounded-full bg-[#10b981] shadow-[0_0_6px_#10b981]" />
                  FIDO2 / APNS Channel Enforced
                </span>
              </div>
            </div>
          </div>

          <div className="text-right">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider">Baseline Voice Embedding Hash</div>
            <div className="text-xs text-[#06b6d4] font-mono font-semibold flex items-center justify-end gap-1.5 mt-0.5">
              <span>{truncateHash(voiceHash, 10, 8)}</span>
              <button
                onClick={() => handleCopyHash(voiceHash)}
                className="text-slate-400 hover:text-white cursor-pointer"
                title="Copy Full SHA-256 Voice Hash"
              >
                {copiedHash ? <Check className="h-3 w-3 text-[#10b981]" /> : <Copy className="h-3 w-3" />}
              </button>
            </div>
          </div>
        </div>

        {/* 6-Digit Cryptographic Challenge Code Box */}
        <div className="rounded-lg bg-[#07080b] border border-[#1f2433] p-4 text-center relative overflow-hidden">
          {/* Subtle background coordinate watermark */}
          <div className="absolute right-2 top-2 text-[9px] font-mono text-slate-600 uppercase select-none">
            NONCE-SHA256 &bull; 256-BIT ENTROPY
          </div>

          <div className="flex items-center justify-center gap-2 text-xs font-mono text-slate-300 uppercase tracking-wider mb-2 font-semibold">
            <Smartphone className="h-4 w-4 text-[#06b6d4]" />
            DISPATCHED OUT-OF-BAND CHALLENGE CODE (OTP)
          </div>

          {/* Letterbox Numbers */}
          <div className="flex items-center justify-center gap-2.5 my-3.5">
            {displayCode.split("").map((digit, idx) => (
              <div
                key={idx}
                className={cn(
                  "h-12 w-10 sm:h-14 sm:w-12 rounded-lg bg-[#151923] border flex items-center justify-center text-xl sm:text-2xl font-mono font-extrabold shadow-inner transition-all duration-300 select-all",
                  simulatedStatus === "APPROVED"
                    ? "border-[#10b981] text-[#10b981] glow-emerald-sm"
                    : simulatedStatus === "REJECTED" || simulatedStatus === "EXPIRED"
                    ? "border-[#f43f5e] text-[#f43f5e] glow-crimson-sm"
                    : "border-[#06b6d4]/50 text-white shadow-[0_0_12px_rgba(6,182,212,0.15)]"
                )}
              >
                {digit}
              </div>
            ))}
          </div>

          <div className="flex items-center justify-center gap-2 text-xs font-mono text-slate-400 mt-2">
            <span>Dispatched to authentic executive device via APNS Encrypted Notification</span>
            <button
              onClick={handleCopyCode}
              className="inline-flex items-center gap-1 text-[11px] text-[#06b6d4] hover:underline cursor-pointer ml-1 font-semibold"
            >
              {copied ? <Check className="h-3 w-3 text-[#10b981]" /> : <Copy className="h-3 w-3" />}
              {copied ? "Copied" : "Copy OTP"}
            </button>
          </div>

          {/* TTL Countdown Progress Bar */}
          <div className="mt-4 pt-3 border-t border-[#1f2433]">
            <div className="flex justify-between text-[11px] font-mono text-slate-400 mb-1.5">
              <span>Challenge TTL Expiration Window</span>
              <span
                className={cn(
                  "font-bold font-mono",
                  secondsRemaining <= 15 ? "text-[#f43f5e]" : "text-[#f59e0b]"
                )}
              >
                {secondsRemaining}s Remaining
              </span>
            </div>
            <div className="w-full bg-[#151923] h-2 rounded-full overflow-hidden border border-[#1f2433]">
              <div
                className={cn(
                  "h-full transition-all duration-1000 rounded-full",
                  secondsRemaining <= 15 ? "bg-[#f43f5e] shadow-[0_0_8px_#f43f5e]" : "bg-[#f59e0b] shadow-[0_0_8px_#f59e0b]"
                )}
                style={{ width: `${(secondsRemaining / 60) * 100}%` }}
              />
            </div>
          </div>
        </div>

        {/* Manual Test Verification Form for SOC Operator */}
        <form onSubmit={handleSubmitVerify} className="rounded-lg bg-[#07080b]/60 border border-[#1f2433] p-3 space-y-2">
          <label className="block text-xs font-mono text-slate-300 font-semibold">
            SOC Verification Override (Enter Code Reported by Executive):
          </label>
          <div className="flex gap-2">
            <input
              type="text"
              maxLength={6}
              placeholder="e.g. 892415"
              value={enteredCode}
              onChange={(e) => setEnteredCode(e.target.value.replace(/\D/g, ""))}
              className="flex-1 bg-[#151923] border border-[#1f2433] rounded px-3 py-1.5 text-sm font-mono tracking-widest text-center text-white placeholder:text-slate-600 focus:outline-none focus:border-[#06b6d4] focus:shadow-[0_0_10px_rgba(6,182,212,0.25)]"
            />
            <button
              type="submit"
              disabled={isVerifying || enteredCode.length < 6}
              className="px-4 py-1.5 bg-[#06b6d4] hover:bg-[#0891b2] disabled:opacity-40 text-black text-xs font-mono font-bold rounded transition-all cursor-pointer shadow-sm glow-cyan-sm"
            >
              Verify OTP
            </button>
          </div>
        </form>

        {/* Manual SOC Override Actions */}
        <div className="pt-2 border-t border-[#1f2433] flex flex-wrap items-center justify-between gap-2">
          <button
            onClick={handleResend}
            className="px-3 py-1.5 rounded bg-[#151923] hover:bg-[#1f2433] text-slate-300 text-xs font-mono border border-[#1f2433] flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <RefreshCw className="h-3 w-3" />
            Resend Push OTP
          </button>

          <div className="flex items-center gap-2">
            <button
              onClick={handleReject}
              className="px-3.5 py-1.5 rounded bg-[#f43f5e]/15 hover:bg-[#f43f5e]/25 text-[#f43f5e] text-xs font-mono font-bold border border-[#f43f5e]/30 flex items-center gap-1.5 transition-all cursor-pointer shadow-sm"
            >
              <XCircle className="h-3.5 w-3.5" />
              Reject &amp; Arrest Wire
            </button>

            <button
              onClick={handleForceApprove}
              className="px-4 py-1.5 rounded bg-[#10b981] hover:bg-[#059669] text-black text-xs font-mono font-bold shadow-md flex items-center gap-1.5 transition-all cursor-pointer glow-emerald-sm"
            >
              <ShieldCheck className="h-3.5 w-3.5" />
              Force Dual-Authorization
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BiometricChallengeConsole;
