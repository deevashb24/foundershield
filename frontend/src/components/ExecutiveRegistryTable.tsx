"use client";

import React, { useState } from "react";
import {
  Users,
  UserPlus,
  ShieldCheck,
  ShieldAlert,
  Mic,
  DollarSign,
  Mail,
  Phone,
  Hash,
  X,
  CheckCircle2,
  AlertCircle,
  Upload,
  Copy,
  Check,
  Key,
} from "lucide-react";
import { ExecutiveDTO } from "@/types";
import { cn, formatCurrency, truncateHash } from "@/lib/utils";
import { mockExecutives } from "@/lib/mockData";

export interface EnrollExecutiveFormData {
  name: string;
  title: string;
  phoneNumber: string;
  email: string;
  wireApprovalLimitUsd: number;
  voiceBiometricEnrolled: boolean;
  voiceFingerprintHash?: string;
}

export interface ExecutiveRegistryTableProps {
  executives?: ExecutiveDTO[];
  onEnrollExecutive?: (data: EnrollExecutiveFormData) => void;
  isEnrolling?: boolean;
}

export const ExecutiveRegistryTable: React.FC<ExecutiveRegistryTableProps> = ({
  executives = mockExecutives,
  onEnrollExecutive,
  isEnrolling = false,
}) => {
  const [list, setList] = useState<ExecutiveDTO[]>(executives);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [copiedHashId, setCopiedHashId] = useState<string | null>(null);

  React.useEffect(() => {
    if (executives) {
      setList(executives);
    }
  }, [executives]);

  const [formData, setFormData] = useState<EnrollExecutiveFormData>({
    name: "",
    title: "",
    phoneNumber: "+1-",
    email: "",
    wireApprovalLimitUsd: 10000,
    voiceBiometricEnrolled: true,
    voiceFingerprintHash: "f4a8b192e4bce3e8d910a9c8f0e1329bb6d87e0fa1b2c3d4e5f60718293a7788",
  });

  const handleOpenModal = () => {
    setIsModalOpen(true);
  };

  const handleCloseModal = () => {
    setIsModalOpen(false);
  };

  const handleCopyHash = (hash: string, id: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHashId(id);
    setTimeout(() => setCopiedHashId(null), 2000);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name || !formData.email || !formData.phoneNumber) return;

    const newExec: ExecutiveDTO = {
      id: `exec-${Date.now()}`,
      name: formData.name,
      title: formData.title,
      phoneNumber: formData.phoneNumber,
      email: formData.email,
      voiceBiometricEnrolled: formData.voiceBiometricEnrolled,
      voiceFingerprintHash: formData.voiceBiometricEnrolled ? formData.voiceFingerprintHash : null,
      wireApprovalLimitUsd: formData.wireApprovalLimitUsd,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    setList((prev) => [...prev, newExec]);
    onEnrollExecutive?.(formData);
    setIsModalOpen(false);

    // Reset form
    setFormData({
      name: "",
      title: "",
      phoneNumber: "+1-",
      email: "",
      wireApprovalLimitUsd: 10000,
      voiceBiometricEnrolled: true,
      voiceFingerprintHash: "f4a8b192e4bce3e8d910a9c8f0e1329bb6d87e0fa1b2c3d4e5f60718293a7788",
    });
  };

  return (
    <div className="rounded-lg cyber-card flex flex-col h-full overflow-hidden shadow-2xl">
      {/* Header bar */}
      <div className="p-3.5 border-b border-[#1f2433] bg-[#151923]/80 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="h-6 w-6 rounded bg-[#06b6d4]/15 border border-[#06b6d4]/30 flex items-center justify-center">
            <Users className="h-3.5 w-3.5 text-[#06b6d4]" />
          </div>
          <div>
            <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white flex items-center gap-2">
              EXECUTIVE REGISTRY &amp; ZERO-TRUST WIRE APPROVAL LIMITS
              <span className="text-[10px] px-2 py-0.5 rounded bg-[#1f2433] text-slate-300 font-normal">
                {list.length} Enrolled Profiles
              </span>
            </h3>
            <p className="text-[11px] font-mono text-slate-400">
              Enrolled C-Suite Voice Fingerprint Vectors &amp; Unchallenged Banking Ceilings
            </p>
          </div>
        </div>

        <button
          onClick={handleOpenModal}
          className="px-3.5 py-1.5 rounded-lg bg-[#06b6d4] hover:bg-[#0891b2] text-black text-xs font-mono font-bold flex items-center gap-1.5 transition-all cursor-pointer shadow-md glow-cyan-sm"
        >
          <UserPlus className="h-3.5 w-3.5" />
          Enroll Executive
        </button>
      </div>

      {/* Registry Table */}
      <div className="flex-1 overflow-x-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-[#07080b]/80 border-b border-[#1f2433] text-slate-400 uppercase text-[10px]">
            <tr>
              <th className="py-3 px-4 font-semibold tracking-wider">Executive Officer</th>
              <th className="py-3 px-4 font-semibold tracking-wider">Contact Routing</th>
              <th className="py-3 px-4 font-semibold tracking-wider">Voice Biometric Status</th>
              <th className="py-3 px-4 text-right font-semibold tracking-wider">Wire Ceiling Limit</th>
              <th className="py-3 px-4 text-center font-semibold tracking-wider">Interception Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1f2433]">
            {list.map((exec) => {
              const enrolled = exec.voiceBiometricEnrolled ?? exec.voice_biometric_enrolled ?? false;
              const hash = exec.voiceFingerprintHash ?? exec.voice_fingerprint_hash;
              const limit = exec.wireApprovalLimitUsd ?? exec.wire_approval_limit_usd ?? 0;
              const phone = exec.phoneNumber ?? exec.phone_number ?? "";

              return (
                <tr key={exec.id} className="hover:bg-[#151923]/70 transition-colors">
                  {/* Executive Name & Title */}
                  <td className="py-3.5 px-4">
                    <div className="flex items-center gap-3">
                      <div className="h-8 w-8 rounded-lg bg-[#151923] border border-[#1f2433] flex items-center justify-center font-bold text-white text-xs shadow-inner">
                        {exec.name
                          .split(" ")
                          .map((n) => n[0])
                          .join("")}
                      </div>
                      <div>
                        <div className="font-bold text-white text-xs tracking-tight">{exec.name}</div>
                        <div className="text-[11px] text-slate-400">{exec.title}</div>
                      </div>
                    </div>
                  </td>

                  {/* Contact Routing */}
                  <td className="py-3.5 px-4">
                    <div className="space-y-0.5 text-[11px]">
                      <div className="text-slate-200 flex items-center gap-1.5 font-mono">
                        <Phone className="h-3 w-3 text-slate-500" />
                        {phone}
                      </div>
                      <div className="text-slate-400 flex items-center gap-1.5 font-mono">
                        <Mail className="h-3 w-3 text-slate-500" />
                        {exec.email}
                      </div>
                    </div>
                  </td>

                  {/* Voice Biometric Status */}
                  <td className="py-3.5 px-4">
                    {enrolled ? (
                      <div className="space-y-1">
                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded bg-[#10b981]/15 text-[#10b981] border border-[#10b981]/30 text-[10px] font-bold shadow-sm glow-emerald-sm">
                          <ShieldCheck className="h-3 w-3" />
                          ENROLLED (VECTOR SYNCED)
                        </span>
                        <div className="text-[10px] text-slate-400 font-mono flex items-center gap-1.5">
                          <span>SHA-256:</span>
                          <span className="text-[#06b6d4] font-semibold">{truncateHash(hash || "", 8, 6)}</span>
                          {hash && (
                            <button
                              onClick={() => handleCopyHash(hash, exec.id)}
                              className="text-slate-500 hover:text-white cursor-pointer ml-0.5"
                              title="Copy SHA-256 Voice Hash"
                            >
                              {copiedHashId === exec.id ? (
                                <Check className="h-3 w-3 text-[#10b981]" />
                              ) : (
                                <Copy className="h-3 w-3" />
                              )}
                            </button>
                          )}
                        </div>
                      </div>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded bg-[#f59e0b]/15 text-[#f59e0b] border border-[#f59e0b]/30 text-[10px] font-bold">
                        <AlertCircle className="h-3 w-3" />
                        PENDING ENROLLMENT
                      </span>
                    )}
                  </td>

                  {/* Wire Approval Limit */}
                  <td className="py-3.5 px-4 text-right">
                    <div className="text-sm font-extrabold font-mono text-white tracking-tight">
                      {formatCurrency(limit)}
                    </div>
                    <div className="text-[10px] text-slate-400">
                      Wires above this limit require OTP
                    </div>
                  </td>

                  {/* Status Badge */}
                  <td className="py-3.5 px-4 text-center">
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#06b6d4]/10 text-[#06b6d4] border border-[#06b6d4]/30 text-[10px] font-semibold">
                      <span className="h-1.5 w-1.5 rounded-full bg-[#06b6d4] shadow-[0_0_6px_#06b6d4]" />
                      ACTIVE DEFENSE
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Enroll Executive Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 animate-in fade-in duration-200">
          <div className="cyber-card-elevated border border-[#1f2433] rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4 glow-cyan-sm">
            <div className="flex items-center justify-between border-b border-[#1f2433] pb-3.5">
              <div className="flex items-center gap-2.5">
                <div className="h-7 w-7 rounded bg-[#06b6d4]/15 border border-[#06b6d4]/30 flex items-center justify-center">
                  <UserPlus className="h-4 w-4 text-[#06b6d4]" />
                </div>
                <h3 className="text-sm font-mono font-bold text-white uppercase tracking-wider">
                  Enroll Executive Profile &amp; Biometrics
                </h3>
              </div>
              <button
                onClick={handleCloseModal}
                className="text-slate-400 hover:text-white cursor-pointer transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4 text-xs font-mono">
              <div>
                <label className="block text-slate-300 mb-1.5 font-semibold">Full Legal Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Rachel Foster"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full bg-[#07080b] border border-[#1f2433] rounded px-3 py-2 text-white focus:outline-none focus:border-[#06b6d4] focus:shadow-[0_0_10px_rgba(6,182,212,0.25)] transition-all"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1.5 font-semibold">Corporate Title</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Chief Operating Officer"
                    value={formData.title}
                    onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                    className="w-full bg-[#07080b] border border-[#1f2433] rounded px-3 py-2 text-white focus:outline-none focus:border-[#06b6d4] focus:shadow-[0_0_10px_rgba(6,182,212,0.25)] transition-all"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 mb-1.5 font-semibold">Wire Ceiling Limit ($ USD)</label>
                  <input
                    type="number"
                    step="1000"
                    required
                    value={formData.wireApprovalLimitUsd}
                    onChange={(e) =>
                      setFormData({ ...formData, wireApprovalLimitUsd: Number(e.target.value) })
                    }
                    className="w-full bg-[#07080b] border border-[#1f2433] rounded px-3 py-2 text-white focus:outline-none focus:border-[#06b6d4] focus:shadow-[0_0_10px_rgba(6,182,212,0.25)] transition-all"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1.5 font-semibold">E.164 Enrolled Phone</label>
                  <input
                    type="text"
                    required
                    placeholder="+1-415-555-0100"
                    value={formData.phoneNumber}
                    onChange={(e) => setFormData({ ...formData, phoneNumber: e.target.value })}
                    className="w-full bg-[#07080b] border border-[#1f2433] rounded px-3 py-2 text-white focus:outline-none focus:border-[#06b6d4] focus:shadow-[0_0_10px_rgba(6,182,212,0.25)] transition-all"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 mb-1.5 font-semibold">Corporate Email</label>
                  <input
                    type="email"
                    required
                    placeholder="officer@vanceholdings.com"
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                    className="w-full bg-[#07080b] border border-[#1f2433] rounded px-3 py-2 text-white focus:outline-none focus:border-[#06b6d4] focus:shadow-[0_0_10px_rgba(6,182,212,0.25)] transition-all"
                  />
                </div>
              </div>

              {/* Voice Biometric Checkbox & Simulated Hash */}
              <div className="p-3.5 rounded-lg bg-[#07080b] border border-[#1f2433] space-y-2">
                <div className="flex items-center justify-between">
                  <label className="flex items-center gap-2 text-slate-200 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formData.voiceBiometricEnrolled}
                      onChange={(e) =>
                        setFormData({ ...formData, voiceBiometricEnrolled: e.target.checked })
                      }
                      className="rounded border-[#1f2433] text-[#06b6d4] focus:ring-0"
                    />
                    <span className="font-semibold">Train &amp; Enroll Reference Voice Biometric Embedding</span>
                  </label>
                  <Mic className="h-4 w-4 text-[#06b6d4]" />
                </div>
                {formData.voiceBiometricEnrolled && (
                  <div className="text-[10px] text-slate-400 font-mono">
                    Computed SHA-256 Voice Baseline Hash:
                    <div className="text-[#06b6d4] font-semibold truncate mt-0.5 select-all">
                      {formData.voiceFingerprintHash}
                    </div>
                  </div>
                )}
              </div>

              <div className="pt-3 border-t border-[#1f2433] flex justify-end gap-2.5">
                <button
                  type="button"
                  onClick={handleCloseModal}
                  className="px-3.5 py-1.5 rounded-lg bg-[#07080b] hover:bg-[#151923] text-slate-300 border border-[#1f2433] cursor-pointer transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isEnrolling}
                  className="px-4 py-1.5 rounded-lg bg-[#06b6d4] hover:bg-[#0891b2] text-black font-bold cursor-pointer transition-all shadow-md glow-cyan-sm"
                >
                  Save &amp; Enroll
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default ExecutiveRegistryTable;
