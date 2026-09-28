"use client";

import React, { useState, useEffect, useId } from "react";
import {
  Activity,
  Play,
  Pause,
  RotateCcw,
  Volume2,
  Sliders,
  Cpu,
  Layers,
  Fingerprint,
  Info,
  CheckCircle2,
  AlertTriangle,
  ZoomIn,
  Radio,
} from "lucide-react";
import { SecurityIncidentResponse, SpectralArtifactItem } from "@/types";
import { cn } from "@/lib/utils";
import { mockIncidents } from "@/lib/mockData";

export interface AudioSpectrogramViewerProps {
  selectedIncident?: SecurityIncidentResponse | null;
  onAnalyzeNewAudio?: () => void;
}

export const AudioSpectrogramViewer: React.FC<AudioSpectrogramViewerProps> = ({
  selectedIncident = mockIncidents[0],
  onAnalyzeNewAudio,
}) => {
  const incident = selectedIncident || mockIncidents[0];
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackTime, setPlaybackTime] = useState<number>(0);
  const [selectedArtifactIndex, setSelectedArtifactIndex] = useState<number>(0);
  const [activeTab, setActiveTab] = useState<"COMPARISON" | "ARTIFACTS" | "FREQUENCY_BANDS">("COMPARISON");

  const canvasGradId = useId();

  const artifacts: SpectralArtifactItem[] =
    incident.spectralArtifactsDetected ||
    incident.spectral_artifacts_detected ||
    mockIncidents[0].spectralArtifactsDetected ||
    [];

  const confidenceScore =
    incident.deepfakeConfidenceScore ?? incident.deepfake_confidence_score ?? 98.4;

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (isPlaying) {
      interval = setInterval(() => {
        setPlaybackTime((prev) => {
          if (prev >= 4.5) {
            setIsPlaying(false);
            return 0;
          }
          return Number((prev + 0.1).toFixed(1));
        });
      }, 100);
    }
    return () => clearInterval(interval);
  }, [isPlaying]);

  return (
    <div className="rounded-lg cyber-card flex flex-col h-full overflow-hidden shadow-2xl">
      {/* Header bar */}
      <div className="p-3.5 border-b border-[#1f2433] bg-[#151923]/80 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="h-6 w-6 rounded bg-[#06b6d4]/15 border border-[#06b6d4]/30 flex items-center justify-center">
            <Activity className="h-3.5 w-3.5 text-[#06b6d4]" />
          </div>
          <div>
            <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white flex items-center gap-2">
              ACOUSTIC FORENSIC SPECTROGRAM &amp; NEURAL VOCODER ANALYSIS
            </h3>
            <p className="text-[11px] font-mono text-slate-400">
              Target: <span className="text-slate-200 font-semibold">{incident.executive?.name || "Target Executive"}</span> &bull; Incident: <span className="text-[#06b6d4] font-semibold">{incident.id.slice(0, 8)}</span>
            </p>
          </div>
        </div>

        {/* Forensic View Mode Tabs */}
        <div className="flex items-center gap-1 bg-[#07080b] p-1 rounded-lg border border-[#1f2433]">
          {(["COMPARISON", "ARTIFACTS", "FREQUENCY_BANDS"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={cn(
                "px-2.5 py-1 text-[10px] font-mono uppercase tracking-wider rounded transition-all cursor-pointer",
                activeTab === tab
                  ? "bg-[#06b6d4] text-black font-bold shadow-sm glow-cyan-sm"
                  : "text-slate-400 hover:text-slate-200"
              )}
            >
              {tab.replace("_", " ")}
            </button>
          ))}
        </div>
      </div>

      <div className="p-4 space-y-4 flex-1 overflow-y-auto">
        {/* Main Spectrogram Canvas / SVG Visualizer */}
        <div className="relative rounded-lg border border-[#1f2433] bg-[#07080b] p-3 overflow-hidden shadow-inner">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 border-b border-[#1f2433]/80 pb-2 mb-2">
            <div className="flex items-center gap-3 flex-wrap">
              <span className="flex items-center gap-1.5 text-[#f43f5e] font-semibold">
                <span className="h-2 w-2 rounded-full bg-[#f43f5e] shadow-[0_0_6px_#f43f5e] animate-pulse" />
                INTERCEPTED INBOUND AUDIO (UNENROLLED SYNTHESIS)
              </span>
              <span className="text-slate-600">vs</span>
              <span className="flex items-center gap-1.5 text-[#10b981] font-semibold">
                <span className="h-2 w-2 rounded-full bg-[#10b981] shadow-[0_0_6px_#10b981]" />
                BIOMETRIC BASELINE REFERENCE (VERIFIED ENROLLMENT)
              </span>
            </div>
            <div className="text-right">
              <span className="text-[#06b6d4] font-mono text-[10px] px-2 py-0.5 rounded bg-[#06b6d4]/10 border border-[#06b6d4]/20">
                24-BIT / 48kHz SPECTRAL FFT
              </span>
            </div>
          </div>

          {/* SVG Spectrogram Graph */}
          <div className="relative h-44 w-full">
            <svg
              className="w-full h-full"
              viewBox="0 0 600 180"
              preserveAspectRatio="none"
            >
              <defs>
                {/* Glow Filters */}
                <filter id={`${canvasGradId}-glow-cyan`} x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
                <filter id={`${canvasGradId}-glow-crimson`} x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>

                <linearGradient id={`${canvasGradId}-synthetic`} x1="0%" y1="0%" x2="0%" y2="100%">
                  <stop offset="0%" stopColor="#f43f5e" stopOpacity="0.8" />
                  <stop offset="50%" stopColor="#f59e0b" stopOpacity="0.4" />
                  <stop offset="100%" stopColor="#8b5cf6" stopOpacity="0.05" />
                </linearGradient>
                <linearGradient id={`${canvasGradId}-reference`} x1="0%" y1="0%" x2="0%" y2="100%">
                  <stop offset="0%" stopColor="#10b981" stopOpacity="0.7" />
                  <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.05" />
                </linearGradient>
                <pattern id="grid-spec" width="40" height="20" patternUnits="userSpaceOnUse">
                  <path d="M 40 0 L 0 0 0 20" fill="none" stroke="#1f2433" strokeWidth="0.6" />
                </pattern>
              </defs>

              {/* Background Coordinate Grid */}
              <rect width="600" height="180" fill="url(#grid-spec)" />

              {/* Genuine Biometric Voice Vector (Harmonic Smooth Wave) */}
              <path
                d="M 0,110 C 50,70 100,140 150,90 C 200,40 250,130 300,100 C 350,60 400,140 450,80 C 500,30 550,120 600,95 L 600,180 L 0,180 Z"
                fill={`url(#${canvasGradId}-reference)`}
                opacity="0.3"
              />
              <path
                d="M 0,110 C 50,70 100,140 150,90 C 200,40 250,130 300,100 C 350,60 400,140 450,80 C 500,30 550,120 600,95"
                fill="none"
                stroke="#10b981"
                strokeWidth="1.8"
                strokeDasharray="4 2"
              />

              {/* Inbound Intercepted Synthetic Voice (Erratic Neural Vocoder Artifacts) */}
              <path
                d="M 0,130 Q 30,120 60,60 T 120,40 T 180,140 T 240,25 T 300,110 T 360,35 T 420,130 T 480,20 T 540,80 T 600,45 L 600,180 L 0,180 Z"
                fill={`url(#${canvasGradId}-synthetic)`}
                opacity="0.45"
              />
              <path
                d="M 0,130 Q 30,120 60,60 T 120,40 T 180,140 T 240,25 T 300,110 T 360,35 T 420,130 T 480,20 T 540,80 T 600,45"
                fill="none"
                stroke="#f43f5e"
                strokeWidth="2.2"
                filter={`url(#${canvasGradId}-glow-crimson)`}
              />

              {/* Anomaly Callout Markers (Phase Discontinuity & HiFi-GAN Vocoder) */}
              {/* Marker 1: Vocoder synthesis at 1420ms (approx x=180) */}
              <g transform="translate(180, 20)">
                <line x1="0" y1="0" x2="0" y2="140" stroke="#f43f5e" strokeWidth="1" strokeDasharray="2 2" />
                <circle cx="0" cy="20" r="4" fill="#f43f5e" className="animate-ping" />
                <circle cx="0" cy="20" r="3" fill="#f43f5e" />
                <rect x="-48" y="-18" width="96" height="16" rx="3" fill="#151923" stroke="#f43f5e" strokeWidth="0.8" />
                <text x="0" y="-7" fill="#f43f5e" fontSize="8" fontFamily="monospace" textAnchor="middle" fontWeight="bold">
                  HiFi-GAN (1420ms)
                </text>
              </g>

              {/* Marker 2: Phase Discontinuity at 2100ms (approx x=280) */}
              <g transform="translate(280, 20)">
                <line x1="0" y1="0" x2="0" y2="140" stroke="#f59e0b" strokeWidth="1" strokeDasharray="2 2" />
                <circle cx="0" cy="90" r="3" fill="#f59e0b" />
                <rect x="-48" y="-18" width="96" height="16" rx="3" fill="#151923" stroke="#f59e0b" strokeWidth="0.8" />
                <text x="0" y="-7" fill="#f59e0b" fontSize="8" fontFamily="monospace" textAnchor="middle" fontWeight="bold">
                  Phase Cut (2100ms)
                </text>
              </g>

              {/* Marker 3: Robotic pitch jitter at 3150ms (approx x=420) */}
              <g transform="translate(420, 20)">
                <line x1="0" y1="0" x2="0" y2="140" stroke="#8b5cf6" strokeWidth="1" strokeDasharray="2 2" />
                <circle cx="0" cy="110" r="3" fill="#8b5cf6" />
                <rect x="-48" y="-18" width="96" height="16" rx="3" fill="#151923" stroke="#8b5cf6" strokeWidth="0.8" />
                <text x="0" y="-7" fill="#8b5cf6" fontSize="8" fontFamily="monospace" textAnchor="middle" fontWeight="bold">
                  0.8Hz Jitter (3150ms)
                </text>
              </g>

              {/* Real-time playback cursor with glowing head */}
              <g transform={`translate(${(playbackTime / 4.5) * 600}, 0)`}>
                <line
                  x1="0"
                  y1="0"
                  x2="0"
                  y2="180"
                  stroke="#06b6d4"
                  strokeWidth="2"
                  filter={`url(#${canvasGradId}-glow-cyan)`}
                />
                <circle cx="0" cy="10" r="3" fill="#06b6d4" />
              </g>
            </svg>

            {/* Frequency Axis Labels (Hz) */}
            <div className="absolute left-1.5 top-2 bottom-2 flex flex-col justify-between text-[9px] font-mono text-slate-500 pointer-events-none select-none">
              <span>8000 Hz</span>
              <span>4000 Hz</span>
              <span>2000 Hz</span>
              <span>500 Hz</span>
              <span>0 Hz</span>
            </div>

            {/* Time Axis Labels (s) */}
            <div className="absolute bottom-1 left-12 right-2 flex justify-between text-[9px] font-mono text-slate-500 pointer-events-none select-none">
              <span>0.0s</span>
              <span>1.0s</span>
              <span>2.0s</span>
              <span>3.0s</span>
              <span>4.0s</span>
              <span>4.5s</span>
            </div>
          </div>

          {/* Audio Controls Bar */}
          <div className="mt-3 pt-2.5 border-t border-[#1f2433] flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <button
                onClick={() => setIsPlaying(!isPlaying)}
                className="h-8 w-8 rounded-lg bg-[#06b6d4] hover:bg-[#0891b2] text-black flex items-center justify-center transition-all cursor-pointer font-bold shadow-md glow-cyan-sm"
                title={isPlaying ? "Pause Forensic Playback" : "Play Forensic Sample"}
              >
                {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4 ml-0.5" />}
              </button>
              <button
                onClick={() => {
                  setIsPlaying(false);
                  setPlaybackTime(0);
                }}
                className="h-8 w-8 rounded-lg bg-[#151923] hover:bg-[#1f2433] text-slate-300 flex items-center justify-center border border-[#1f2433] transition-colors cursor-pointer"
                title="Reset Scrub Position"
              >
                <RotateCcw className="h-3.5 w-3.5" />
              </button>
              <span className="text-xs font-mono text-slate-300 pl-1.5">
                <span className="font-bold text-white">{playbackTime.toFixed(1)}s</span>{" "}
                <span className="text-slate-500">/ 4.5s</span>
              </span>
            </div>

            <div className="flex items-center gap-3">
              <span className="text-[11px] font-mono text-slate-400">
                Acoustic Distance: <span className="text-[#f43f5e] font-bold font-mono">d = 0.892 (THRESHOLD EXCEEDED)</span>
              </span>
              <span className="text-[11px] font-mono px-2.5 py-0.5 rounded bg-[#f43f5e]/15 text-[#f43f5e] border border-[#f43f5e]/30 font-bold glow-crimson-sm">
                CONFIDENCE: {confidenceScore.toFixed(1)}% SYNTHETIC
              </span>
            </div>
          </div>
        </div>

        {/* Tab Content 1: COMPARISON STATS */}
        {activeTab === "COMPARISON" && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="p-3.5 rounded-lg bg-[#07080b]/60 border border-[#1f2433] transition-all hover:border-[#f43f5e]/40">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="uppercase text-[11px] font-semibold text-slate-300">Phase Discontinuity</span>
                <span className="text-[#f43f5e] font-bold font-mono">94.1%</span>
              </div>
              <p className="text-[11px] text-slate-300 mt-1.5 font-mono leading-relaxed">
                Boundary stitching anomalies detected in <span className="text-white font-semibold">2500Hz - 4800Hz</span> phoneme transitions.
              </p>
              <div className="mt-2.5 w-full bg-[#151923] h-1.5 rounded-full overflow-hidden border border-[#1f2433]">
                <div className="bg-[#f43f5e] h-full shadow-[0_0_6px_#f43f5e]" style={{ width: "94.1%" }} />
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#07080b]/60 border border-[#1f2433] transition-all hover:border-[#f59e0b]/40">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="uppercase text-[11px] font-semibold text-slate-300">Robotic Pitch Jitter</span>
                <span className="text-[#f59e0b] font-bold font-mono">89.7%</span>
              </div>
              <p className="text-[11px] text-slate-300 mt-1.5 font-mono leading-relaxed">
                Fundamental frequency jitter std-dev suppressed to <span className="text-white font-semibold">0.8 Hz</span> (Human baseline: 4.2 Hz).
              </p>
              <div className="mt-2.5 w-full bg-[#151923] h-1.5 rounded-full overflow-hidden border border-[#1f2433]">
                <div className="bg-[#f59e0b] h-full shadow-[0_0_6px_#f59e0b]" style={{ width: "89.7%" }} />
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#07080b]/60 border border-[#1f2433] transition-all hover:border-[#8b5cf6]/40">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="uppercase text-[11px] font-semibold text-slate-300">Neural Vocoder Footprint</span>
                <span className="text-[#8b5cf6] font-bold font-mono">98.4%</span>
              </div>
              <p className="text-[11px] text-slate-300 mt-1.5 font-mono leading-relaxed">
                Matches HiFi-GAN / ElevenLabs-v2 synthetic harmonic resynthesis envelope.
              </p>
              <div className="mt-2.5 w-full bg-[#151923] h-1.5 rounded-full overflow-hidden border border-[#1f2433]">
                <div className="bg-[#8b5cf6] h-full shadow-[0_0_6px_#8b5cf6]" style={{ width: "98.4%" }} />
              </div>
            </div>
          </div>
        )}

        {/* Tab Content 2: DETECTED ARTIFACTS LIST */}
        {activeTab === "ARTIFACTS" && (
          <div className="space-y-2">
            {artifacts.map((artifact, idx) => (
              <div
                key={idx}
                className="p-3 rounded-lg bg-[#07080b]/70 border border-[#1f2433] flex items-start justify-between gap-3 text-xs font-mono transition-all hover:border-[#2c3347]"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-white uppercase">{artifact.type.replace(/_/g, " ")}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#1f2433] text-slate-300 font-mono">
                      Band: {artifact.frequencyBandHz || artifact.frequency_band_hz || "Full spectrum"}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#1f2433] text-slate-300 font-mono">
                      Offset: {artifact.timestampOffsetMs || artifact.timestamp_offset_ms || 0}ms
                    </span>
                  </div>
                  <p className="text-slate-400 mt-1 text-[11px] leading-relaxed">
                    {artifact.description}
                  </p>
                </div>
                <div className="text-right shrink-0">
                  <span className="text-xs font-extrabold font-mono text-[#f43f5e] bg-[#f43f5e]/10 px-2 py-0.5 rounded border border-[#f43f5e]/30">
                    {artifact.confidence.toFixed(1)}% match
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Tab Content 3: FREQUENCY BANDS TELEMETRY */}
        {activeTab === "FREQUENCY_BANDS" && (
          <div className="p-3.5 rounded-lg bg-[#07080b]/60 border border-[#1f2433] font-mono text-xs space-y-2.5">
            <div className="flex justify-between text-slate-400 border-b border-[#1f2433] pb-2 text-[10px] font-semibold uppercase tracking-wider">
              <span>BAND PROFILE</span>
              <span>SPECTRAL ENERGY</span>
              <span className="text-right">SYNTHETIC PROBABILITY</span>
            </div>
            {[
              { band: "0Hz - 500Hz (Sub-bass / Formant F0)", energy: "-14 dBFS", synth: "89.2% (Frozen micro-tremor)", color: "text-[#f59e0b]" },
              { band: "500Hz - 2000Hz (Formants F1 & F2)", energy: "-8 dBFS", synth: "76.4% (Robotic prosody)", color: "text-[#f59e0b]" },
              { band: "2000Hz - 4800Hz (Consonant treble)", energy: "-22 dBFS", synth: "94.1% (Phase cancellation)", color: "text-[#f43f5e]" },
              { band: "4800Hz - 8000Hz (Vocoder harmonics)", energy: "-31 dBFS", synth: "98.4% (HiFi-GAN artifact)", color: "text-[#f43f5e]" },
            ].map((row, idx) => (
              <div key={idx} className="flex justify-between items-center py-1 text-[11px] text-slate-300">
                <span className="text-slate-200 font-mono">{row.band}</span>
                <span className="text-slate-400 font-mono">{row.energy}</span>
                <span className={cn("font-bold font-mono text-right", row.color)}>{row.synth}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default AudioSpectrogramViewer;
