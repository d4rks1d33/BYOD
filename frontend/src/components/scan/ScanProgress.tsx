"use client";

import { cn } from "@/lib/utils";
import type { ScanStatus } from "@/types";

interface ScanProgressProps {
  status: ScanStatus;
  progress: number;
  phase: string;
}

const PHASES = ["recon", "dast", "sast", "correlation", "report"];

export function ScanProgress({ status, progress, phase }: ScanProgressProps) {
  const isRunning = status === "running";
  const isFailed = status === "failed";
  const isDone = status === "completed";

  const currentPhaseIdx = PHASES.indexOf(phase.toLowerCase());

  return (
    <div className="space-y-4 p-4 bg-secondary rounded-lg border border-border">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {isRunning && (
            <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          )}
          {isFailed && (
            <span className="w-2 h-2 rounded-full bg-red-500" />
          )}
          {isDone && (
            <span className="w-2 h-2 rounded-full bg-blue-400" />
          )}
          <span className="text-sm font-medium capitalize">{status}</span>
          {phase && (
            <span className="text-xs text-muted-foreground">— {phase}</span>
          )}
        </div>
        <span className="text-sm text-muted-foreground">{Math.round(progress)}%</span>
      </div>

      {/* Progress bar */}
      <div className="h-1.5 bg-muted rounded-full overflow-hidden">
        <div
          className={cn(
            "h-full rounded-full transition-all duration-500",
            isFailed ? "bg-red-500" : isDone ? "bg-blue-500" : "bg-primary"
          )}
          style={{ width: `${Math.max(2, progress)}%` }}
        />
      </div>

      {/* Phase stepper */}
      <div className="flex justify-between">
        {PHASES.map((p, idx) => (
          <div key={p} className="flex flex-col items-center gap-1">
            <div
              className={cn(
                "w-6 h-6 rounded-full border-2 flex items-center justify-center text-xs",
                idx < currentPhaseIdx
                  ? "border-primary bg-primary text-white"
                  : idx === currentPhaseIdx && isRunning
                  ? "border-primary text-primary animate-pulse"
                  : "border-muted text-muted-foreground"
              )}
            >
              {idx < currentPhaseIdx ? "✓" : idx + 1}
            </div>
            <span className="text-xs text-muted-foreground capitalize hidden sm:block">{p}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
