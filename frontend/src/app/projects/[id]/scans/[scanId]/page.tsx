"use client";

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { projects as projectsApi, scans as scansApi } from "@/lib/api";
import { useScan } from "@/hooks/useScans";
import { useWebSocket } from "@/hooks/useWebSocket";
import { useScanStore } from "@/stores/scan";
import { ScanProgress } from "@/components/scan/ScanProgress";
import { ScanTerminal } from "@/components/scan/ScanTerminal";
import Link from "next/link";
import { useEffect, useMemo } from "react";
import type { WSScanEvent } from "@/types";

export default function ScanDetailPage() {
  const { id, scanId } = useParams<{ id: string; scanId: string }>();

  const { data: project } = useQuery({
    queryKey: ["project", id],
    queryFn: () => projectsApi.get(id),
  });

  const { data: scan } = useScan(scanId);

  const { scanLogs, progress, phase, handleWsEvent, setActiveScan, clearLogs } = useScanStore();

  useEffect(() => {
    if (scan) setActiveScan(scan);
    return () => clearLogs();
  }, [scan, setActiveScan, clearLogs]);

  const isLive = scan?.status === "running" || scan?.status === "pending" || scan?.status === "queued";

  // Fetch persisted logs from Redis stream
  const { data: logsData } = useQuery({
    queryKey: ["scan-logs", scanId],
    queryFn: () => scansApi.logs(scanId, 1000),
    enabled: !!scanId,
    refetchInterval: isLive ? 2000 : false,
  });

  // Format persisted logs and merge with live ws logs
  const formattedLogs = useMemo(() => {
    const persisted: string[] = (logsData?.logs ?? []).map((log) => {
      const time = log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : "";
      const levelColor =
        log.level === "ERROR" ? "\x1b[31m" :
        log.level === "WARN" ? "\x1b[33m" :
        log.level === "INFO" ? "\x1b[36m" : "\x1b[37m";
      return `\x1b[90m[${time}]\x1b[0m ${levelColor}[${log.level}]\x1b[0m \x1b[35m[${log.agent}]\x1b[0m ${log.message}`;
    });
    return [...persisted, ...scanLogs];
  }, [logsData, scanLogs]);

  useWebSocket({
    projectId: id,
    onEvent: (event: WSScanEvent) => handleWsEvent(event),
    enabled: isLive,
  });

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border px-6 py-3 flex items-center gap-3">
        <Link href="/dashboard" className="text-muted-foreground hover:text-foreground text-sm transition-colors">
          ← Dashboard
        </Link>
        <span className="text-muted-foreground">/</span>
        <Link href={`/projects/${id}`} className="text-muted-foreground hover:text-foreground text-sm transition-colors">
          {project?.name ?? "Project"}
        </Link>
        <span className="text-muted-foreground">/</span>
        <span className="font-semibold">Scan</span>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8 space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Scan Details</h1>
          {scan && (
            <span className={`text-sm px-3 py-1 rounded-full border ${
              scan.status === "running" ? "border-green-700 text-green-400 bg-green-900/20" :
              scan.status === "completed" ? "border-blue-700 text-blue-400 bg-blue-900/20" :
              scan.status === "failed" ? "border-red-700 text-red-400 bg-red-900/20" :
              "border-border text-muted-foreground"
            }`}>
              {scan.status}
            </span>
          )}
        </div>

        {scan && (
          <ScanProgress
            status={scan.status}
            progress={isLive ? progress : (scan.status === "completed" ? 100 : progress)}
            phase={phase || ""}
          />
        )}

        {/* Stats */}
        {scan?.statistics && (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {[
              { label: "Critical", value: scan.statistics.findings_critical ?? 0, color: "text-red-400" },
              { label: "High", value: scan.statistics.findings_high ?? 0, color: "text-orange-400" },
              { label: "Medium", value: scan.statistics.findings_medium ?? 0, color: "text-yellow-400" },
              { label: "Low", value: scan.statistics.findings_low ?? 0, color: "text-green-400" },
              { label: "Endpoints", value: scan.statistics.endpoints_discovered ?? 0, color: "text-blue-400" },
            ].map(({ label, value, color }) => (
              <div key={label} className="p-4 rounded-lg bg-secondary border border-border text-center">
                <div className={`text-2xl font-bold ${color}`}>{value}</div>
                <div className="text-xs text-muted-foreground mt-1">{label}</div>
              </div>
            ))}
          </div>
        )}

        {/* Live terminal */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
              Scan Output {isLive && <span className="text-green-400 ml-2">● Live</span>}
            </h2>
            {scan?.status === "completed" && (
              <Link
                href={`/projects/${id}/findings`}
                className="text-sm text-primary hover:underline"
              >
                View Findings →
              </Link>
            )}
          </div>
          <ScanTerminal logs={formattedLogs} height={500} />
        </div>
      </main>
    </div>
  );
}
