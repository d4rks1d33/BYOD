"use client";

import { useParams, useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { useState, useRef } from "react";
import { projects as projectsApi, scans as scansApi } from "@/lib/api";
import { useScanList, useStartScan, useCancelScan } from "@/hooks/useScans";
import { formatDate } from "@/lib/utils";
import Link from "next/link";
import type { Scan } from "@/types";

export default function ProjectPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [isUploading, setIsUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const { data: project, isLoading: projectLoading } = useQuery({
    queryKey: ["project", id],
    queryFn: () => projectsApi.get(id),
  });

  const { data: scanData, isLoading: scansLoading } = useScanList(id);
  const startScan = useStartScan(id);
  const cancelScan = useCancelScan(id);

  const scans = scanData?.items ?? [];
  const activeScan = scans.find((s) => s.status === "running" || s.status === "pending");

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    try {
      const result = await scansApi.uploadPostman(id, file);
      alert("Postman collection uploaded successfully! The endpoints will be used in your next scan.");
      console.log("Uploaded endpoints:", result.content);
    } catch (error: any) {
      alert(`Upload failed: ${error.message || "Unknown error"}`);
    } finally {
      setIsUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  if (projectLoading) {
    return <div className="flex items-center justify-center min-h-screen text-muted-foreground">Loading…</div>;
  }

  if (!project) {
    return <div className="flex items-center justify-center min-h-screen text-red-400">Project not found</div>;
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border px-6 py-3 flex items-center gap-3">
        <Link href="/dashboard" className="text-muted-foreground hover:text-foreground text-sm transition-colors">
          ← Dashboard
        </Link>
        <span className="text-muted-foreground">/</span>
        <span className="font-semibold">{project.name}</span>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8 space-y-8">
        {/* Project summary */}
        <div className="p-6 rounded-xl bg-secondary border border-border">
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-2xl font-bold">{project.name}</h1>
              <p className="text-muted-foreground font-mono text-sm mt-1">{project.target_url}</p>
              {project.description && (
                <p className="text-sm text-muted-foreground mt-2">{project.description}</p>
              )}
            </div>
            <div className="flex gap-3">
              <Link href={`/projects/${id}/findings`}>
                <button className="px-4 py-2 rounded-lg border border-border text-sm hover:bg-background transition-colors">
                  Findings
                </button>
              </Link>
              
              <div className="relative">
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileUpload}
                  accept=".json"
                  className="hidden"
                />
                <button
                  onClick={() => fileInputRef.current?.click()}
                  disabled={isUploading}
                  className="px-4 py-2 rounded-lg border border-border text-sm hover:bg-background transition-colors disabled:opacity-50"
                >
                  {isUploading ? "Uploading..." : "Upload Postman"}
                </button>
              </div>

              {activeScan ? (
                <button
                  onClick={() => cancelScan.mutate(activeScan.id)}
                  className="px-4 py-2 rounded-lg bg-red-700 text-white text-sm hover:bg-red-600 transition-colors"
                >
                  Cancel Scan
                </button>
              ) : (
                <button
                  onClick={() => startScan.mutate({ scan_type: "full" })}
                  disabled={startScan.isPending}
                  className="px-4 py-2 rounded-lg bg-primary text-white text-sm hover:opacity-90 disabled:opacity-50 transition-opacity"
                >
                  {startScan.isPending ? "Starting…" : "Start Scan"}
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Scans list */}
        <div>
          <h2 className="text-lg font-semibold mb-4">Scan History</h2>
          {scansLoading ? (
            <div className="text-muted-foreground text-sm">Loading scans…</div>
          ) : scans.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground border border-dashed border-border rounded-xl">
              No scans yet. Start your first scan above.
            </div>
          ) : (
            <div className="space-y-3">
              {scans.map((scan) => (
                <ScanRow key={scan.id} scan={scan} projectId={id} />
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

function ScanRow({ scan, projectId }: { scan: Scan; projectId: string }) {
  const statusColors: Record<string, string> = {
    running: "text-green-400",
    completed: "text-blue-400",
    failed: "text-red-400",
    pending: "text-yellow-400",
    cancelled: "text-gray-400",
    paused: "text-orange-400",
  };

  return (
    <Link href={`/projects/${projectId}/scans/${scan.id}`}>
      <div className="flex items-center justify-between p-4 rounded-lg bg-secondary border border-border hover:border-primary/50 transition-all cursor-pointer">
        <div className="flex items-center gap-4">
          <div className={`text-sm font-medium capitalize ${statusColors[scan.status] ?? "text-gray-400"}`}>
            {scan.status}
          </div>
          <div className="text-sm text-muted-foreground">{scan.scan_type} scan</div>
          <div className="text-xs text-muted-foreground">{formatDate(scan.created_at)}</div>
        </div>
        <div className="flex items-center gap-4 text-sm text-muted-foreground">
          {scan.statistics && (
            <span>{scan.statistics.findings_total ?? 0} findings</span>
          )}
          <span>→</span>
        </div>
      </div>
    </Link>
  );
}
