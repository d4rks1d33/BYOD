"use client";

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { projects as projectsApi } from "@/lib/api";
import { useFinding } from "@/hooks/useFindings";
import { formatDate } from "@/lib/utils";
import Link from "next/link";
import { 
  ArrowLeft, 
  AlertCircle, 
  Code, 
  ExternalLink, 
  FileCode, 
  Info, 
  ShieldAlert, 
  ShieldCheck, 
  Terminal, 
  Zap 
} from "lucide-react";
import { cn } from "@/lib/utils";

export default function FindingDetailPage() {
  const { id: projectId, findingId } = useParams<{ id: string; findingId: string }>();

  const { data: project, isLoading: projectLoading } = useQuery({
    queryKey: ["project", projectId],
    queryFn: () => projectsApi.get(projectId!),
  });

  const { data: finding, isLoading: findingLoading } = useFinding(findingId!);

  if (projectLoading || findingLoading) {
    return <div className="flex items-center justify-center min-h-screen text-muted-foreground">Loading…</div>;
  }

  if (!project || !finding) {
    return <div className="flex items-center justify-center min-h-screen text-red-400">Finding not found</div>;
  }

  const SEVERITY_COLORS: Record<string, string> = {
    critical: "bg-red-500/10 text-red-500 border-red-500/20",
    high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    low: "bg-blue-500/10 text-blue-500 border-blue-500/20",
    info: "bg-gray-500/10 text-gray-500 border-gray-500/20",
  };
  const severityColor = SEVERITY_COLORS[finding.severity] || SEVERITY_COLORS.info;

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border px-6 py-3 flex items-center gap-3">
        <Link href={`/projects/${projectId}/findings`} className="text-muted-foreground hover:text-foreground text-sm transition-colors">
          <div className="flex items-center gap-1">
            <ArrowLeft className="w-4 h-4" />
            Back to Findings
          </div>
        </Link>
        <span className="text-muted-foreground">/</span>
        <span className="font-semibold">{project.name}</span>
        <span className="text-muted-foreground">/</span>
        <span className="font-semibold text-primary">Finding Details</span>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-8 space-y-8">
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <span className={cn("px-2.5 py-0.5 rounded-full text-xs font-bold uppercase border", severityColor)}>
              {finding.severity}
            </span>
            <h1 className="text-3xl font-bold tracking-tight">{finding.title}</h1>
          </div>
          <div className="flex items-center gap-2 text-muted-foreground text-sm">
            <Terminal className="w-4 h-4" />
            <code className="bg-secondary px-1.5 py-0.5 rounded">{finding.endpoint || "No endpoint"}</code>
            {finding.parameter && (
              <>
                <span className="text-muted-foreground">|</span>
                <span className="text-primary font-medium">param: {finding.parameter}</span>
              </>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-6">
            <div className="p-4 rounded-xl bg-card border border-border shadow-sm">
              <div className="flex items-center gap-2 mb-3 text-primary font-semibold">
                <Info className="w-4 h-4" />
                <h3>Description</h3>
              </div>
              <p className="text-sm text-muted-foreground leading-relaxed">
                {finding.description || "No description provided."}
              </p>
            </div>

            <div className="p-4 rounded-xl bg-card border border-border shadow-sm">
              <div className="flex items-center gap-2 mb-3 text-primary font-semibold">
                <ShieldAlert className="w-4 h-4" />
                <h3>Impact</h3>
              </div>
              <p className="text-sm text-muted-foreground leading-relaxed">
                {finding.impact || "No impact description provided."}
              </p>
            </div>
          </div>

          <div className="space-y-6">
            <div className="p-4 rounded-xl bg-card border border-border shadow-sm">
              <div className="flex items-center gap-2 mb-3 text-primary font-semibold">
                <Zap className="w-4 h-4" />
                <h3>Vulnerability Details</h3>
              </div>
              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">CWE ID</span>
                  <span className="font-mono font-medium">{finding.cwe_id || "N/A"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">CVSS Score</span>
                  <span className="font-medium">{finding.cvss_score?.toFixed(1) || "N/A"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Detected At</span>
                  <span className="text-muted-foreground">{formatDate(finding.created_at)}</span>
                </div>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-card border border-border shadow-sm">
              <div className="flex items-center gap-2 mb-3 text-primary font-semibold">
                <Code className="w-4 h-4" />
                <h3>Payload</h3>
              </div>
              <div className="bg-black/50 rounded p-3 font-mono text-xs text-green-400 overflow-x-auto">
                {finding.payload ? finding.payload : "No payload provided."}
              </div>
            </div>
          </div>
        </div>

        {finding.evidence && finding.evidence.length > 0 && (
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-primary font-semibold">
              <FileCode className="w-4 h-4" />
              <h3>Evidence</h3>
            </div>
            <div className="space-y-4">
              {finding.evidence.map((ev, idx) => (
                <div key={idx} className="p-4 rounded-xl bg-black/50 border border-border font-mono text-xs text-muted-foreground overflow-x-auto whitespace-pre-wrap">
                  {ev.http_request && (
                    <>
                      <div className="text-blue-400 mb-2 font-bold">REQUEST:</div>
                      <div className="mb-4">{ev.http_request}</div>
                    </>
                  )}
                  {ev.http_response && (
                    <>
                      <div className="text-green-400 mb-2 font-bold">RESPONSE:</div>
                      <div>{ev.http_response}</div>
                    </>
                  )}
                  {ev.payload && (
                    <>
                      <div className="text-yellow-400 mb-2 font-bold">PAYLOAD:</div>
                      <div>{ev.payload}</div>
                    </>
                  )}
                  {ev.tool_output && (
                    <>
                      <div className="text-purple-400 mb-2 font-bold">TOOL OUTPUT:</div>
                      <div>{ev.tool_output}</div>
                    </>
                  )}
                  {ev.screenshot_path && (
                    <>
                      <div className="text-pink-400 mb-2 font-bold">SCREENSHOT:</div>
                      <div className="text-xs italic">{ev.screenshot_path}</div>
                    </>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {finding.reproduction_steps && finding.reproduction_steps.length > 0 && (
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-primary font-semibold">
              <ShieldCheck className="w-4 h-4" />
              <h3>Reproduction Steps</h3>
            </div>
            <ol className="list-decimal list-inside space-y-2 text-sm text-muted-foreground">
              {finding.reproduction_steps.map((step, idx) => (
                <li key={idx}>{step}</li>
              ))}
            </ol>
          </div>
        )}

        {finding.remediation && (
          <div className="p-6 rounded-xl bg-green-500/5 border border-green-500/20 space-y-3">
            <div className="flex items-center gap-2 text-green-600 font-semibold">
              <ShieldCheck className="w-4 h-4" />
              <h3>Remediation</h3>
            </div>
            <p className="text-sm text-muted-foreground leading-relaxed">
              {finding.remediation}
            </p>
          </div>
        )}
      </main>
    </div>
  );
}
