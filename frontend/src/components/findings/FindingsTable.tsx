"use client";

import { useState } from "react";
import type { Finding, SeverityLevel, FindingStatus } from "@/types";
import { cn, severityBadgeClass, formatDate, truncate } from "@/lib/utils";
import { useFindings, useVerifyFinding } from "@/hooks/useFindings";

interface FindingsTableProps {
  projectId: string;
}

const SEVERITY_OPTIONS: SeverityLevel[] = ["critical", "high", "medium", "low", "info"];
const STATUS_OPTIONS: FindingStatus[] = ["new", "verified", "false_positive", "accepted_risk", "fixed"];

export function FindingsTable({ projectId }: FindingsTableProps) {
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [page, setPage] = useState(1);

  const { data, isLoading, error } = useFindings(projectId, {
    severity: severityFilter || undefined,
    status: statusFilter || undefined,
    page,
    limit: 50,
  });

  const verify = useVerifyFinding(projectId);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-48 text-muted-foreground">
        Loading findings…
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-red-400 p-4 rounded bg-red-900/20 border border-red-800">
        Failed to load findings.
      </div>
    );
  }

  const findings = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / 50);

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <select
          value={severityFilter}
          onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
          className="bg-secondary border border-border rounded px-3 py-1.5 text-sm text-foreground"
        >
          <option value="">All Severities</option>
          {SEVERITY_OPTIONS.map((s) => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>

        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
          className="bg-secondary border border-border rounded px-3 py-1.5 text-sm text-foreground"
        >
          <option value="">All Statuses</option>
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>{s.replace("_", " ")}</option>
          ))}
        </select>

        <span className="ml-auto text-sm text-muted-foreground self-center">
          {total} finding{total !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Table */}
      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-secondary">
            <tr>
              <th className="text-left px-4 py-3 text-muted-foreground font-medium">Severity</th>
              <th className="text-left px-4 py-3 text-muted-foreground font-medium">Title</th>
              <th className="text-left px-4 py-3 text-muted-foreground font-medium hidden md:table-cell">Endpoint</th>
              <th className="text-left px-4 py-3 text-muted-foreground font-medium hidden lg:table-cell">CWE</th>
              <th className="text-left px-4 py-3 text-muted-foreground font-medium">Status</th>
              <th className="text-left px-4 py-3 text-muted-foreground font-medium hidden xl:table-cell">Found</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {findings.length === 0 ? (
              <tr>
                <td colSpan={7} className="text-center py-10 text-muted-foreground">
                  No findings match the current filters.
                </td>
              </tr>
            ) : (
              findings.map((f) => (
                <FindingRow
                  key={f.id}
                  finding={f}
                  onVerify={() => verify.mutate(f.id)}
                />
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center gap-2">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-3 py-1 rounded border border-border text-sm disabled:opacity-40 hover:bg-secondary"
          >
            Prev
          </button>
          <span className="px-3 py-1 text-sm text-muted-foreground">
            {page} / {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="px-3 py-1 rounded border border-border text-sm disabled:opacity-40 hover:bg-secondary"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}

function FindingRow({ finding, onVerify }: { finding: Finding; onVerify: () => void }) {
  return (
    <tr className="hover:bg-secondary/50 transition-colors">
      <td className="px-4 py-3">
        <span className={cn("inline-block px-2 py-0.5 rounded text-xs font-semibold uppercase", severityBadgeClass(finding.severity))}>
          {finding.severity}
        </span>
      </td>
      <td className="px-4 py-3 font-medium max-w-xs">
        <a href={`/findings/${finding.id}`} className="hover:text-primary transition-colors">
          {truncate(finding.title, 70)}
        </a>
      </td>
      <td className="px-4 py-3 hidden md:table-cell text-muted-foreground font-mono text-xs">
        {finding.endpoint ? truncate(finding.endpoint, 50) : "—"}
      </td>
      <td className="px-4 py-3 hidden lg:table-cell text-muted-foreground text-xs">
        {finding.cwe_id || "—"}
      </td>
      <td className="px-4 py-3">
        <StatusBadge status={finding.status} />
      </td>
      <td className="px-4 py-3 hidden xl:table-cell text-muted-foreground text-xs">
        {formatDate(finding.created_at)}
      </td>
      <td className="px-4 py-3">
        {finding.status === "new" && (
          <button
            onClick={onVerify}
            className="text-xs px-2 py-1 rounded border border-primary text-primary hover:bg-primary hover:text-white transition-colors"
          >
            Verify
          </button>
        )}
      </td>
    </tr>
  );
}

function StatusBadge({ status }: { status: FindingStatus }) {
  const map: Record<FindingStatus, string> = {
    new: "bg-gray-800 text-gray-300",
    verified: "bg-blue-900 text-blue-200",
    false_positive: "bg-purple-900 text-purple-200",
    accepted_risk: "bg-yellow-900 text-yellow-200",
    fixed: "bg-green-900 text-green-200",
  };
  return (
    <span className={cn("inline-block px-2 py-0.5 rounded text-xs capitalize", map[status])}>
      {status.replace("_", " ")}
    </span>
  );
}
