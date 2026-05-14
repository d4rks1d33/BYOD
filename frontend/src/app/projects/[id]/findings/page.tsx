"use client";

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { projects as projectsApi } from "@/lib/api";
import { FindingsTable } from "@/components/findings/FindingsTable";
import Link from "next/link";

export default function FindingsPage() {
  const { id } = useParams<{ id: string }>();

  const { data: project } = useQuery({
    queryKey: ["project", id],
    queryFn: () => projectsApi.get(id),
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
        <span className="font-semibold">Findings</span>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-2xl font-bold">Findings</h1>
          <div className="flex gap-3">
            <a
              href={`/api/projects/${id}/findings/export?format=csv`}
              className="px-3 py-1.5 text-sm rounded border border-border hover:bg-secondary transition-colors"
            >
              Export CSV
            </a>
            <a
              href={`/api/projects/${id}/findings/export?format=json`}
              className="px-3 py-1.5 text-sm rounded border border-border hover:bg-secondary transition-colors"
            >
              Export JSON
            </a>
          </div>
        </div>

        <FindingsTable projectId={id} />
      </main>
    </div>
  );
}
