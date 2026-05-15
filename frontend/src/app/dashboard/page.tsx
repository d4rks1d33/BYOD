"use client";

import { useQuery } from "@tanstack/react-query";
import { projects as api } from "@/lib/api";
import { useAuthStore } from "@/stores/auth";
import { formatDate } from "@/lib/utils";
import { TargetType } from "@/types";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, useEffect } from "react";

export default function DashboardPage() {
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);
  const router = useRouter();

  // Redirect to login if not authenticated
  useEffect(() => {
    if (typeof window !== "undefined") {
      const token = localStorage.getItem("ap_access_token");
      if (!token) {
        router.push("/login");
      }
    }
  }, [router]);

  const { data: projectList, isLoading } = useQuery({
    queryKey: ["projects"],
    queryFn: api.list,
  });

  function handleLogout() {
    logout();
    router.push("/login");
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Nav */}
      <header className="border-b border-border px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-lg font-bold text-foreground">AutoPentest</span>
          <span className="text-xs bg-primary/20 text-primary px-2 py-0.5 rounded-full">
            AI Security
          </span>
        </div>
        <div className="flex items-center gap-4">
          <Link
            href="/dashboard/ai-settings"
            className="text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            🤖 AI Models
          </Link>
          <span className="text-sm text-muted-foreground">{user?.email}</span>
          <button
            onClick={handleLogout}
            className="text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            Sign out
          </button>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8 space-y-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Projects</h1>
            <p className="text-muted-foreground text-sm mt-0.5">Manage your security assessments</p>
          </div>
          <NewProjectButton onCreated={() => router.refresh()} />
        </div>

        {isLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="h-40 rounded-xl bg-secondary border border-border animate-pulse" />
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {(projectList?.items ?? []).map((p) => (
              <Link key={p.id} href={`/projects/${p.id}`}>
                <div className="h-full p-5 rounded-xl bg-secondary border border-border hover:border-primary/50 hover:bg-secondary/80 transition-all cursor-pointer group">
                  <div className="flex items-start justify-between mb-3">
                    <h3 className="font-semibold group-hover:text-primary transition-colors line-clamp-1">
                      {p.name}
                    </h3>
                    <StatusDot status={p.status} />
                  </div>
                  <p className="text-sm text-muted-foreground font-mono truncate mb-3">
                    {p.target_url}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    Created {formatDate(p.created_at)}
                  </p>
                </div>
              </Link>
            ))}

            {(projectList?.items ?? []).length === 0 && (
              <div className="col-span-3 text-center py-16 text-muted-foreground">
                No projects yet. Create your first security assessment.
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}

function StatusDot({ status }: { status: string }) {
  const color = status === "active" ? "bg-green-500" : status === "archived" ? "bg-gray-500" : "bg-yellow-500";
  return <span className={`w-2 h-2 rounded-full ${color}`} />;
}

function NewProjectButton({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [targetType, setTargetType] = useState<TargetType>("web_application");
  const [description, setDescription] = useState("");
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [collectionUrl, setCollectionUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const config: any = {};
      if (targetType === "repository" && repositoryUrl) {
        config.repository_url = repositoryUrl;
      }
      if ((targetType === "rest_api" || targetType === "graphql_api") && collectionUrl) {
        config.collection_url = collectionUrl;
      }

      await api.create({
        name,
        target_url: url,
        target_type: targetType,
        description: description || undefined,
        config: Object.keys(config).length > 0 ? config : undefined,
      });
      setOpen(false);
      setName("");
      setUrl("");
      setTargetType("web_application");
      setDescription("");
      setRepositoryUrl("");
      setCollectionUrl("");
      onCreated();
    } catch (err: any) {
      setError(err.detail?.message || err.message || "Failed to create project");
    } finally {
      setLoading(false);
    }
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="px-4 py-2 rounded-lg bg-primary text-white text-sm font-medium hover:opacity-90 transition-opacity"
      >
        + New Project
      </button>
    );
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={() => !loading && setOpen(false)}>
      <form
        onSubmit={create}
        onClick={(e) => e.stopPropagation()}
        className="bg-secondary rounded-xl border border-border p-6 w-full max-w-md space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto"
      >
        <h2 className="text-lg font-semibold">New Project</h2>

        {error && (
          <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-3 text-sm text-red-400">
            {error}
          </div>
        )}

        <div>
          <label className="block text-sm mb-1.5">Project Name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} required
            className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-primary" />
        </div>

        <div>
          <label className="block text-sm mb-1.5">Target Type</label>
          <select value={targetType} onChange={(e) => setTargetType(e.target.value as TargetType)}
            className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-primary">
            <option value="web_application">Web Application</option>
            <option value="rest_api">REST API</option>
            <option value="graphql_api">GraphQL API</option>
            <option value="repository">Code Repository (SAST)</option>
            <option value="mobile_backend">Mobile Backend</option>
          </select>
        </div>

        <div>
          <label className="block text-sm mb-1.5">
            {targetType === "repository" ? "Repository URL" : "Target URL"}
          </label>
          <input value={url} onChange={(e) => setUrl(e.target.value)} required type="url"
            placeholder={
              targetType === "repository"
                ? "https://github.com/user/repo"
                : "https://target.example.com"
            }
            className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-primary font-mono text-sm" />
        </div>

        {targetType === "repository" && (
          <div className="text-xs text-muted-foreground bg-blue-500/10 border border-blue-500/30 rounded-lg p-2">
            For private repositories, configure Git credentials in project settings after creation.
          </div>
        )}

        {(targetType === "rest_api" || targetType === "graphql_api") && (
          <div>
            <label className="block text-sm mb-1.5">
              API Collection URL (Optional)
              <span className="text-xs text-muted-foreground ml-2">Postman/OpenAPI link</span>
            </label>
            <input value={collectionUrl} onChange={(e) => setCollectionUrl(e.target.value)}
              type="url"
              placeholder="https://api.example.com/openapi.json"
              className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-primary font-mono text-sm" />
          </div>
        )}

        <div>
          <label className="block text-sm mb-1.5">Description (Optional)</label>
          <textarea value={description} onChange={(e) => setDescription(e.target.value)}
            rows={2}
            placeholder="Brief description of this security assessment"
            className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-primary resize-none" />
        </div>

        <div className="flex gap-3 justify-end pt-2">
          <button type="button" onClick={() => setOpen(false)} disabled={loading}
            className="px-4 py-2 text-sm rounded-lg border border-border hover:bg-background transition-colors disabled:opacity-50">
            Cancel
          </button>
          <button type="submit" disabled={loading}
            className="px-4 py-2 text-sm rounded-lg bg-primary text-white hover:opacity-90 disabled:opacity-50 transition-opacity">
            {loading ? "Creating…" : "Create"}
          </button>
        </div>
      </form>
    </div>
  );
}
