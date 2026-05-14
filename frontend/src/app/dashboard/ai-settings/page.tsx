"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { aiModels as api } from "@/lib/api";
import type { AIModelConfig } from "@/types";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/stores/auth";

type Provider = "gemini" | "openai" | "anthropic" | "ollama" | "vllm" | "llamacpp" | "openrouter";

interface ProviderInfo {
  id: Provider;
  label: string;
  description: string;
  needsApiKey: boolean;
  needsUrl?: "ollama_host" | "vllm_base_url" | null;
  needsGgufPath?: boolean;
  defaultModels: string[];
  icon: string;
}

const PROVIDERS: ProviderInfo[] = [
  {
    id: "gemini",
    label: "Google Gemini",
    description: "Gemini 2.5 Flash / Pro — fast and powerful",
    needsApiKey: true,
    defaultModels: ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash-exp"],
    icon: "✨",
  },
  {
    id: "openai",
    label: "OpenAI",
    description: "GPT-4o, GPT-4o-mini — excellent at reasoning",
    needsApiKey: true,
    defaultModels: ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"],
    icon: "🤖",
  },
  {
    id: "anthropic",
    label: "Anthropic Claude",
    description: "Claude 3.5 Sonnet — great at analysis",
    needsApiKey: true,
    defaultModels: ["claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022", "claude-3-opus-20240229"],
    icon: "🧠",
  },
  {
    id: "ollama",
    label: "Ollama (Local)",
    description: "Run local models like Llama, Mistral, CodeLlama",
    needsApiKey: false,
    needsUrl: "ollama_host",
    defaultModels: ["llama3.1:8b", "llama3.1:70b", "codellama:13b", "mistral:7b"],
    icon: "🦙",
  },
  {
    id: "vllm",
    label: "vLLM (Local)",
    description: "High-throughput local model serving",
    needsApiKey: false,
    needsUrl: "vllm_base_url",
    defaultModels: ["meta-llama/Llama-3.1-8B-Instruct"],
    icon: "⚡",
  },
  {
    id: "llamacpp",
    label: "Local .gguf",
    description: "Run any .gguf model directly via llama.cpp",
    needsApiKey: false,
    needsGgufPath: true,
    defaultModels: ["custom"],
    icon: "📦",
  },
  {
    id: "openrouter",
    label: "OpenRouter",
    description: "Access thousands of models with one API",
    needsApiKey: true,
    defaultModels: [
      "meta-llama/llama-3.1-8b-instruct", 
      "google/gemini-2.5-flash", 
      "anthropic/claude-3.5-sonnet"
    ],
    icon: "🌀",
  },
];

export default function AISettingsPage() {
  const router = useRouter();
  const user = useAuthStore((s) => s.user);
  const qc = useQueryClient();

  const { data: models, isLoading } = useQuery({
    queryKey: ["ai-models"],
    queryFn: api.list,
  });

  const activateMutation = useMutation({
    mutationFn: (id: string) => api.activate(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ai-models"] }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ai-models"] }),
  });

  const [addOpen, setAddOpen] = useState(false);

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link href="/dashboard" className="text-muted-foreground hover:text-foreground text-sm transition-colors">
            ← Dashboard
          </Link>
          <span className="text-muted-foreground">/</span>
          <span className="font-semibold">AI Settings</span>
        </div>
        <span className="text-sm text-muted-foreground">{user?.email}</span>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-8 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">AI Model Configuration</h1>
            <p className="text-muted-foreground text-sm mt-0.5">
              Choose which LLM will power your security audits
            </p>
          </div>
          <button
            onClick={() => setAddOpen(true)}
            className="px-4 py-2 rounded-lg bg-primary text-white text-sm font-medium hover:opacity-90 transition-opacity"
          >
            + Add Model
          </button>
        </div>

        <div className="rounded-lg border border-blue-500/30 bg-blue-500/10 p-4 text-sm">
          <div className="font-medium text-blue-300 mb-1">💡 How it works</div>
          <div className="text-muted-foreground">
            Configure one or more LLM providers below. The system will use the <b>active</b> model
            during scans, with automatic fallback to others if one fails. For .gguf models, place
            the file in <code className="bg-secondary px-1 rounded">./models/</code> directory
            before building Docker.
          </div>
        </div>

        {isLoading ? (
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-24 rounded-lg bg-secondary border border-border animate-pulse" />
            ))}
          </div>
        ) : (
          <div className="space-y-3">
            {(models ?? []).length === 0 ? (
              <div className="text-center py-16 text-muted-foreground border border-dashed border-border rounded-lg">
                <div className="text-4xl mb-3">🤖</div>
                <p className="mb-2">No AI models configured yet</p>
                <p className="text-xs">Click &quot;Add Model&quot; to set up your first LLM</p>
              </div>
            ) : (
              (models ?? []).map((model) => (
                <ModelCard
                  key={model.id}
                  model={model}
                  onActivate={() => activateMutation.mutate(model.id)}
                  onDelete={() => {
                    if (confirm(`Delete "${model.name}"?`)) {
                      deleteMutation.mutate(model.id);
                    }
                  }}
                  activating={activateMutation.isPending}
                />
              ))
            )}
          </div>
        )}
      </main>

      {addOpen && (
        <AddModelDialog
          onClose={() => setAddOpen(false)}
          onCreated={() => {
            setAddOpen(false);
            qc.invalidateQueries({ queryKey: ["ai-models"] });
          }}
        />
      )}
    </div>
  );
}

function ModelCard({
  model,
  onActivate,
  onDelete,
  activating,
}: {
  model: AIModelConfig;
  onActivate: () => void;
  onDelete: () => void;
  activating: boolean;
}) {
  const providerInfo = PROVIDERS.find((p) => p.id === model.provider) ?? PROVIDERS[0];

  return (
    <div
      className={`p-5 rounded-lg border transition-colors ${
        model.is_active
          ? "border-primary bg-primary/5"
          : "border-border bg-secondary"
      }`}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3 flex-1 min-w-0">
          <div className="text-2xl">{providerInfo.icon}</div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 mb-1">
              <h3 className="font-semibold truncate">{model.name}</h3>
              {model.is_active && (
                <span className="px-2 py-0.5 text-xs rounded-full bg-primary text-white">
                  ACTIVE
                </span>
              )}
            </div>
            <div className="text-sm text-muted-foreground space-y-0.5">
              <div>
                <span className="capitalize">{providerInfo.label}</span> ·{" "}
                <code className="text-xs bg-background px-1.5 py-0.5 rounded">
                  {model.model_ref}
                </code>
              </div>
              {model.ollama_host && (
                <div className="text-xs">Host: {model.ollama_host}</div>
              )}
              {model.vllm_base_url && (
                <div className="text-xs">URL: {model.vllm_base_url}</div>
              )}
              {model.config && typeof (model.config as Record<string, unknown>).gguf_path === "string" && (
                <div className="text-xs font-mono">Path: {String((model.config as Record<string, unknown>).gguf_path)}</div>
              )}
              {model.total_inferences > 0 && (
                <div className="text-xs">
                  {model.total_inferences.toLocaleString()} inferences
                  {model.avg_inference_ms ? ` · avg ${Math.round(model.avg_inference_ms)}ms` : ""}
                </div>
              )}
            </div>
          </div>
        </div>
        <div className="flex flex-col gap-2 items-end shrink-0">
          {!model.is_active && (
            <button
              onClick={onActivate}
              disabled={activating}
              className="px-3 py-1.5 text-xs rounded-md bg-primary text-white hover:opacity-90 disabled:opacity-50 transition-opacity"
            >
              Activate
            </button>
          )}
          <button
            onClick={onDelete}
            className="px-3 py-1.5 text-xs rounded-md text-red-400 hover:bg-red-500/10 transition-colors"
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  );
}

function AddModelDialog({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: () => void;
}) {
  const [provider, setProvider] = useState<Provider>("gemini");
  const [name, setName] = useState("");
  const [modelRef, setModelRef] = useState("gemini-2.5-flash");
  const [apiKey, setApiKey] = useState("");
  const [url, setUrl] = useState("");
  const [ggufPath, setGgufPath] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const providerInfo = PROVIDERS.find((p) => p.id === provider)!;

  function handleProviderChange(p: Provider) {
    setProvider(p);
    const info = PROVIDERS.find((x) => x.id === p)!;
    setModelRef(info.defaultModels[0] ?? "");
    setName(`${info.label} - ${info.defaultModels[0] ?? "custom"}`);
    setApiKey("");
    setUrl("");
    setGgufPath("");
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const body: Record<string, unknown> = {
        name: name || `${providerInfo.label} - ${modelRef}`,
        provider,
        model_ref: modelRef,
      };

      if (providerInfo.needsApiKey) {
        if (!apiKey) throw new Error("API key is required");
        body.api_key = apiKey;
      }

      if (providerInfo.needsUrl === "ollama_host") {
        body.ollama_host = url || "http://localhost:11434";
      } else if (providerInfo.needsUrl === "vllm_base_url") {
        body.vllm_base_url = url || "http://localhost:8000/v1";
      }

      if (providerInfo.needsGgufPath) {
        if (!ggufPath) throw new Error("GGUF path is required (e.g., /models/my-model.gguf)");
        body.gguf_path = ggufPath;
      }

      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/ai-models`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${localStorage.getItem("ap_access_token") ?? ""}`,
          },
          body: JSON.stringify(body),
        }
      );

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err?.detail?.message || `Failed (${res.status})`);
      }

      onCreated();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to create model");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div
      className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4"
      onClick={() => !loading && onClose()}
    >
      <form
        onSubmit={submit}
        onClick={(e) => e.stopPropagation()}
        className="bg-secondary rounded-xl border border-border p-6 w-full max-w-2xl space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto"
      >
        <h2 className="text-lg font-semibold">Add AI Model</h2>

        {error && (
          <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-3 text-sm text-red-400">
            {error}
          </div>
        )}

        <div>
          <label className="block text-sm font-medium mb-2">Provider</label>
          <div className="grid grid-cols-2 gap-2">
            {PROVIDERS.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => handleProviderChange(p.id)}
                className={`text-left p-3 rounded-lg border transition-colors ${
                  provider === p.id
                    ? "border-primary bg-primary/10"
                    : "border-border bg-background hover:border-primary/50"
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-lg">{p.icon}</span>
                  <span className="font-medium text-sm">{p.label}</span>
                </div>
                <p className="text-xs text-muted-foreground">{p.description}</p>
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium mb-1.5">Display Name</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={`${providerInfo.label} - ${modelRef}`}
            className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-primary"
          />
        </div>

        <div>
          <label className="block text-sm font-medium mb-1.5">Model</label>
          <input
            type="text"
            value={modelRef}
            onChange={(e) => setModelRef(e.target.value)}
            required
            list="model-options"
            className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground font-mono text-sm focus:outline-none focus:ring-2 focus:ring-primary"
          />
          <datalist id="model-options">
            {providerInfo.defaultModels.map((m) => (
              <option key={m} value={m} />
            ))}
          </datalist>
          <p className="text-xs text-muted-foreground mt-1">
            Suggestions: {providerInfo.defaultModels.join(", ")}
          </p>
        </div>

        {providerInfo.needsApiKey && (
          <div>
            <label className="block text-sm font-medium mb-1.5">
              API Key <span className="text-red-400">*</span>
            </label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              required
              placeholder={
                provider === "gemini"
                  ? "AIzaSy..."
                  : provider === "openrouter"
                  ? "sk-or-v1-..."
                  : provider === "openai"
                  ? "sk-..."
                  : "sk-ant-..."
              }
              className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground font-mono text-sm focus:outline-none focus:ring-2 focus:ring-primary"
            />
            <p className="text-xs text-muted-foreground mt-1">
              Stored securely in the database. Never returned via API.
            </p>
          </div>
        )}

        {providerInfo.needsUrl && (
          <div>
            <label className="block text-sm font-medium mb-1.5">
              {providerInfo.needsUrl === "ollama_host" ? "Ollama Host" : "vLLM Base URL"}
            </label>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder={
                providerInfo.needsUrl === "ollama_host"
                  ? "http://host.docker.internal:11434"
                  : "http://localhost:8000/v1"
              }
              className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground font-mono text-sm focus:outline-none focus:ring-2 focus:ring-primary"
            />
            <p className="text-xs text-muted-foreground mt-1">
              {providerInfo.needsUrl === "ollama_host"
                ? "Use host.docker.internal for Ollama running on host (macOS/Windows)"
                : "vLLM OpenAI-compatible API endpoint"}
            </p>
          </div>
        )}

        {providerInfo.needsGgufPath && (
          <div>
            <label className="block text-sm font-medium mb-1.5">
              GGUF File Path <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              value={ggufPath}
              onChange={(e) => setGgufPath(e.target.value)}
              required
              placeholder="/models/my-model.gguf"
              className="w-full px-3 py-2 rounded-lg bg-background border border-border text-foreground font-mono text-sm focus:outline-none focus:ring-2 focus:ring-primary"
            />
            <div className="text-xs text-muted-foreground mt-1 space-y-1">
              <p>1. Place your .gguf file in <code className="bg-background px-1 rounded">./models/</code> in the project</p>
              <p>2. Rebuild containers (this directory is mounted at <code className="bg-background px-1 rounded">/models</code>)</p>
              <p>3. Enter path: <code className="bg-background px-1 rounded">/models/your-file.gguf</code></p>
            </div>
          </div>
        )}

        <div className="flex gap-3 justify-end pt-2">
          <button
            type="button"
            onClick={onClose}
            disabled={loading}
            className="px-4 py-2 text-sm rounded-lg border border-border hover:bg-background transition-colors disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={loading}
            className="px-4 py-2 text-sm rounded-lg bg-primary text-white hover:opacity-90 disabled:opacity-50 transition-opacity"
          >
            {loading ? "Creating…" : "Create & Activate"}
          </button>
        </div>
      </form>
    </div>
  );
}
