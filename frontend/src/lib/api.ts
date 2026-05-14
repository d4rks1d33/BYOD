import type {
  Project,
  Scan,
  Finding,
  Evidence,
  ReportJob,
  AIModelConfig,
  PaginatedResponse,
  TokenResponse,
  LoginRequest,
  User,
} from "@/types";
import { getValidAccessToken, clearTokens } from "./auth";

const BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const token = await getValidAccessToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${BASE}${path}`, { ...options, headers });

  if (res.status === 401) {
    clearTokens();
    window.location.href = "/login";
    throw new Error("Unauthorized");
  }

  if (!res.ok) {
    const error = await res.json().catch(() => ({}));
    throw Object.assign(new Error(error?.detail?.message || `HTTP ${res.status}`), {
      status: res.status,
      detail: error?.detail,
    });
  }

  if (res.status === 204) return undefined as T;
  return res.json();
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
export const auth = {
  login: (body: LoginRequest) =>
    request<TokenResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  me: () => request<User>("/users/me"),
};

// ─── Projects ─────────────────────────────────────────────────────────────────
export const projects = {
  list: () => request<PaginatedResponse<Project>>("/projects/"),

  get: (id: string) => request<Project>(`/projects/${id}`),

  create: (body: Partial<Project>) =>
    request<Project>("/projects/", { method: "POST", body: JSON.stringify(body) }),

  update: (id: string, body: Partial<Project>) =>
    request<Project>(`/projects/${id}`, { method: "PUT", body: JSON.stringify(body) }),

  delete: (id: string) =>
    request<void>(`/projects/${id}`, { method: "DELETE" }),
};

// ─── Scans ────────────────────────────────────────────────────────────────────
export const scans = {
  list: (projectId: string) =>
    request<PaginatedResponse<Scan>>(`/projects/${projectId}/scans`),

  get: (scanId: string) => request<Scan>(`/scans/${scanId}`),

  create: (projectId: string, body: { scan_type?: string; config?: Record<string, unknown> }) =>
    request<Scan>(`/projects/${projectId}/scans`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  pause: (scanId: string) =>
    request<Scan>(`/scans/${scanId}/pause`, { method: "POST" }),

  resume: (scanId: string) =>
    request<Scan>(`/scans/${scanId}/resume`, { method: "POST" }),

  cancel: (scanId: string) =>
    request<Scan>(`/scans/${scanId}/cancel`, { method: "POST" }),

  logs: (scanId: string, limit = 500) =>
    request<{ logs: Array<{ id: string; level: string; agent: string; message: string; timestamp: string }>; total: number }>(
      `/scans/${scanId}/logs?limit=${limit}`
    ),
};

// ─── Findings ─────────────────────────────────────────────────────────────────
export const findings = {
  list: (
    projectId: string,
    params?: {
      severity?: string;
      status?: string;
      page?: number;
      limit?: number;
      sort?: string;
    }
  ) => {
    const qs = new URLSearchParams(
      Object.fromEntries(
        Object.entries(params || {}).filter(([, v]) => v !== undefined).map(([k, v]) => [k, String(v)])
      )
    ).toString();
    return request<PaginatedResponse<Finding>>(
      `/projects/${projectId}/findings${qs ? `?${qs}` : ""}`
    );
  },

  get: (id: string) => request<Finding>(`/findings/${id}`),

  update: (id: string, body: { status?: string; notes?: string }) =>
    request<Finding>(`/findings/${id}`, { method: "PATCH", body: JSON.stringify(body) }),

  verify: (id: string) =>
    request<Finding>(`/findings/${id}/verify`, { method: "POST" }),

  markFalsePositive: (id: string, reason?: string) =>
    request<Finding>(`/findings/${id}/false-positive`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),

  evidence: (findingId: string) =>
    request<Evidence[]>(`/findings/${findingId}/evidence`),

  export: (projectId: string, format: "json" | "csv", severity?: string) => {
    const qs = new URLSearchParams({ format, ...(severity ? { severity } : {}) }).toString();
    return `/api/projects/${projectId}/findings/export?${qs}`;
  },
};

// ─── Reports ──────────────────────────────────────────────────────────────────
export const reports = {
  list: (projectId: string) =>
    request<ReportJob[]>(`/projects/${projectId}/reports`),

  create: (projectId: string, body: { format: string; scan_id?: string }) =>
    request<ReportJob>(`/projects/${projectId}/reports`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  get: (id: string) => request<ReportJob>(`/reports/${id}`),

  downloadUrl: (id: string) => `/api/reports/${id}/download`,
};

// ─── AI Models ────────────────────────────────────────────────────────────────
export const aiModels = {
  list: () => request<AIModelConfig[]>("/ai-models"),

  get: (id: string) => request<AIModelConfig>(`/ai-models/${id}`),

  create: (body: {
    name: string;
    provider: string;
    model_ref: string;
    api_key?: string;
    ollama_host?: string;
    vllm_base_url?: string;
    gguf_path?: string;
  }) =>
    request<AIModelConfig>("/ai-models", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  update: (id: string, body: Partial<{ name: string; model_ref: string; api_key: string }>) =>
    request<AIModelConfig>(`/ai-models/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),

  activate: (id: string) =>
    request<AIModelConfig>(`/ai-models/${id}/activate`, { method: "POST" }),

  delete: (id: string) =>
    request<void>(`/ai-models/${id}`, { method: "DELETE" }),
};
