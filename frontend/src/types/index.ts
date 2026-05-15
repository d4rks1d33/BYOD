export type Role = "admin" | "analyst" | "viewer";
export type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";
export type ScanStatus = "pending" | "queued" | "running" | "paused" | "completed" | "failed" | "cancelled";
export type FindingStatus = "new" | "verified" | "false_positive" | "accepted_risk" | "fixed";

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: Role;
  is_active: boolean;
  created_at: string;
}

export type TargetType = "web_application" | "rest_api" | "graphql_api" | "repository" | "mobile_backend";

export interface Project {
  id: string;
  name: string;
  description?: string;
  target_url: string;
  target_type: TargetType;
  status: string;
  owner_id: string;
  scope_urls?: string[];
  config?: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface Scan {
  id: string;
  project_id: string;
  scan_type: string;
  status: ScanStatus;
  celery_task_id?: string;
  started_at?: string;
  completed_at?: string;
  config?: Record<string, unknown>;
  statistics?: ScanStatistics;
  error_message?: string;
  created_at: string;
  updated_at: string;
}

export interface ScanStatistics {
  endpoints_discovered?: number;
  findings_total?: number;
  findings_critical?: number;
  findings_high?: number;
  findings_medium?: number;
  findings_low?: number;
  duration_seconds?: number;
}

export interface Finding {
  id: string;
  project_id: string;
  scan_id?: string;
  title: string;
  description?: string;
  severity: SeverityLevel;
  status: FindingStatus;
  finding_type?: string;
  endpoint?: string;
  method?: string;
  parameter?: string;
  payload?: string;
  cwe_id?: string;
  cve_ids?: string[];
   cvss_score?: number;
   cvss_vector?: string;
   impact?: string;
   evidence?: Evidence[];
   reproduction_steps?: string[];
   remediation?: string;
   tool?: string;


  file_path?: string;
  line_number?: number;
  notes?: string;
  verified_at?: string;
  created_at: string;
  updated_at: string;
}

export interface Evidence {
  id: string;
  finding_id?: string;
  evidence_type: string;
  http_request?: string;
  http_response?: string;
  payload?: string;
  screenshot_path?: string;
  tool_output?: string;
  metadata?: Record<string, unknown>;

  created_at: string;
}

export interface ReportJob {
  id: string;
  project_id: string;
  scan_id?: string;
  format: "html" | "pdf" | "json";
  status: "pending" | "running" | "complete" | "failed";
  file_path?: string;
  error_message?: string;
  created_at: string;
}

export interface AIModelConfig {
  id: string;
  name: string;
  provider: string;
  model_ref: string;
  ollama_host?: string;
  vllm_base_url?: string;
  is_active: boolean;
  is_default: boolean;
  avg_inference_ms?: number;
  total_inferences: number;
  config?: Record<string, unknown>;
  has_api_key?: boolean;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
}

export interface WSScanEvent {
  type: string;
  scan_id?: string;
  project_id?: string;
  phase?: string;
  progress?: number;
  message?: string;
  finding?: Finding;
  timestamp?: string;
}

export interface LoginRequest {
  email: string;
  password: string;
  mfa_code?: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
}
