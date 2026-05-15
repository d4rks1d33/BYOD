import enum


class TargetTypeEnum(str, enum.Enum):
    web_application = "web_application"
    rest_api = "rest_api"
    graphql_api = "graphql_api"
    repository = "repository"
    mobile_backend = "mobile_backend"


class ScanTypeEnum(str, enum.Enum):
    full = "full"
    dast_only = "dast_only"
    sast_only = "sast_only"
    recon_only = "recon_only"
    auth_audit = "auth_audit"
    api_audit = "api_audit"


class ScanStatusEnum(str, enum.Enum):
    queued = "queued"
    running = "running"
    paused = "paused"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class SeverityEnum(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingStatusEnum(str, enum.Enum):
    new = "new"
    verified = "verified"
    false_positive = "false_positive"
    accepted_risk = "accepted_risk"
    fixed = "fixed"


class EvidenceTypeEnum(str, enum.Enum):
    http_request_response = "http_request_response"
    screenshot = "screenshot"
    har_export = "har_export"
    code_snippet = "code_snippet"
    tool_output = "tool_output"


class ReportFormatEnum(str, enum.Enum):
    html = "html"
    pdf = "pdf"
    json = "json"
    markdown = "markdown"
    csv = "csv"


class SystemRoleEnum(str, enum.Enum):
    super_admin = "super_admin"
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class AIProviderEnum(str, enum.Enum):
    llamacpp = "llamacpp"
    ollama = "ollama"
    vllm = "vllm"
    openai_compatible = "openai_compatible"
    anthropic = "anthropic"
    openai = "openai"
    gemini = "gemini"
    openrouter = "openrouter"
