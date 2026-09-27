"""
Central configuration, loaded from environment / .env file.
Nothing here talks to the network - just settings.
"""

import os

from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


class Config:
    # LLM backend. Options: anthropic | openai | google | mock
    #   openai = any OpenAI-compatible /chat/completions endpoint (OpenAI,
    #            OpenRouter, Ollama, vLLM, LM Studio, DeepSeek, ...) - point
    #            OPENAI_BASE_URL at it.
    #   mock   = deterministic offline provider for dev/CI with no API key.
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic")

    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "")  # "" -> falls back to AGENT_MODEL

    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "")  # "" -> falls back to AGENT_MODEL

    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
    GOOGLE_MODEL = os.getenv("GOOGLE_MODEL", "")  # "" -> falls back to AGENT_MODEL

    # FreeLLMAPI - one unified key for many free LLM providers behind a single
    # OpenAI-compatible gateway (https://freellmapi.co, self-hostable).
    # LLM_PROVIDER=freellmapi uses these. The gateway handles routing/fallover;
    # FREELLMAPI_MODEL=auto (default) lets it pick the best model per request.
    FREELLMAPI_API_KEY = os.getenv("FREELLMAPI_API_KEY", "")
    FREELLMAPI_BASE_URL = os.getenv("FREELLMAPI_BASE_URL", "http://localhost:3001/v1")
    FREELLMAPI_MODEL = os.getenv("FREELLMAPI_MODEL", "auto")

    # Generic default model - used by any provider that doesn't set its own
    # <PROVIDER>_MODEL.
    AGENT_MODEL = os.getenv("AGENT_MODEL", "claude-sonnet-4-6")

    # --- Agent watcher plumbing (run.py / dashboard agent panel) ---
    # Stop-file: dashboard writes it to ask the overnight watcher to stop.
    AGENT_STOP_FILE = os.getenv("AGENT_STOP_FILE", "data/agent_stop.txt")
    # Heartbeat: watcher updates it each poll so the dashboard can show
    # "still alive / last cycle / triaged" without polling the process.
    AGENT_HEARTBEAT_PATH = os.getenv("AGENT_HEARTBEAT_PATH", "data/agent_heartbeat.json")
    # Captured stdout/stderr of the default overnight watcher (dashboard-managed).
    AGENT_LOG_FILE = os.getenv("AGENT_LOG_FILE", "data/agent_run.log")
    # Per-agent state dir for *named* watchers: data/agents/<agent_id>/
    # (heartbeat.json + stop.txt + run.log). The default agent ("default")
    # keeps the legacy AGENT_* paths above.
    AGENT_DIR = os.getenv("AGENT_DIR", "data/agents")
    # Seconds between poll cycles (--interval default in run.py).
    AGENT_POLL_INTERVAL = float(os.getenv("AGENT_POLL_INTERVAL", "30"))

    # --- LLM retry/backoff (openai_compat_provider._post) ---
    # Free gateways (FreeLLMAPI, OpenRouter free tier, ...) throw 429/5xx under
    # load; retries with exponential backoff + jitter keep one blip from killing
    # a whole overnight batch. LLM_RETRY_BACKOFF_MAX caps the per-step wait
    # (and is honored even when the gateway sends a huge Retry-After header).
    LLM_MAX_RETRIES = int(os.getenv("LLM_MAX_RETRIES", "5"))
    LLM_RETRY_BACKOFF_BASE = float(os.getenv("LLM_RETRY_BACKOFF_BASE", "1.5"))
    LLM_RETRY_BACKOFF_MAX = float(os.getenv("LLM_RETRY_BACKOFF_MAX", "30"))
    # 429s are rate-limit signals: retrying them hard only keeps the key inside
    # the rate-limit window. Far fewer retries than 5xx, and Retry-After (when
    # the gateway sends one) is honored before the bounded exponential fallback.
    LLM_429_MAX_RETRIES = int(os.getenv("LLM_429_MAX_RETRIES", "2"))
    # One structured log line per LLM attempt (request_id/attempt/model/status/
    # latency/usage/retry_after). API keys and prompt contents are never logged.
    LLM_TRACE_REQUESTS = _bool("LLM_TRACE_REQUESTS", True)

    # FreeLLMAPI - after a rate-limit failure, make ONE extra attempt with an
    # explicit alternate model (a different provider family than the last one
    # that routed successfully), using the gateway's own /v1/models list.
    # Bounded to a single fallback request *on failure* - the happy path is
    # untouched, so this does not increase request volume under normal use.
    FREELLMAPI_FALLBACK_ENABLED = _bool("FREELLMAPI_FALLBACK_ENABLED", True)
    FREELLMAPI_FALLBACK_MODELS_TTL = int(os.getenv("FREELLMAPI_FALLBACK_MODELS_TTL", "300"))

    # Chat agent tool-loop budget: max LLM calls per /api/chat message. The
    # loop returns as soon as the model answers without a tool call, so this is
    # a hard ceiling (anti run-away), not the typical call count.
    LLM_MAX_TOOL_TURNS = int(os.getenv("LLM_MAX_TOOL_TURNS", "8"))

    # --- Audit / storage (JSONL + JSON stores under data/) ---
    # Triage verdicts - main.py / run.py / dashboard.py's on-demand triage
    # route all append here. This is also the input queue feedback_cli.py
    # reads for analyst review + lesson distillation.
    TRIAGE_LOG_PATH = os.getenv("TRIAGE_LOG_PATH", "data/triage_log.jsonl")
    # Chat agent transcripts (separate from triage - conversational, not verdicts).
    CHAT_LOG_PATH = os.getenv("CHAT_LOG_PATH", "data/chat_log.jsonl")
    # AI SOC Engineer conversation transcripts (dashboard /api/engineer/chat).
    ENGINEER_LOG_PATH = os.getenv("ENGINEER_LOG_PATH", "data/engineer_log.jsonl")

    # Lookup tables - small named threat-intel stores for the chat agent and
    # dashboard (see lookup_tables.py). Single atomic JSON file.
    LOOKUP_TABLES_PATH = os.getenv("LOOKUP_TABLES_PATH", "data/lookup_tables.json")

    # Alert rules - local correlation/filtering evaluated before LLM triage
    # (see rules.py). RULES_PATH holds rule definitions; RULE_STATE_PATH
    # holds the rolling window counters for threshold/grouping rules.
    RULES_PATH = os.getenv("RULES_PATH", "data/rules.json")
    RULE_STATE_PATH = os.getenv("RULE_STATE_PATH", "data/rule_state.json")

    # --- Web search (OSINT enrichment, no API key) ---
    # OFF by default so triage never blocks on an external lookup. When on,
    # the chat agent can enrich alerts via SearXNG (or DuckDuckGo fallback).
    WEB_SEARCH_ENABLED = _bool("WEB_SEARCH_ENABLED", False)
    SEARXNG_URL = os.getenv("SEARXNG_URL", "")

    # --- Outbound notifications (rules.py action.notify) ---
    # Generic webhook (Slack/Teams-compatible {"text": "..."} payload, or any
    # endpoint that accepts a JSON POST) fired when a rule's action.notify is
    # set. Empty = notifications are logged but never actually sent.
    NOTIFY_WEBHOOK_URL = os.getenv("NOTIFY_WEBHOOK_URL", "")
    NOTIFY_TIMEOUT_SECONDS = float(os.getenv("NOTIFY_TIMEOUT_SECONDS", "10"))
    NOTIFICATIONS_LOG_PATH = os.getenv("NOTIFICATIONS_LOG_PATH", "data/notifications.jsonl")

    # --- Dashboard auth ---
    # If set, every dashboard.py route (except a couple of static assets)
    # requires this token, either as `Authorization: Bearer <token>` or
    # `?token=<token>`. Empty = no auth (fine for strictly local use on
    # 127.0.0.1; set this before binding --host to anything else).
    DASHBOARD_TOKEN = os.getenv("DASHBOARD_TOKEN", "")
    # Optional per-user tokens: "user:token[:role],user:token[:role],...". When
    # set (with or without DASHBOARD_TOKEN), a Bearer token maps to a VERIFIED
    # identity - the Approval Center uses it for separation of duties (a proposer
    # cannot approve their own proposal) and ignores any client-supplied "by"
    # field. The optional role is "viewer" (reads), "approver" (reads + the
    # Approval Center + /api/engineer/tool) or "admin" (everything, incl. the
    # rules/lookup/provider CRUD and watcher control routes). An entry with no
    # role - or an unrecognised one - is an admin, so configs written before
    # roles existed keep the access they always had.
    DASHBOARD_USERS = os.getenv("DASHBOARD_USERS", "")

    # Splunk (also configurable per-provider via the dashboard)
    SPLUNK_HOST = os.getenv("SPLUNK_HOST", "")
    SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN", "")
    SPLUNK_VERIFY_SSL = _bool("SPLUNK_VERIFY_SSL", True)
    SPLUNK_SEARCH = os.getenv("SPLUNK_SEARCH", "search index=notable status=new | head 20")

    # CrowdStrike
    FALCON_CLIENT_ID = os.getenv("FALCON_CLIENT_ID", "")
    FALCON_CLIENT_SECRET = os.getenv("FALCON_CLIENT_SECRET", "")
    FALCON_BASE_URL = os.getenv("FALCON_BASE_URL", "https://api.crowdstrike.com")

    # Agent behavior / guardrails
    AUTO_CLOSE_CONFIDENCE_THRESHOLD = float(os.getenv("AUTO_CLOSE_CONFIDENCE_THRESHOLD", "0.9"))
    DRY_RUN_ACTIONS = _bool("DRY_RUN_ACTIONS", True)
    # Use mock Splunk/CrowdStrike connectors instead of live APIs - for testing
    # the agent + RAG + self-improvement loop before wiring real credentials.
    MOCK_MODE = _bool("MOCK_MODE", False)

    # --- SIEM platform (alert source) ---
    # Which SIEM platform to pull alerts from: splunk | qradar | elastic |
    # sentinel | wazuh | mock. Additional connections can be added at runtime
    # through the dashboard (data/siem_providers.json) - see siem_providers.py.
    SIEM_PROVIDER = os.getenv("SIEM_PROVIDER", "splunk")

    # IBM QRadar
    QRADAR_HOST = os.getenv("QRADAR_HOST", "")
    QRADAR_TOKEN = os.getenv("QRADAR_TOKEN", "")
    QRADAR_VERIFY_SSL = _bool("QRADAR_VERIFY_SSL", True)
    QRADAR_SEARCH = os.getenv("QRADAR_SEARCH", "SELECT * FROM events LAST 1 HOUR")

    # Elastic Security
    ELASTIC_HOST = os.getenv("ELASTIC_HOST", "")
    ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY", "")
    ELASTIC_VERIFY_SSL = _bool("ELASTIC_VERIFY_SSL", True)
    ELASTIC_INDEX = os.getenv("ELASTIC_INDEX", ".siem-signals-*")

    # Microsoft Sentinel
    SENTINEL_TENANT_ID = os.getenv("SENTINEL_TENANT_ID", "")
    SENTINEL_CLIENT_ID = os.getenv("SENTINEL_CLIENT_ID", "")
    SENTINEL_CLIENT_SECRET = os.getenv("SENTINEL_CLIENT_SECRET", "")
    SENTINEL_WORKSPACE_ID = os.getenv("SENTINEL_WORKSPACE_ID", "")
    SENTINEL_QUERY = os.getenv("SENTINEL_QUERY", "")

    # Wazuh (indexer / OpenSearch API) - docker deployment lives in wazuh/
    # on localhost:9200 with default admin/admin credentials. WazuhConnector
    # (connectors/siem/wazuh.py) refuses to use that default against a
    # non-local host - see its docstring.
    WAZUH_HOST = os.getenv("WAZUH_HOST", "")
    WAZUH_USERNAME = os.getenv("WAZUH_USERNAME", "admin")
    WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "admin")
    WAZUH_INDEX = os.getenv("WAZUH_INDEX", "wazuh-alerts-*")
    WAZUH_RELATED_INDEX = os.getenv("WAZUH_RELATED_INDEX", "wazuh-archives-*")
    WAZUH_VERIFY_SSL = _bool("WAZUH_VERIFY_SSL", False)  # self-signed by default
    WAZUH_CA_CERT = os.getenv("WAZUH_CA_CERT", "")

    # --- Wazuh manager REST API (rules / decoders / logtest / agents) ---
    # This is a *different* surface from the indexer above: the manager API
    # (default port 55000, user wazuh-wui in the bundled docker stack) is what
    # serves rules, decoders, agents, manager/cluster status and logtest. The
    # AI SOC engineer's write tools (create/update/delete rule, decoder, ...)
    # go through here, always behind an approval gate.
    WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://localhost:55000")
    WAZUH_API_USERNAME = os.getenv("WAZUH_API_USERNAME", "wazuh-wui")
    WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD", "")
    WAZUH_API_VERIFY_SSL = _bool("WAZUH_API_VERIFY_SSL", False)
    WAZUH_API_CA_CERT = os.getenv("WAZUH_API_CA_CERT", "")

    # --- Wazuh dashboard / OpenSearch Dashboards (saved-objects API) ---
    # Used by the dashboard engineer to create/verify dashboards and
    # visualizations (best-effort: errors surface cleanly if unreachable).
    WAZUH_DASHBOARD_URL = os.getenv("WAZUH_DASHBOARD_URL", "https://localhost:443")
    WAZUH_DASHBOARD_USERNAME = os.getenv("WAZUH_DASHBOARD_USERNAME", "admin")
    WAZUH_DASHBOARD_PASSWORD = os.getenv("WAZUH_DASHBOARD_PASSWORD", "")
    WAZUH_DASHBOARD_VERIFY_SSL = _bool("WAZUH_DASHBOARD_VERIFY_SSL", False)

    # --- AI SOC engineer: tool layer limits & gates ---
    # Who the audit log and approval center attribute actions to (a free-text
    # analyst name, same convention as ANALYST_NAME in feedback_cli.py).
    ENGINE_USER = os.getenv("ENGINE_USER", "analyst")
    # Audit trail for every tool invocation (timestamp, tool, params, result,
    # permission level, approval status, error).
    AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "data/audit_log.jsonl")
    # Approval center store (pending/proposed actions awaiting human review).
    APPROVALS_PATH = os.getenv("APPROVALS_PATH", "data/approvals.json")
    # Hard caps so a single tool call can never pull unbounded data.
    TOOL_QUERY_SIZE_LIMIT = int(os.getenv("TOOL_QUERY_SIZE_LIMIT", "200"))
    TOOL_RESULT_SIZE_LIMIT = int(os.getenv("TOOL_RESULT_SIZE_LIMIT", "50"))
    TOOL_QUERY_TIMEOUT = float(os.getenv("TOOL_QUERY_TIMEOUT", "20"))
    # Rule validation: how many automatic logtest-driven correction attempts a
    # generated rule gets before it is handed back as "failed" for human debug.
    LOGTEST_MAX_ATTEMPTS = int(os.getenv("LOGTEST_MAX_ATTEMPTS", "3"))
    # Pending proposals older than this are expired and cannot be approved.
    APPROVAL_EXPIRY_SECONDS = int(os.getenv("APPROVAL_EXPIRY_SECONDS", "86400"))
    # An approved proposal must be claimed within this window; 0 = no limit.
    APPROVAL_EXECUTION_WINDOW_SECONDS = int(os.getenv("APPROVAL_EXECUTION_WINDOW_SECONDS", "0"))
    # Separation of duties: a verified approver may not approve their own proposal.
    APPROVAL_BLOCK_SELF_APPROVAL = _bool("APPROVAL_BLOCK_SELF_APPROVAL", True)
    # Quorum before a proposal flips to approved (per band). Consulted at
    # approve time, so tightening the policy applies to existing proposals.
    APPROVAL_PROPOSE_MIN_APPROVERS = int(os.getenv("APPROVAL_PROPOSE_MIN_APPROVERS", "1"))
    APPROVAL_EXECUTE_MIN_APPROVERS = int(os.getenv("APPROVAL_EXECUTE_MIN_APPROVERS", "1"))
    # Tool-use budget per engineer conversation (investigations can need more
    # turns than the triage agent's default).
    ENGINE_MAX_TOOL_TURNS = int(os.getenv("ENGINE_MAX_TOOL_TURNS", "10"))

    # Mock SIEM (SIEM_PROVIDER=mock) - optional override for the canned alerts
    MOCK_SIEM_ALERTS_FILE = os.getenv("MOCK_SIEM_ALERTS_FILE", "")

    # Where the dashboard stores extra SIEM provider connections (JSON list)
    SIEM_PROVIDERS_PATH = os.getenv("SIEM_PROVIDERS_PATH", "./data/siem_providers.json")

    # Storage
    CHROMA_DB_PATH = os.getenv("CHROMA_DB_PATH", "./data/chroma")
    FEEDBACK_LOG_PATH = os.getenv("FEEDBACK_LOG_PATH", "./data/feedback_log.jsonl")

    # RAG embedding backend (rag/knowledge_base.py). "auto" (default) uses
    # the real downloaded sentence-transformer model, except under
    # MOCK_MODE, where it uses the offline hashing fallback (no download,
    # no network) automatically. "hashing" forces the offline fallback even
    # outside MOCK_MODE (air-gapped deployments, CI); "default" always uses
    # the downloaded model. See rag/embeddings.py for what the fallback
    # trades away.
    KB_EMBEDDING_MODE = os.getenv("KB_EMBEDDING_MODE", "auto")


cfg = Config()
