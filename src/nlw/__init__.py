"""Natural Language Workflow Platform.

Package layout (empty scaffolding in M0; filled in later milestones):

- api            FastAPI control plane (routers, deps, auth context)
- core           config, logging, errors, execution context
- domain         Pydantic models, enums, state machines  [mypy strict]
- db             SQLAlchemy models, tenant-scoped repositories, session
- auth           AuthProvider abstraction (Supabase impl)
- tenancy        membership resolution, RLS helpers
- secrets        SecretStore abstraction + implementations
- registry       tool registry + ToolSpec
- tools          tool implementations (data / processing / action)
- connectors     connector clients (postgres, webhook, slack, ...)
- planner        LLM planner + LLMProvider abstraction (BYOK)
- feasibility    deterministic feasibility engine + SQL safety  [mypy strict]
- engine         durable executor: DAG, checkpointing, resume, idempotency  [mypy strict]
- scheduler      due-schedule reader -> enqueue
- worker         Dramatiq actors / entrypoint
- observability  structlog + Prometheus metrics (OpenTelemetry / Langfuse planned)
"""

__version__ = "0.0.0"
