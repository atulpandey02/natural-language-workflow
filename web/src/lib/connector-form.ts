/**
 * Connector form rules that mirror the backend's typed configs (see
 * src/nlw/connectors/*.py and nlw.secrets.store). The backend stays
 * authoritative; these only give earlier, friendlier feedback and guarantee the
 * request body has exactly the typed schema's fields.
 */

export type ConnectorType = "postgres" | "webhook" | "slack" | "static";

export interface ConnectorFormValues {
  type: ConnectorType;
  name: string;
  secret_ref: string;
  workspace_label: string;
  default_channel: string;
  host: string;
  port: string;
  database: string;
  allowed_schemas: string;
  url: string;
  label: string;
}

// SlackConnectorConfig._CHANNEL_ID_RE
export const SLACK_CHANNEL_ID_RE = /^[CGD][A-Z0-9]{2,}$/;
// nlw.secrets.store.SECRET_REF_PATTERN
export const SECRET_REF_RE = /^[A-Z][A-Z0-9_]{0,63}$/;

const SECRET_REQUIRED: Record<ConnectorType, boolean> = {
  slack: true,
  postgres: true,
  webhook: false, // optional unless an auth header is configured
  static: true,
};

// Values that are credential material rather than a reference name.
const CREDENTIAL_SHAPES = [
  /^xox[a-z]-/i, // Slack tokens
  /:\/\//, // any URL, e.g. a Slack incoming-webhook URL
  /hooks\.slack\.com/i,
  /^(sk|pk|ghp|gho|github_pat)_/i,
  /^eyJ[A-Za-z0-9_-]{8,}\./, // JWT
];

export function secretRefProblem(
  raw: string,
  type: ConnectorType,
): "credential" | "required" | "format" | null {
  const v = raw.trim();
  if (CREDENTIAL_SHAPES.some((re) => re.test(v))) return "credential";
  if (!v) return SECRET_REQUIRED[type] ? "required" : null;
  if (!SECRET_REF_RE.test(v.toUpperCase())) return "format";
  return null;
}

function buildConfig(v: ConnectorFormValues): Record<string, unknown> {
  switch (v.type) {
    case "slack":
      return {
        workspace_label: v.workspace_label.trim(),
        default_channel: v.default_channel.trim(),
      };
    case "postgres":
      return {
        host: v.host.trim(),
        port: v.port ? Number(v.port) : 5432,
        database: v.database.trim(),
        allowed_schemas: (v.allowed_schemas || "public")
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      };
    case "webhook":
      return { url: v.url.trim() };
    case "static":
      return v.label.trim() ? { label: v.label.trim() } : {};
  }
}

export function buildConnectorPayload(v: ConnectorFormValues) {
  const ref = v.secret_ref.trim().toUpperCase();
  return {
    type: v.type,
    name: v.name.trim(),
    config: buildConfig(v),
    secret_ref: ref || null,
  };
}

// Stable backend messages (src/nlw/api/routers/connectors.py, nlw.db.quota).
const DUPLICATE_NAME = "a connector with this name already exists";

export function isDuplicateConnectorName(e: { status: number; message: string }): boolean {
  return e.status === 409 && e.message === DUPLICATE_NAME;
}
