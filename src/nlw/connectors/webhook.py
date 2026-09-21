"""The ``webhook`` connector: HTTPS-only outbound POST to an operator-configured
destination (M7, ADR-013/014).

The destination URL lives ONLY in connector config (never in step args), is
re-validated by the SSRF guard at send time, and is contacted with redirects
disabled, bounded timeout, and a bounded response read. Credential-bearing
headers come only from the SecretStore; all other headers are code-controlled.
"""

import json
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, field_validator

from nlw.connectors.base import (
    ConnectorConfigError,
    ConnectorContext,
    ConnectorType,
    register_connector_type,
)
from nlw.connectors.http_action import ActionHttpResponse, perform_action_request
from nlw.connectors.http_guard import SsrfError, validate_url
from nlw.registry.registry import (
    ActionAuthError,
    ActionContext,
    ActionResult,
    AmbiguousActionError,
    ToolExecutionError,
)
from nlw.secrets.store import SecretError

# Hard platform caps (independent of tenant config).
_TIMEOUT_CAP_S = 15
_MAX_RESPONSE_BYTES_CAP = 1_000_000
_MAX_PAYLOAD_BYTES = 256_000

# Only these credential header names may be operator-configured; the VALUE always
# comes from the SecretStore. Reserved / code-controlled headers are excluded.
_ALLOWED_AUTH_HEADERS = frozenset({"Authorization", "X-Api-Key", "X-Auth-Token"})
_USER_AGENT = "nlw-webhook/1.0"


class WebhookConnectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str
    method: str = "POST"
    auth_header_name: str | None = None
    auth_scheme: str | None = None  # e.g. "Bearer"; value comes from the secret
    timeout_s: int = 10
    max_response_bytes: int = 100_000

    @field_validator("url")
    @classmethod
    def _valid_url(cls, v: str) -> str:
        # Static SSRF checks at config time (scheme/userinfo/fragment). DNS/IP
        # policy is enforced again at send time by the guard.
        try:
            validate_url(v)
        except SsrfError as exc:
            raise ValueError(str(exc)) from exc
        return v

    @field_validator("method")
    @classmethod
    def _only_post(cls, v: str) -> str:
        if v.upper() != "POST":
            raise ValueError("only POST is supported in M7")
        return "POST"

    @field_validator("auth_header_name")
    @classmethod
    def _allowed_header(cls, v: str | None) -> str | None:
        if v is not None and v not in _ALLOWED_AUTH_HEADERS:
            raise ValueError(f"auth_header_name must be one of {sorted(_ALLOWED_AUTH_HEADERS)}")
        return v

    @field_validator("timeout_s")
    @classmethod
    def _cap_timeout(cls, v: int) -> int:
        return max(1, min(v, _TIMEOUT_CAP_S))

    @field_validator("max_response_bytes")
    @classmethod
    def _cap_response(cls, v: int) -> int:
        return max(1, min(v, _MAX_RESPONSE_BYTES_CAP))


def parse_config(config: dict[str, Any]) -> WebhookConnectorConfig:
    try:
        return WebhookConnectorConfig.model_validate(config)
    except ValueError as exc:
        raise ConnectorConfigError(f"invalid webhook config: {exc}") from exc


def _build_headers(config: WebhookConnectorConfig, secret: str | None, key: str) -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "Idempotency-Key": key,
        "User-Agent": _USER_AGENT,
    }
    if config.auth_header_name is not None:
        if not secret:
            raise ConnectorConfigError("webhook auth header configured but no secret resolved")
        value = f"{config.auth_scheme} {secret}" if config.auth_scheme else secret
        headers[config.auth_header_name] = value
    return headers


def send_webhook(
    config: WebhookConnectorConfig,
    secret: str | None,
    payload: dict[str, Any],
    idempotency_key: str,
    transport: httpx.BaseTransport | None,
) -> ActionResult:
    """Perform the POST. Raises typed retryable/deterministic errors. The
    transport is injectable; production uses the SSRF ``GuardedTransport``."""
    body = json.dumps(payload).encode("utf-8")
    if len(body) > _MAX_PAYLOAD_BYTES:
        raise ToolExecutionError("webhook payload exceeds maximum size")
    headers = _build_headers(config, secret, idempotency_key)

    # Total-deadline + streaming + phase-aware classification. The response body
    # is not needed for classification (status + headers only); it is drained
    # under a hard byte cap so an oversized/compressed body cannot be buffered.
    resp = perform_action_request(
        method="POST",
        url=config.url,
        content=body,
        headers=headers,
        transport=transport,
        timeout_s=config.timeout_s,
        max_response_bytes=config.max_response_bytes,
        want_body=False,
    )
    return _classify_response(resp)


def _classify_response(resp: ActionHttpResponse) -> ActionResult:
    """Classify a webhook HTTP status CONSERVATIVELY (P1C).

    A generic webhook has NO enforced idempotency contract and no transactional
    guarantee tying an HTTP status to whether the effect occurred, so we auto-retry
    ONLY when the effect provably did not occur:
    - 2xx                -> success.
    - 3xx                -> deterministic failure (redirects are disabled; a 3xx
                            here is a misconfiguration, not an effect).
    - 401/403            -> deterministic auth failure (request rejected, no effect).
    - other 4xx          -> deterministic client error (request rejected, no effect).
    - 429                -> AMBIGUOUS -> UNKNOWN. 429 signals rate limiting but gives
                            NO guarantee an arbitrary receiver produced no effect
                            (it may have acted and still returned 429). With no
                            enforced idempotency contract we must not auto-resend.
                            (Slack's 429 IS retryable — that is backed by Slack's own
                            documented rate-limit contract; see slack.py.)
    - 5xx                -> AMBIGUOUS -> UNKNOWN. A generic 5xx does NOT prove the
                            effect did not occur: a receiver may perform the action
                            and then fail while responding.
    """
    code = resp.status_code
    if 200 <= code < 300:
        request_id = resp.headers.get("X-Request-Id") or resp.headers.get("X-Request-ID")
        return ActionResult(output={"http_status": code}, provider_request_id=request_id)
    if code in (301, 302, 303, 307, 308):
        raise ToolExecutionError("webhook redirect responses are not allowed")
    if code in (401, 403):
        raise ActionAuthError("webhook authentication failed")
    if code == 429:
        raise AmbiguousActionError("webhook rate limited (429); delivery outcome unprovable")
    if 500 <= code < 600:
        raise AmbiguousActionError(f"webhook server error {code}; delivery outcome unprovable")
    # Other 4xx: deterministic client error.
    raise ToolExecutionError(f"webhook rejected the request ({code})")


def _webhook_health(ctx: ConnectorContext) -> None:
    """Validate config + URL + DNS/public-IP policy + secret availability.

    Performs NO side-effecting HTTP request. Actual delivery is the runtime
    liveness proof (ADR-013).
    """
    config = parse_config(ctx.config)
    host, _port = validate_url(config.url)
    # DNS/public-IP policy check (resolution only; not an HTTP request).
    from nlw.connectors.http_guard import _default_resolver, resolve_and_validate

    try:
        resolve_and_validate(host, _default_resolver)
    except SsrfError as exc:
        raise ConnectorConfigError(f"webhook destination not reachable safely: {exc}") from None
    if config.auth_header_name is not None and not ctx.secret:
        raise SecretError("webhook auth configured but secret is unavailable")


WEBHOOK_CONNECTOR = ConnectorType(
    name="webhook",
    config_model=WebhookConnectorConfig,
    secret_required=False,  # auth is optional; required only if auth_header_name is set
    health_check=_webhook_health,
)

register_connector_type(WEBHOOK_CONNECTOR)


def execute_webhook_action(
    args: BaseModel, connector: ConnectorContext, action_ctx: ActionContext
) -> ActionResult:
    """ToolSpec.execute_action for ``webhook.send``."""
    from nlw.tools.action_schemas import WebhookSendArgs

    assert isinstance(args, WebhookSendArgs)
    config = parse_config(connector.config)
    return send_webhook(
        config=config,
        secret=connector.secret,
        payload=args.payload,
        idempotency_key=str(action_ctx.idempotency_key),
        transport=action_ctx.transport,
    )
