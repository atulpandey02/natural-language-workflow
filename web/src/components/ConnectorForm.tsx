"use client";

import { useState } from "react";
import { useForm, useWatch, type FieldPath } from "react-hook-form";
import { useCreateConnector } from "@/lib/api/hooks";
import { ErrorBanner } from "@/components/ui";
import { ApiError } from "@/lib/errors";
import {
  SLACK_CHANNEL_ID_RE,
  buildConnectorPayload,
  secretRefProblem,
  type ConnectorFormValues,
  type ConnectorType,
} from "@/lib/connector-form";

const TYPE_LABEL: Record<ConnectorType, string> = {
  slack: "Slack — share approved results",
  postgres: "PostgreSQL — read-only queries",
  webhook: "Webhook — send approved results",
  static: "Static — test connector",
};

// Where a 422 detail's field path lands in this form.
const FIELD_FOR: Record<string, FieldPath<ConnectorFormValues>> = {
  name: "name",
  secret_ref: "secret_ref",
  "config.workspace_label": "workspace_label",
  "config.default_channel": "default_channel",
  "config.host": "host",
  "config.database": "database",
  "config.url": "url",
};

const EMPTY: Omit<ConnectorFormValues, "type"> = {
  name: "",
  secret_ref: "",
  workspace_label: "",
  default_channel: "",
  host: "",
  port: "5432",
  database: "",
  allowed_schemas: "",
  url: "",
  label: "",
};

function FieldError({ id, message }: { id: string; message?: string }) {
  return message ? (
    <p className="field-error" id={id}>
      {message}
    </p>
  ) : null;
}

export function ConnectorForm({ onCreated }: { onCreated?: () => void }) {
  const create = useCreateConnector();
  const { register, handleSubmit, control, reset, setError, setValue, formState } =
    useForm<ConnectorFormValues>({
      defaultValues: { type: "slack", ...EMPTY },
      mode: "onTouched",
    });
  const { errors } = formState;
  const type = useWatch({ control, name: "type" });
  const [created, setCreated] = useState<string | null>(null);
  const [rejectedCredential, setRejectedCredential] = useState(false);
  const [submitError, setSubmitError] = useState<unknown>(null);

  async function onSubmit(values: ConnectorFormValues) {
    if (create.isPending) return;
    setCreated(null);
    setSubmitError(null);
    try {
      await create.mutateAsync(buildConnectorPayload(values));
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setError("name", { message: "A connector with this name already exists." });
        return;
      }
      if (e instanceof ApiError && e.status === 422 && Array.isArray(e.details)) {
        for (const d of e.details as Array<{ loc?: unknown[] }>) {
          const path = (d.loc ?? []).filter((x) => x !== "body").join(".");
          const field = FIELD_FOR[path];
          if (field) setError(field, { message: "Check this value." });
        }
      }
      setSubmitError(e);
      return;
    }
    setCreated(values.name.trim());
    reset({ type: values.type, ...EMPTY });
    onCreated?.();
  }

  const invalid = (f: FieldPath<ConnectorFormValues>) => (errors[f] ? true : undefined);
  const describedBy = (f: string, hint?: boolean) =>
    [
      hint ? `c-${f}-hint` : null,
      errors[f as FieldPath<ConnectorFormValues>] ? `c-${f}-error` : null,
    ]
      .filter(Boolean)
      .join(" ") || undefined;
  return (
    <form
      className="card"
      onSubmit={handleSubmit(onSubmit)}
      noValidate
      aria-labelledby="connector-form-title"
    >
      <h2 id="connector-form-title" style={{ marginTop: 0, fontSize: 16 }}>
        Add a connector
      </h2>
      <ErrorBanner error={submitError} />
      {created ? (
        <p className="muted" role="status">
          Connector “{created}” added. An operator must provision its secret before it can be used.
        </p>
      ) : null}

      <label htmlFor="c-type">Type</label>
      <select id="c-type" {...register("type")}>
        {(Object.keys(TYPE_LABEL) as ConnectorType[]).map((t) => (
          <option key={t} value={t}>
            {TYPE_LABEL[t]}
          </option>
        ))}
      </select>

      {type === "slack" ? (
        <p className="field-hint" data-testid="slack-scope-note">
          Product Slack: where approved analysis summaries are posted for your team. It is separate
          from the operators&apos; infrastructure alerts (Alertmanager), which are configured
          outside NLW.
        </p>
      ) : null}
      <label htmlFor="c-name">Name</label>
      <input
        id="c-name"
        placeholder={type === "slack" ? "product-slack" : undefined}
        aria-invalid={invalid("name")}
        aria-describedby={describedBy("name")}
        {...register("name", {
          validate: (v) => (v.trim() ? true : "Give this connector a name."),
          maxLength: { value: 120, message: "Use 120 characters or fewer." },
        })}
      />
      <FieldError id="c-name-error" message={errors.name?.message} />

      {type === "slack" ? (
        <>
          <label htmlFor="c-workspace_label">Slack workspace</label>
          <input
            id="c-workspace_label"
            placeholder="NLW Product Demo"
            aria-invalid={invalid("workspace_label")}
            aria-describedby={describedBy("workspace_label", true)}
            {...register("workspace_label", {
              validate: (v, all) =>
                all.type !== "slack" || v.trim() ? true : "Enter the Slack workspace's name.",
            })}
          />
          <p className="field-hint" id="c-workspace_label-hint">
            A label so people know which Slack workspace this posts to.
          </p>
          <FieldError id="c-workspace_label-error" message={errors.workspace_label?.message} />

          <label htmlFor="c-default_channel">Default channel ID</label>
          <input
            id="c-default_channel"
            placeholder="C0123ABCD"
            autoCapitalize="characters"
            spellCheck={false}
            aria-invalid={invalid("default_channel")}
            aria-describedby={describedBy("default_channel", true)}
            {...register("default_channel", {
              validate: (raw, all) => {
                if (all.type !== "slack") return true;
                const v = raw.trim();
                if (!v) return "Enter the channel ID for the default channel.";
                if (v.startsWith("#"))
                  return "Use the channel ID, not its name. In Slack, open the channel's details — the ID is at the bottom and starts with C.";
                if (!SLACK_CHANNEL_ID_RE.test(v))
                  return "Channel IDs start with C, G or D followed by capital letters and digits, for example C0123ABCD.";
                return true;
              },
            })}
          />
          <p className="field-hint" id="c-default_channel-hint">
            For example, the ID of #nlw-product-demo. Messages go only to this channel.
          </p>
          <FieldError id="c-default_channel-error" message={errors.default_channel?.message} />
        </>
      ) : null}

      {type === "postgres" ? (
        <>
          <label htmlFor="c-host">Host</label>
          <input
            id="c-host"
            aria-invalid={invalid("host")}
            aria-describedby={describedBy("host")}
            {...register("host", {
              validate: (v, all) =>
                all.type !== "postgres" || v.trim() ? true : "Enter the host.",
            })}
          />
          <FieldError id="c-host-error" message={errors.host?.message} />
          <label htmlFor="c-port">Port</label>
          <input id="c-port" type="number" inputMode="numeric" {...register("port")} />
          <label htmlFor="c-database">Database</label>
          <input
            id="c-database"
            aria-invalid={invalid("database")}
            aria-describedby={describedBy("database")}
            {...register("database", {
              validate: (v, all) =>
                all.type !== "postgres" || v.trim() ? true : "Enter the database name.",
            })}
          />
          <FieldError id="c-database-error" message={errors.database?.message} />
          <label htmlFor="c-schemas">Allowed schemas (comma-separated)</label>
          <input id="c-schemas" {...register("allowed_schemas")} placeholder="public" />
        </>
      ) : null}
      {type === "webhook" ? (
        <>
          <label htmlFor="c-url">Destination URL</label>
          <input
            id="c-url"
            type="url"
            aria-invalid={invalid("url")}
            aria-describedby={describedBy("url")}
            {...register("url", {
              validate: (v, all) =>
                all.type !== "webhook" || /^https:\/\/\S+$/.test(v.trim())
                  ? true
                  : "Enter an https:// address.",
            })}
          />
          <FieldError id="c-url-error" message={errors.url?.message} />
        </>
      ) : null}
      {type === "static" ? (
        <>
          <label htmlFor="c-label">Label (optional)</label>
          <input id="c-label" {...register("label")} />
        </>
      ) : null}

      <label htmlFor="c-secret_ref">Secret reference</label>
      <input
        id="c-secret_ref"
        placeholder={type === "slack" ? "SLACK_DEMO_BOT_TOKEN" : "PG_MAIN"}
        autoComplete="off"
        spellCheck={false}
        aria-invalid={invalid("secret_ref")}
        aria-describedby={describedBy("secret_ref", true)}
        {...register("secret_ref", {
          // Credential material is cleared the moment it is entered, so it never
          // stays in form state, on screen, or in a request.
          onChange: (e: React.ChangeEvent<HTMLInputElement>) => {
            const credential = secretRefProblem(e.target.value, "static") === "credential";
            if (credential) setValue("secret_ref", "");
            if (credential || e.target.value) setRejectedCredential(credential);
          },
          validate: (v, all) => {
            if (!v.trim() && rejectedCredential)
              return "That looks like a credential. Enter only the name of the secret your operator provisioned — never the token or URL itself.";
            const problem = secretRefProblem(v, all.type);
            if (problem === "required") return "Enter the secret reference name.";
            if (problem === "format" || problem === "credential")
              return "Use capital letters, digits and underscores, starting with a letter (for example SLACK_DEMO_BOT_TOKEN).";
            return true;
          },
        })}
      />
      <p className="field-hint" id="c-secret_ref-hint">
        {type === "slack"
          ? "The name of the Slack bot token your operator stored on the NLW server. "
          : "The name of the credential your operator stored on the NLW server. "}
        NLW never asks for, shows or stores the secret itself.
      </p>
      <FieldError id="c-secret_ref-error" message={errors.secret_ref?.message} />

      <div style={{ marginTop: 12 }}>
        <button type="submit" disabled={formState.isSubmitting || create.isPending}>
          {create.isPending ? "Adding…" : "Create connector"}
        </button>
      </div>
    </form>
  );
}
