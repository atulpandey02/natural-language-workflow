"use client";

import { useState } from "react";
import { useForm, useWatch } from "react-hook-form";
import { useCreateConnector } from "@/lib/api/hooks";
import { ErrorBanner } from "@/components/ui";

type ConnectorType = "postgres" | "webhook" | "slack" | "static";

interface FormValues {
  type: ConnectorType;
  name: string;
  secret_ref: string;
  // type-specific
  host?: string;
  port?: string;
  database?: string;
  allowed_schemas?: string;
  url?: string;
  default_channel?: string;
  label?: string;
}

function buildConfig(v: FormValues): Record<string, unknown> {
  switch (v.type) {
    case "postgres":
      return {
        host: v.host,
        port: v.port ? Number(v.port) : 5432,
        database: v.database,
        allowed_schemas: (v.allowed_schemas || "public")
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      };
    case "webhook":
      return { url: v.url };
    case "slack":
      return v.default_channel ? { default_channel: v.default_channel } : {};
    case "static":
      return v.label ? { label: v.label } : {};
    default:
      return {};
  }
}

export function ConnectorForm({ onCreated }: { onCreated?: () => void }) {
  const create = useCreateConnector();
  const { register, handleSubmit, control, reset, formState } = useForm<FormValues>({
    defaultValues: { type: "postgres", name: "", secret_ref: "" },
  });
  const type = useWatch({ control, name: "type" });
  const [ok, setOk] = useState(false);

  async function onSubmit(values: FormValues) {
    setOk(false);
    await create.mutateAsync({
      type: values.type,
      name: values.name,
      config: buildConfig(values),
      secret_ref: values.secret_ref ? values.secret_ref.toUpperCase() : null,
    });
    setOk(true);
    reset({ type: values.type, name: "", secret_ref: "" });
    onCreated?.();
  }

  return (
    <form className="card" onSubmit={handleSubmit(onSubmit)} noValidate>
      <h2 style={{ marginTop: 0, fontSize: 16 }}>Add a connector</h2>
      <ErrorBanner error={create.error} />
      {ok ? <p className="muted">Connector created.</p> : null}

      <label htmlFor="c-type">Type</label>
      <select id="c-type" {...register("type")}>
        <option value="postgres">postgres</option>
        <option value="webhook">webhook</option>
        <option value="slack">slack</option>
        <option value="static">static</option>
      </select>

      <label htmlFor="c-name">Name</label>
      <input id="c-name" {...register("name", { required: true })} />

      {type === "postgres" ? (
        <>
          <label htmlFor="c-host">Host</label>
          <input id="c-host" {...register("host")} />
          <label htmlFor="c-port">Port</label>
          <input id="c-port" type="number" {...register("port")} defaultValue={5432} />
          <label htmlFor="c-db">Database</label>
          <input id="c-db" {...register("database")} />
          <label htmlFor="c-schemas">Allowed schemas (comma-separated)</label>
          <input id="c-schemas" {...register("allowed_schemas")} placeholder="public" />
        </>
      ) : null}
      {type === "webhook" ? (
        <>
          <label htmlFor="c-url">Webhook URL</label>
          <input id="c-url" {...register("url")} />
        </>
      ) : null}
      {type === "slack" ? (
        <>
          <label htmlFor="c-chan">Default channel (optional)</label>
          <input id="c-chan" {...register("default_channel")} />
        </>
      ) : null}
      {type === "static" ? (
        <>
          <label htmlFor="c-label">Label (optional)</label>
          <input id="c-label" {...register("label")} />
        </>
      ) : null}

      <label htmlFor="c-secret">Secret reference</label>
      <input id="c-secret" {...register("secret_ref")} placeholder="PG_MAIN" />
      <p className="muted" style={{ marginTop: 4 }}>
        Enter only the secret <em>reference</em> name. The actual credential is pre-provisioned by
        an operator in the worker environment — this console never sees or stores secret values.
      </p>

      <div style={{ marginTop: 12 }}>
        <button type="submit" disabled={formState.isSubmitting || create.isPending}>
          {create.isPending ? "Creating…" : "Create connector"}
        </button>
      </div>
    </form>
  );
}
