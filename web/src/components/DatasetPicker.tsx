"use client";
import { useEffect, useRef } from "react";
import { useDatasets } from "@/lib/api/analytics-hooks";
import { ErrorBanner, Loading } from "./ui";

export function DatasetPicker({
  onSelect,
  preselect = null,
}: {
  onSelect: (prompt: string) => void;
  preselect?: string | null;
}) {
  const datasets = useDatasets();
  const applied = useRef(false);
  useEffect(() => {
    if (applied.current || !preselect || !datasets.data) return;
    const match = datasets.data.find((d) => d.id === preselect);
    if (match) {
      applied.current = true;
      onSelect(match.prompt);
    }
  }, [preselect, datasets.data, onSelect]);
  return (
    <section aria-label="Golden analytical use cases">
      <div className="section-heading">
        <h2>Start with a question</h2>
        <span className="muted small">Versioned synthetic data</span>
      </div>
      {datasets.isLoading ? <Loading label="Loading sample datasets…" /> : null}
      <ErrorBanner error={datasets.error} />
      {datasets.data?.length === 0 ? (
        <p className="notice">
          Synthetic pilot datasets are not enabled in this environment. You can still plan with your
          available connectors.
        </p>
      ) : null}
      <div className="dataset-grid">
        {datasets.data?.map((d) => (
          <button
            type="button"
            className="dataset-card"
            key={d.id}
            onClick={() => onSelect(d.prompt)}
            aria-describedby={`example-${d.id}`}
          >
            <span className="dataset-symbol" aria-hidden="true">
              {d.id === "sales-v1" ? "↗" : "◎"}
            </span>
            <strong>{d.name}</strong>
            <span>
              {d.id === "sales-v1"
                ? "Find the trends behind your revenue."
                : "Understand service quality and operational risk."}
            </span>
            <small>
              {d.rows.toLocaleString()} records · {d.grain}
            </small>
            <small>Synthetic historical snapshot · {d.as_of}</small>
            <small className="dataset-example" id={`example-${d.id}`}>
              Example: “{d.prompt}”
            </small>
          </button>
        ))}
      </div>
    </section>
  );
}
