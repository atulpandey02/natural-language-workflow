"use client";

import { useState } from "react";
import { ErrorBanner } from "@/components/ui";
import { useConfirmSemantics } from "@/lib/api/dataset-hooks";
import { COMPATIBLE_ROLES, COMPATIBLE_TYPES, analysisLock, proposeSemantics } from "@/lib/datasets";
import type {
  ProfileView,
  SemanticColumn,
  SemanticRevisionOut,
  SemanticRole,
  SemanticType,
} from "@/lib/api/types";

/** Start from the latest confirmed revision when it fits this profile. */
function initial(profile: ProfileView, latest: SemanticRevisionOut | undefined): SemanticColumn[] {
  const proposed = proposeSemantics(profile);
  const confirmed = latest?.mapping.columns;
  if (!confirmed || confirmed.length !== proposed.length) return proposed;
  return proposed.map((p) => confirmed.find((c) => c.name === p.name) ?? p);
}

/**
 * Proposed column meanings for a person to review and confirm. Nothing is
 * applied until an admin or owner presses Confirm; the API validates every
 * choice against the closed vocabularies and the profile.
 */
export function SemanticsForm({
  datasetId,
  versionId,
  profile,
  latest,
}: {
  datasetId: string;
  versionId: string;
  profile: ProfileView;
  latest: SemanticRevisionOut | undefined;
}) {
  const confirm = useConfirmSemantics(datasetId, versionId);
  const [columns, setColumns] = useState<SemanticColumn[]>(() => initial(profile, latest));
  const [done, setDone] = useState<number | null>(null);

  function update(i: number, patch: Partial<SemanticColumn>) {
    setDone(null);
    setColumns((cols) =>
      cols.map((c, j) => {
        if (j !== i) return c;
        const next = { ...c, ...patch };
        // Keep the combination one the API accepts.
        if (!COMPATIBLE_ROLES[next.semantic_type].includes(next.role))
          next.role = COMPATIBLE_ROLES[next.semantic_type][0];
        if (analysisLock(profile.columns[i], next)) next.analysis_allowed = false;
        return next;
      }),
    );
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (confirm.isPending) return;
    try {
      const rev = await confirm.mutateAsync(columns);
      setDone(rev.revision_number);
    } catch {
      // Shown by ErrorBanner below.
    }
  }

  return (
    <form onSubmit={submit} aria-labelledby="semantics-title" data-testid="semantics-form">
      <h3 id="semantics-title">Column meanings</h3>
      <p className="muted small">
        {latest
          ? `Revision ${latest.revision_number} is confirmed. Changing and confirming again records a new revision.`
          : "These are proposals from the profile. Review each column, then confirm."}
      </p>
      <ErrorBanner error={confirm.error} />
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Column meanings">
        <table>
          <thead>
            <tr>
              <th>Column</th>
              <th>Label</th>
              <th>Meaning</th>
              <th>Role</th>
              <th>Analysable</th>
            </tr>
          </thead>
          <tbody>
            {columns.map((c, i) => {
              const col = profile.columns[i];
              const lock = analysisLock(col, { ...c, analysis_allowed: true });
              const base = `sem-${i}`;
              return (
                <tr key={c.name}>
                  <th scope="row">{col.header}</th>
                  <td>
                    <label className="sr-only" htmlFor={`${base}-label`}>
                      Label for {col.header}
                    </label>
                    <input
                      id={`${base}-label`}
                      value={c.label}
                      maxLength={80}
                      onChange={(e) => update(i, { label: e.target.value })}
                    />
                  </td>
                  <td>
                    <label className="sr-only" htmlFor={`${base}-type`}>
                      Meaning of {col.header}
                    </label>
                    <select
                      id={`${base}-type`}
                      value={c.semantic_type}
                      onChange={(e) => update(i, { semantic_type: e.target.value as SemanticType })}
                    >
                      {COMPATIBLE_TYPES[col.inferredType].map((t) => (
                        <option key={t} value={t}>
                          {t}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <label className="sr-only" htmlFor={`${base}-role`}>
                      Role of {col.header}
                    </label>
                    <select
                      id={`${base}-role`}
                      value={c.role}
                      onChange={(e) => update(i, { role: e.target.value as SemanticRole })}
                    >
                      {COMPATIBLE_ROLES[c.semantic_type].map((r) => (
                        <option key={r} value={r}>
                          {r}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <input
                      id={`${base}-allowed`}
                      type="checkbox"
                      checked={c.analysis_allowed}
                      disabled={Boolean(lock)}
                      aria-describedby={lock ? `${base}-lock` : undefined}
                      onChange={(e) => update(i, { analysis_allowed: e.target.checked })}
                    />{" "}
                    <label htmlFor={`${base}-allowed`} className="sr-only">
                      Allow analysis of {col.header}
                    </label>
                    {lock ? (
                      <span className="muted small" id={`${base}-lock`}>
                        {lock}
                      </span>
                    ) : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <div className="row">
        <button type="submit" disabled={confirm.isPending}>
          {confirm.isPending ? "Confirming…" : "Confirm column meanings"}
        </button>
      </div>
      <p role="status" aria-live="polite" className="muted small">
        {done ? `Column meanings confirmed (revision ${done}).` : ""}
      </p>
    </form>
  );
}
