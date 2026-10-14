import { INDICATOR_LABEL, WARNING_LABEL } from "@/lib/datasets";
import type { ProfileView } from "@/lib/api/types";

/**
 * The value-free profile: structure, counts, detected types, sensitivity
 * indicators and warnings. It renders ONLY the allowlisted view from
 * `profileView`; no cell value, minimum, maximum, mean or digest reaches here.
 */
export function ProfileTable({ profile }: { profile: ProfileView }) {
  return (
    <section aria-labelledby="profile-title" data-testid="profile">
      <h3 id="profile-title">Profile</h3>
      <p className="muted small">
        {profile.rows.toLocaleString()} rows · {profile.columnCount} columns · {profile.encoding}.
        Only structure and counts are shown, never the values themselves.
      </p>
      {profile.warnings.length ? (
        <ul className="small">
          {profile.warnings.map((w) => (
            <li key={w}>{WARNING_LABEL[w]}</li>
          ))}
        </ul>
      ) : null}
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Column profile">
        <table>
          <thead>
            <tr>
              <th>Column</th>
              <th>Detected type</th>
              <th>Filled</th>
              <th>Empty</th>
              <th>Distinct</th>
              <th>Notes</th>
            </tr>
          </thead>
          <tbody>
            {profile.columns.map((c) => (
              <tr key={c.name}>
                <td>
                  <strong>{c.header}</strong>
                  {c.header !== c.name ? <span className="muted small"> ({c.name})</span> : null}
                </td>
                <td>{c.inferredType}</td>
                <td>{c.nonNull.toLocaleString()}</td>
                <td>{c.nulls.toLocaleString()}</td>
                <td>
                  {c.distinct === null ? "—" : c.distinct.toLocaleString()}
                  {c.distinctOverLimit ? "+" : ""}
                </td>
                <td className="small">
                  {[
                    ...c.indicators.map((i) => INDICATOR_LABEL[i]),
                    ...c.warnings.map((w) => WARNING_LABEL[w]),
                  ]
                    .filter(Boolean)
                    .join("; ") || "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
