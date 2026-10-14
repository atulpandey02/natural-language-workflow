// Shared fixtures for the dataset journey tests (not a test file itself).
import type { DatasetVersionOut } from "@/lib/api/types";
import type { KeyValueStore } from "@/lib/datasets";

export function version(over: Partial<DatasetVersionOut> = {}): DatasetVersionOut {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    dataset_id: "22222222-2222-4222-8222-222222222222",
    version_number: 1,
    status: "QUARANTINED",
    original_filename: "orders.csv",
    media_type: "text/csv",
    declared_size_bytes: 120,
    content_sha256: null,
    rejection_code: null,
    created_by: "33333333-3333-4333-8333-333333333333",
    created_at: "2026-10-14T10:00:00Z",
    activated_at: null,
    superseded_at: null,
    rejected_at: null,
    deletion_requested_at: null,
    has_content: false,
    profiling_started_at: null,
    profiled_at: null,
    ...over,
  };
}

export function memoryStore(): KeyValueStore & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return {
    data,
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => void data.set(k, v),
    removeItem: (k) => void data.delete(k),
  };
}

export const PROFILE = {
  contract_version: "profile-2",
  content_sha256: "a".repeat(64),
  size_bytes: 120,
  encoding: "utf-8",
  delimiter: ",",
  header_rows: 1,
  row_count: 3,
  column_count: 3,
  formula_like_cells: 0,
  distinct_limit: 1000,
  warnings: ["UTF8_BOM", "SOMETHING_NEW"],
  columns: [
    {
      position: 0,
      header: "Region",
      name: "region",
      inferred_type: "string",
      non_null_count: 3,
      null_count: 0,
      null_fraction: 0,
      distinct_count: 2,
      distinct_over_limit: false,
      min_value: null,
      max_value: null,
      mean: null,
      min_length: 5,
      max_length: 5,
      parse_error_count: 0,
      formula_like_count: 0,
      indicators: [],
      warnings: [],
    },
    {
      position: 1,
      header: "Amount",
      name: "amount",
      inferred_type: "decimal",
      non_null_count: 3,
      null_count: 0,
      null_fraction: 0,
      distinct_count: 3,
      distinct_over_limit: false,
      min_value: "SENTINEL-MIN-901",
      max_value: "SENTINEL-MAX-902",
      mean: 903.25,
      parse_error_count: 0,
      formula_like_count: 0,
      indicators: [],
      warnings: [],
    },
    {
      position: 2,
      header: "Email",
      name: "email",
      inferred_type: "string",
      non_null_count: 3,
      null_count: 0,
      null_fraction: 0,
      distinct_count: 3,
      distinct_over_limit: false,
      parse_error_count: 0,
      formula_like_count: 0,
      indicators: ["possible_email"],
      warnings: ["NOT_A_REAL_WARNING"],
      storage_key: "versions/t/d/v/source.csv",
    },
  ],
};
