# Rotate a connector secret

Secrets are resolved in the worker only, by tenant-scoped env var
`NLW_SECRET_<TENANT_HEX>_<SECRET_REF>` (EnvironmentSecretStore). Connector rows
store only a stable `secret_ref`, so rotation never touches the database.

**Do:**
1. Update the env value for `NLW_SECRET_<TENANT_HEX>_<SECRET_REF>` in the worker's
   git-ignored secrets env_file (or your secret source).
2. Recreate/restart the worker so it picks up the new value. No API/scheduler
   change (they never receive `NLW_SECRET_*`).
3. Verify by triggering a run that uses the connector; confirm success in
   `nlw_action_attempts_total` / logs (secrets never appear in logs).
4. (Pre-production) A cloud secret-manager backend behind the SecretStore
   abstraction will make rotation versioned and hot — see ADR-018.
