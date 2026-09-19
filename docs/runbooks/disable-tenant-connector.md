# Disable a tenant connector

**When:** a connector's credentials are compromised/expired or it is misbehaving.

**Do:**
1. Set the connector `status = 'disabled'` for the tenant (authorized, audited DB
   update). The engine refuses disabled connectors at resolution time
   (`ConnectorDisabledError`), failing the step deterministically.
2. Rotate the credential if compromised (see rotate-secret).
3. Re-enable by setting status back to `unchecked`; the next use re-runs the
   health check before activation.
