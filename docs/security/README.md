# Security

Threat model and security posture. Tracks V1 requirements separately from later
hardening. Cross-cutting concerns (tenant isolation, secret redaction, SQL
safety, SSRF protection, audit trail) are implemented with the components they
protect, not deferred.

## Pilot guarantee — identity & connector authorization (M11.5 P1A)

The application role cannot enumerate or rewrite unrelated platform identities.
Connector mutation and credential attachment require workspace admin/owner
authority enforced by **both** the API and PostgreSQL. Secret aliases remain
tenant-scoped identifiers and do not independently confer member authority.
(Governing principle: authentication establishes identity; membership establishes
workspace access; role establishes mutation authority; a secret alias identifies
a secret, it never grants permission to use it. See ADR-003, ADR-006, ADR-011.)

**Identity bootstrap boundary (accurate).** The `resolve_or_create_user`
SECURITY DEFINER function returns **only an internal UUID**; it cannot read,
modify, or disclose another existing identity, and it never rewrites a stable
`auth_provider_id`. During normal execution its `auth_provider_id`/`email`
arguments come from the **verified JWT**, never request JSON. It does **not**
cryptographically authenticate its own arguments: arbitrary SQL running as
`nlw_app` could still call it with an unused provider id to create a
**junk/reserved** identity (a new row) — but never touch an existing user's row.
Its guaranteed protection is against **cross-user reads/updates and cross-user
mutation through the bootstrap function**, not against arbitrary `nlw_app` SQL.
Defending against a **forged complete request/identity context** (arbitrary
arguments or `app.user_id`) was deferred to the signed-context milestone — now
**delivered by M11.5 P3B / ADR-024** (below).

Deferred (explicitly not provided by P1A):

- signed DB request context — **delivered by P3B (migration `0016`,
  [ADR-024](../adr/ADR-024-signed-database-context.md))**: RLS trusts only
  HMAC-verified, purpose-bound, expiring `app.ctx_*` claims; bare
  `app.user_id`/`app.tenant_id` grant nothing. Not protected: a runtime
  compromised together with its key file, the owner credential, bypass roles or
  the superuser (HMAC is symmetric). Operator procedure:
  [runbooks/signed-context-keys.md](../runbooks/signed-context-keys.md);
- cloud/envelope-encrypted secret storage and rotation;
- self-service secret onboarding;
- connector destination binding to a durable credential entity;
- team invitations and separation-of-duties administration.

## PostgreSQL connector trust boundary (M11.5 P1B)

**Pilot guarantee.** PostgreSQL queries are limited by deterministic SQL
scope/function validation (lexical-scope table allowlisting + a default-deny
function allowlist), a read-only database session, and an external
least-privilege role. Production connections validate every resolved destination,
pin the connection to an approved address, preserve hostname verification, and
require `sslmode=verify-full`. See ADR-009 and ADR-012.

**Operator responsibilities for external databases.** The platform validator is
defense-in-depth, NOT a substitute for least-privilege external credentials. The
external database administrator must:

- grant the connector role only the approved tables/views (SELECT only);
- revoke unnecessary `USAGE` on schemas the connector should not reach;
- review and revoke executable functions where appropriate — especially avoid
  granting `EXECUTE` on unsafe `SECURITY DEFINER` functions (a read-only session
  does not stop them from returning protected data);
- not rely solely on platform SQL parsing.

**TLS / certificates (production/staging).** The connector requires
`sslmode=verify-full`, so the external database must present a certificate valid
for the configured hostname, chaining to a CA in the system trust store. The
connection is pinned to a validated IP (`hostaddr`) while the original hostname is
used for certificate verification.

**Private / non-public databases.** Production blocks private, loopback,
link-local/metadata, and platform-internal destinations by default. A legitimately
private approved database (e.g. staging on a private network) must be added to the
operator-owned `postgres_destination_allowlist` (exact IP / CIDR) — there is no
broad "disable SSRF protection" switch, and no tenant/connector field can enable a
private target in production.

**Limitations (deferred).** No claim that SQL parsing replaces external grants; no
arbitrary user-defined or schema-qualified functions in the pilot; DNS/network
controls reduce but do not eliminate credential-exfiltration risk; credentials
remain operator-managed.
