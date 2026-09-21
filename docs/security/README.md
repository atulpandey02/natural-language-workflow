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
arguments or `app.user_id`) is deferred to the signed/non-forgeable-context
milestone (below).

Deferred (explicitly not provided by P1A):

- signed/non-forgeable DB request context (GUCs remain forgeable by the app role);
- cloud/envelope-encrypted secret storage and rotation;
- self-service secret onboarding;
- connector destination binding to a durable credential entity;
- team invitations and separation-of-duties administration.
