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

Deferred (explicitly not provided by P1A):

- signed/non-forgeable DB request context (GUCs remain forgeable by the app role);
- cloud/envelope-encrypted secret storage and rotation;
- self-service secret onboarding;
- connector destination binding to a durable credential entity;
- team invitations and separation-of-duties administration.
