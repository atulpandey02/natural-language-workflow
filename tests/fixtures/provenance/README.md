# Release-provenance test fixtures

Attestation envelopes in the exact shape `gh attestation verify --format json`
prints (gh 2.78: Fulcio certificate extensions + SLSA v1 in-toto statement), for
`manifest.json` (a CI-style manifest whose bytes hash to the attested subject).
They carry NO real signature: the unit tests exercise the POLICY evaluation only
(`nlw.ops.release_provenance.evaluate_attestation` / `evaluate_run`); the real
signature/transparency-log verification is `gh`'s job and is exercised end to end
by the Delivery workflow's proof job and the PR negative proof in CI.

Never point a rollout at these files: they are not release authority.
