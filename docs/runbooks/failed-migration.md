# Failed / partial migration

**Symptoms:** deploy step `alembic upgrade head` failed; `/health/ready` →
`schema: down` (DB revision ≠ expected head).

**Do:**
1. Do NOT switch traffic to the new image. Readiness will keep it out of rotation.
2. Inspect: `alembic current`, `alembic history`, and the migration error.
3. Fix forward where possible (correct the migration, re-run `upgrade head`).
4. If you must roll back the image, redeploy the previous **schema-compatible**
   digest. Image rollback does NOT auto-downgrade the DB; only run a deliberate
   `alembic downgrade` if that specific migration is safely reversible.
5. Re-verify readiness returns `schema: ok` before restoring traffic.
