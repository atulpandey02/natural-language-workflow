"""Phased, gated staging rollout for the signed-context upgrade (M12A-Prep).

``python -m nlw.ops.rollout`` drives the existing Compose deployment on the
staging host through explicit phases. The default invocation is READ-ONLY
(``preflight``); every mutating phase re-verifies the target identity, the
immutable release pins, the current migration revision and the operator gates
(authorization phrase, escrow attestation, verified off-host backup, clean
drain) before touching anything. Nothing here prints or transports secret
values: key material stays in files on the host, credentials stay in the host's
``.env.prod`` / ``.env.backup``, and the rollout state file records metadata
only.
"""
