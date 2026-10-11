# O-2 AWS policy review (local, structural; NOT validated by AWS)

Scope: every IAM, trust, bucket, KMS and CloudTrail template in
[dataset-s3-provisioning.md](../runbooks/dataset-s3-provisioning.md), read
against ADR-033, the S3 store (`nlw.storage.s3`), credential handling
(`nlw.storage.s3_credentials`), migration 0028 and the dataset alert rules.

## Assurance model (round 3)

**Production isolation during D6 is an AWS-side control, not a property of
the reviewed shell.**

- **The boundary.** Every principal the proof uses, and every role it
  creates, carries the proof-principal permissions boundary
  ([provisioning §3.6](../runbooks/dataset-s3-provisioning.md#36-proof-principal-permissions-boundary-mandatory-for-d6)).
  It refuses anything named for production, any key tagged for production,
  every IAM escalation path, and changes to itself.
- **Account mode.** Decision E14 may instead put D6 in a dedicated proof
  account; the boundary stays mandatory there.
- **Credentials.** Human credentials are short-lived Identity Center sessions
  only (E11). No long-term access key is created or used.
- **Gate.** D6 is **blocked** until an independent verifier records the
  account, the principals, the attached boundary and their effective
  permissions (E15). P00-02 enforces that, and P01-02 re-checks it before
  anything is created.

**What the tests are.** Regression defence in depth, not proof of isolation:

- **Template checks:**
  - strict parsing: duplicate keys, and any `Effect` other than exactly
    `Allow` or `Deny`, are refused;
  - the six roles' Allow statements are pinned exactly, and every Allow in
    the key, bucket and trust policies is allow-listed by principal, action
    and condition;
  - every Deny, every policy's Sid set, both lifecycle rules and the event
    selectors are pinned exactly.
- **Procedure checks:** an allow-list of the AWS changes the procedure may
  make, plus execution of the proof's shell against a stub `aws`. **The stub
  run does not observe every possible AWS call** (round-3 F1): it misses a
  call on a branch the stub's generic answers never take, an `aws` binary
  given by absolute path, and an SDK call inside a heredoc.

**What this review is.** A reading of the JSON as written, plus those
contract tests: `test_dataset_s3_provisioning_templates.py`
and `test_dataset_s3_d6_proof.py`. **What it is not.** No policy has been sent
to AWS, run through IAM Access Analyzer's policy validation, or evaluated by
the IAM policy simulator. AWS can still reject a template, or evaluate a
condition differently from this reading. Those questions belong to the
[D6 proof](../runbooks/dataset-s3-d6-proof.md), which has not run.

## Properties checked

| Property | Where it is enforced | Local check | Proof step |
|---|---|---|---|
| Least privilege | Each role allows only the actions ADR-033 lists; no `*` action, no `NotAction` or `NotResource` in an Allow; every Allow is scoped to the bucket's `versions/` prefix, the environment key, or one named role | `test_allows_are_least_privilege`, `test_role_capabilities_match_the_identity_model` | P03-11, P08–P11 |
| Explicit cross-environment denial | Dataset bucket `DenyOtherEnvironmentRoles`; every dataset role has `NeverOtherEnvironment` (all `nlw-<OTHER_ENV>-*` buckets, unconditional); every role holding KMS access has `NeverOtherEnvironmentKeys` (keys not tagged `nlw-env=<ENV>`); the bootstrap role denies all S3 and KMS | `test_cross_environment_access_is_explicitly_denied` | P10 |
| Immutable conditional writes | `DenyUnconditionalCreate` (no `If-None-Match` on object creation in `versions/`), `DenyServerSideCopy`; no runtime delete | existing `test_the_dataset_bucket_policy_is_deny_only_and_keeps_write_once_and_tls`, `test_conditional_writes_and_copy_are_enforced` | P05, P07 |
| Required SSE-KMS headers | Four separate denies: algorithm missing, key missing, algorithm not `aws:kms`, key not exactly `<KEY_ARN>`; no `…IfExists` | existing `test_every_creation_request_must_name_sse_kms_and_the_environment_key` | P06, P07 |
| Exact environment KMS key | `DenyWrongSseKmsKey` compares the full ARN; KMS key-policy grants require `kms:ViaService` = S3 in us-east-1 and the bucket's encryption context | `test_key_policies_split_encrypt_from_decrypt_and_never_let_admins_use_keys` | P06 |
| Version-aware operator purge | Only the operator role holds `s3:DeleteObjectVersion`; plain `s3:DeleteObject` is granted to nobody; the bucket denies both to every other principal | `test_runtime_roles_can_never_delete` | P11, P12 |
| No runtime deletion | API, ingest and bootstrap hold no `s3:Delete*`; bucket `DenyDeleteExceptOperator` | `test_runtime_roles_can_never_delete`, `test_every_deny_and_every_sid_is_pinned` (DenyDeleteExceptOperator pinned exactly) | P11 |
| No operator-role assumption by the instance role | Bootstrap allows `sts:AssumeRole` on exactly the API and ingest roles and denies every other role (`NotResource`); the operator trust allows only named humans with MFA, denies any session without MFA context, and denies the bootstrap and runtime roles by name | `test_the_instance_role_can_never_become_the_operator`, `test_human_roles_require_mfa` | P12 |
| CloudTrail and audit-bucket tamper protection | Every dataset role denies the trail, audit bucket and audit key, and denies altering any trail; the audit bucket denies dataset roles and every delete or retention change except by the audit administrator; Object Lock; log-file validation; no statement grants scheduling the audit key's deletion, so that needs a key-policy change first, which the account root and delegated administrators can make and the management-event trail must record | existing audit tests, `test_audit_tamper_protection_is_complete`, `test_every_deny_and_every_sid_is_pinned` (every audit Deny pinned exactly, including its condition) | P11, P13 |
| API and ingest credential separation | Separate roles, trust policies requiring different session names, separate credential files and mounts; only the API may generate data keys, in both the role policies and the key policy | `test_api_and_ingest_credentials_are_separate` | P14, P15 |
| No IMDS fallback | The SDK credential chain is replaced by one provider that reads only the file (`s3_credentials._session`); IMDSv2 with hop limit 1; host firewall drop | existing `test_the_sdk_chain_is_pinned_to_the_file_and_never_falls_back`; `test_the_credential_chain_has_no_fallback`; `test_the_proof_instance_requires_imdsv2_with_hop_limit_one`. P14-04 shows only that a missing file is refused with IMDS reachable; mid-run expiry with IMDS reachable is untested until P14-05 runs | P03-14, P14-04, P14-05 |

## Findings fixed in this change

| Id | Finding | Fix |
|---|---|---|
| **F1** | The dataset key policy granted `kms:GenerateDataKey` to the ingest and operator roles. A key-policy statement naming a role is sufficient on its own in the same account, so the role policies' narrower grants did not limit it. The D6 item "the ingest role cannot generate data keys" would have failed. | Split into an API statement (`GenerateDataKey`, `Decrypt`) and a decrypt-only statement for ingest and operator. |
| **F2** | The operator role had no cross-environment deny. The ingest role's deny covered buckets but not keys. The API's bucket deny depended on a resource tag. | All four dataset roles now carry an unconditional deny on every `nlw-<OTHER_ENV>-*` bucket and object; roles with KMS access also deny keys not tagged for their environment. |
| **F3** | Trust policies existed only as prose, so MFA and the bootstrap-to-operator boundary were not reviewable or testable. | Templates `trust-bootstrap`, `trust-api`, `trust-ingest` and `trust-human-mfa`. MFA is enforced by an Allow condition and by two denies, one for a missing MFA key (`Null`) and one for `false`, keeping the template free of `…IfExists`. |
| **F4** | The bootstrap role's limits were only the absence of grants. Another attached policy could have widened them. | Explicit denies: every role except API and ingest (`NotResource`), and all S3 and KMS. |
| **F5** | The key policies showed one statement each. The administration statement, and whether the account root could use the keys, were unstated. | A full dataset key policy and an audit key administration statement: root and the administrator may manage but never use the key; no statement grants the audit key's deletion, so it needs a key-policy change first (residual risk R3). |
| **F6** | `CopyObject` was possible: the API role's `PutObject` and `GetObject` grants allow a server-side copy of one stored object to another key. | `DenyServerSideCopy` on any request with `x-amz-copy-source`. |
| **F7** | The audit administrator and audit reader roles had no templates; the audit lifecycle rule was prose. | Templates `role-audit-admin`, `role-audit-reader` and `audit-bucket-lifecycle`. |

## Accepted residual risks (unchanged by this review)

| Id | Risk | Why accepted | Evidence in the proof |
|---|---|---|---|
| **R1** | The API role can read object bytes, because `HeadObject` requires `s3:GetObject`. | ADR-033 note 1: the code calls only head and attributes; every read is a data event. | P08-01 records it as allowed and audited |
| **R2** | The ingest role can read any object under `versions/`, across workspaces. | ADR-033 note 2: exact-object access is enforced in the application against the claimed version; every read is a data event. | P09-02 records it as allowed and audited |
| **R3** | The account root (through delegated IAM administrators) and `<ADMIN_ROLE>` may rewrite a key policy, and with it grant themselves use. | Recoverability of the key; such a change is a management event in the account trail (decision E7). | none; reviewed with E7 |
| **R4** | Whether the encryption denies refuse `UploadPart` or `CompleteMultipartUpload` is not stated by AWS documentation. | No exception is added; a refusal stops the proof (S3) and changes the design instead. | P07 |
| **R5** | The production-side cross-environment checks are simulations: production resources do not exist. | Creating production-named principals for a staging proof is refused. | P10 |
| **R6** | The credential refresher is not built. The stand-in cannot show systemd scheduling, retry and backoff, ownership and mode, tmpfs, reboot behaviour or the refresh-failure alert. | It ships with O-6, where those become proof items. | P14 shows application-side rotation and expiry only |
| **R7** | API and ingest containers both run as uid 10001; isolation between their credentials rests on separate read-only mounts. | Acceptable while the refresher is unbuilt; O-6 must give them separate runtime users. | none |
| **R8** | Principals other than the six dataset and audit roles (account administrators) may pass the bootstrap role or launch an instance with it, and so obtain API and ingest credentials. | Restricting them needs an account-level control outside this repository (decision E12). | P03-11 checks the principals E12 lists |
| **R9** | `CreateBucket` in us-east-1 succeeds for a bucket the account already owns. A same-account principal racing the proof between `HeadBucket` and `CreateBucket` with an empty, unconfigured bucket would pass the pristine checks. | The random proof suffix makes accidental collision negligible; a deliberate race needs an insider who could alter the bucket anyway, and the management trail records it. | P03-06, P03-07 |
| **R11** | MFA for human sessions is enforced by IAM Identity Center's sign-in settings, which IAM policy cannot see. | Identity Center sessions carry no `aws:MultiFactorAuthPresent` after role chaining; the independent gate record attests MFA (E15). | P00-03 sign-in |
| **R12** | The stub run of the procedure is not exhaustive (F1). | Production isolation rests on the AWS-side boundary, independently verified; the stub run is regression defence. | P01-02 |
| **R10** | Whether the data-event selector records bucket-level `ListBucket`/`ListBucketVersions` is not established. | Decision E13 after P13 observes it. | P13 |

## Unresolved AWS behaviour (D6 decides; nothing is inferred)

| Id | Question | Where the proof answers it |
|---|---|---|
| **I1** | Whether CloudTrail delivers log and digest files into an Object Lock bucket whose default encryption is SSE-KMS under a key policy that conditions on `aws:cloudtrail:arn` | P13 (S6), including `validate-logs` |
| **I2** | Whether an alias, a bare key id or a non-existent key ARN in the encryption header is refused with `AccessDenied` (bucket policy) or a KMS error | P06-01; a KMS error is S9, not a security failure |
| **I3** | IAM cannot stop the API from re-creating a key whose versions were all purged (`If-None-Match` succeeds when no version exists); only the database guard prevents reuse | not an AWS proof item |
| **I4** | The API may abort any multipart upload whose id it knows; listing is denied, so this is denial of service at most | not an AWS proof item |
| E-MPU | Whether the encryption-header denies refuse `UploadPart` or `CompleteMultipartUpload` (R4) | P07 (S3) |
| M5 | Whether KMS applies `aws:ResourceTag` conditions to the tag-on-create authorization in `TagOnlyUntaggedKeys` | P03-04 |

## Security review of PR #60 (round 1) — dispositions

| Finding | Correction | Test or negative control |
|---|---|---|
| **H1** existing-bucket takeover in us-east-1 | `HeadBucket` absence in the same block; random proof suffix; pristine checks (no tags, no policy, no versions) before any configuration; ledger bound to the proof id; S2 on difference; race documented (R9) | `test_bucket_creation_is_guarded_in_the_same_block`; controls for a missing absence check, a configuration before the pristine checks, and a non-random suffix |
| **H2** tests accepted privilege escalations | Round 1 checked every statement whose `Effect` was exactly `Allow` against principal allow-lists and pinned role Allows. **Round 2 (N1, N2) found that a lowercase or duplicated `Effect`, duplicate JSON keys, or a neutralised Deny still passed;** see the round-2 table. | the seven escalations from the review |
| **M1** production via a variable | Round 1 resolved variables statically. **Round 2 (N3) found that substitutions, indirect or case-converted variables, ledger values and helper functions still passed;** the procedure is now executed against a stub `aws`. | `$OTHER_BUCKET`, `${PROD_KEY}`, concatenation |
| **M2** unledgered objects after an unexpected success | R-OBJ: X10 (operator, exact proof prefixes, post-start versions only) and X11 (administrator, one exact key); recovered ids feed X04; X05 still refuses anything unrecorded | controls for a widened prefix, a missing start-time check, and X05 removed |
| **M3** Identity Center and MFA | Decision E11, required before D6; P00 refuses anything but `iam-user-mfa` | decision and guard tests |
| **M4** multipart fallback understated | The fallback is an application change and a new review | text test |
| **M5** audit admin could re-tag any key | `TagOnlyUntaggedKeys` requires `Null aws:ResourceTag/nlw-env` | control removing the condition |
| **L1** missing configuration actions | Replication, inventory, analytics, metrics, Intelligent-Tiering and acceleration denied on both buckets | controls removing replication or inventory |
| **L2** overclaims | Audit-key deletion and IMDS wording corrected; P14-05 added | text tests |
| **L3** reviewed commit | P00 and `render` require HEAD = `REVIEWED_COMMIT` and a clean tree | wrong-commit and dirty-tree controls, run against a temporary repository |
| **L4** stop ids | S10 for failed commands (an `EXIT` handler since round 2; round 1 used an `ERR` trap) and a create with no identifier; S4 unexpected success; S8 cleanup safety | stop-enforcement test |
| **L5** list events | Documented as open, observed in P13, decision E13 (R10) | decision test |
| **L6** shallow procedure parsing | Commands are tokenised (global options, substitutions, multi-line quotes). **Round 2 (N4) found that wrappers such as `timeout`, `xargs`, `nohup`, `sudo -u` and `bash -c` hid calls;** they are now refused statically and caught by execution. | one control each |
| **L7** PassRole and budget | Explicit `NeverPassOrAttachDatasetRoles` on six roles; P03-11 simulation; decision E12; P03-00 creates and verifies the budget alert, described as an alert, not enforcement | controls removing the deny and the budget verification |
| **L8** shared uid | R7 | — |
| **L9** stand-in limits | Listed at P14 and in R6 | — |
| **L10** cleanup identity | X01 checks the exact trail, instance-profile, bucket, budget and proof-id values; X02 checks the trail's and instance profile's tags and ARNs | controls removing either |

## Security review of PR #60 (round 2, fresh reviewer at `fbc48ea`) — dispositions

| Finding | Correction | Tests and negative controls |
|---|---|---|
| **N1** lowercase or duplicated `Effect`, duplicate JSON keys | Templates are parsed with a duplicate-key hook; every statement must carry a Sid, only known keys, and `Effect` exactly `Allow` or `Deny`; anything not exactly `Deny` is checked as an Allow. `render` refuses duplicate keys and a non-canonical `Effect` too | lowercase `allow` in the key and audit-bucket policies, duplicate `Effect`, duplicate `Action`, missing `Effect` |
| **N2** Denies could be neutralised | Every policy template's Sid set and every Deny statement (principal, actions, resources, condition) is pinned exactly in `tests/fixtures/dataset_s3_policy_pins.json`; `DenyOutsideAccount` and every other Deny are mandatory | inert conditions on six Denies, a narrowed resource, `role/*` exemptions on three, `DenyOutsideAccount` removed, a Deny turned into an Allow |
| **N3** production by indirection | Every step after P00-02, with `lib.sh`, is executed by bash against a stub `aws` that records its fully expanded arguments; PATH holds only stubs and local tools; the real AWS CLI is never reachable. Any production name in a MUTATING step or in a mutating call fails, and every statically parsed call must actually execute **Round 3 (F1) showed the stub run can still be evaded; it is now regression defence only, and the AWS-side boundary is the control.** | command substitution, `${!T}`, `${E,,}`, a ledger value, a `lib.sh` helper, `timeout`, `xargs`, `bash -c`, `nohup`, `sudo -u`, `aws s3 cp` |
| **N4** wrappers hid calls | An `aws` word in any position other than the command is refused, as is `aws` inside a `bash -c`/`eval` string; execution catches the rest | one static control per wrapper |
| **N5** undefined credential source | **Superseded in round 3:** the Keychain model used long-term access keys, and a key could outlive the run (F6). Human credentials are now short-lived Identity Center sessions only; no access key is created; X08 removes only this run's cached tokens and sessions, matched by the run id in their names (F8). | key in the config, undefined source profile, a step printing the credential, age-based cache deletion, Keychain kept, §F weakened, P00-02 key check removed; X08's cache cleanup executed against a fake cache |
| **N6** non-`put` changes before the pristine checks | Any mutating call between `create-bucket` and the ledger entry is refused | `delete-bucket-policy` inserted |
| **N7** `--key=`, `aws s3 cp`, `delete-objects` | Keys are parsed from `--key`, `--key=` and `--delete`; high-level `aws s3` is refused | one control each |
| **N8** open uploads lost | X10 also lists open uploads under the two prefixes (newer than the run) and records them; X04 aborts them by id | listing removed, age check removed, abort removed |
| **N9** human lists unvalidated; drift unchecked | `validate_humans` (IAM users of the approved account; no wildcard, root, role, other account, duplicate or operator/audit-admin overlap) runs before any role is created; `render` validates and re-serialises the list; P03-11 compares every trust, inline, key, bucket and lifecycle policy and the selectors after normalisation **Round 3 (F2, F5, F7):** P03-11 also checks each role's attached policies and boundary, the keys' grants, both buckets' controls, both keys' rotation and the audit bucket's encryption; simulations fail closed; the lists are matched in full (no trailing newline, F9). | eleven validation cases executed through `lib.sh`; four `render` refusals including injection; normaliser equivalence and drift; comparison removed |
| **N10** orphaned bucket | P03-06/07 journal the absence check; X12 recovers an unrecorded bucket only if it carries this run's suffix, the journal shows this run confirmed it absent, and it is still empty and unconfigured | suffix check removed; journal note removed |
| **N11** trap and rotator | No `set -E` and no ERR trap; an EXIT handler runs registered cleanups and records S10 with the failing command; P14-02 registers the rotator's kill-and-wait | executed on every available bash (3.2 locally, 5 in CI): guarded substitution gives no S10, a failure in a function names its command, a background process does not outlive a stop; `set -E` and missing cleanup are detected |
| **N12** consistency | P00-01 exports only; P00-02 verifies and extracts with a manifest; every later step runs through `run-step`, which refuses a modified file; the S2 row, A.1 suffix, E8 role-name form (checked in `lib.sh`), the 63-character name limit and E11's identity check (P00-03) are corrected | run-step refuses a tampered step; ADMIN_ROLE as an ARN is refused; five text controls |

**What the stub execution does not show.** It runs the shell with fake AWS
answers, so it shows which commands the procedure issues on the paths the
stub's answers lead to. It does not show:

- how AWS responds;
- a call on a branch only real answers take (coverage is per step and per
  service and operation, not per call site);
- an `aws` binary given by absolute path;
- an SDK call.

It is defence in depth. The boundary is the control (round 3).

## Security review of PR #60 (round 3, fresh reviewer at `77b2013`) — dispositions

| Finding | Correction | Tests and negative controls |
|---|---|---|
| **F1** the stub run can be evaded | **Assurance model changed:** the stub run is regression defence only, and the claims are narrowed. Production isolation is the mandatory proof-principal boundary (and optionally a dedicated account, E14), verified independently before D6 (E15) and again in P01-02 | gate and boundary checks; boundary weakening controls |
| **F2** the procedure could grant extra privileges | An allow-list of the AWS changes the procedure may make (no `attach-*-policy`, permissions-boundary change, `create-grant`, access key or hand-written inline policy; every `create-role` carries the boundary); P03-11 checks each role has exactly its inline policy, no attached policy and exactly the boundary, and both keys have no grant. The boundary refuses the same escalations in AWS | static controls for each; `verify_role_shape` and `verify_no_grants` executed against a fake `aws` that reports AdministratorAccess attached, an unexpected boundary, an extra inline policy, a grant, or a failed listing |
| **F3** lifecycle rules unchecked | Both lifecycle rules and the event selectors are pinned whole | expiry added, scope widened, audit noncurrent expiry shortened, selectors narrowed; a drifted deployed lifecycle stops `same` |
| **F4** flaky harness | Each stub writes one record per write | 10 of 10 consecutive runs pass |
| **F5** E12 simulation failed open | `sim_denied`: an error or empty result is S9, any non-deny is S4; the E12 list is validated first | executed against a fake `aws`: empty, error and allowed results |
| **F6** a key could outlive the run | No long-term key exists any more (Identity Center only) | a step creating an access key, or P00-02 accepting IAM users, is detected |
| **F7** P03-11 checked less than claimed | Audit-bucket encryption, both keys' rotation, both buckets' public-access block and ownership controls are checked | `verify_bucket_controls` executed against missing or partial controls |
| **F8** X08 deleted other runs' sessions | Matched by this run's id in the session and SSO-session names | X08 executed against a cache with another run's, another account's and look-alike entries |
| **F9** trailing newline accepted | Full matches in `validate_principals` and `render` | newline cases executed for both |
| **F10** tree and manifest gaps | P00-02 requires `RUNBOOK_DIR` to be the reviewed checkout's runbook directory; `aws-config` is in the manifest. The manifest beside its files still detects only accidental drift (documented) | P00-02 executed with a foreign runbook tree, no gate, a mismatched gate and long-term credentials |
| **F11** "never reachable" | The claim now says what isolation the tests rely on: PATH holds only stubs and local tools, and the proxy variables point nowhere | — |
| **F12** expected-denied writes to the audit bucket | Must target `$BUCKET` | a write to `$AUDIT_BUCKET` is detected |
| **F13** a dataset role as `ADMIN_ROLE` | `lib.sh` refuses `nlw-*-dataset-*` | executed with two dataset role names |

## Limits of this local validation

- **No AWS evaluation.** Syntax, action names, condition keys and their
  behaviour for each S3 operation are as read, not as AWS evaluates them.
- **Sizes are counted locally.** Every template is rendered by the proof's
  own `render` helper with dummy values and measured without whitespace
  against AWS's documented limits. The largest are the bucket policy (3,063
  of 20,480 characters), the audit-admin role (2,008 of 10,240) and the human
  trust policy (888 of 2,048). AWS's own counter was not consulted.
- **No AWS command was run.** The proof's shell is syntax-checked (`bash -n`)
  and executed end to end against a stub `aws` (bash 3.2 locally, bash 5 in
  CI); every template renders completely; the probe's offline refusals run
  against the application code. The real AWS CLI was never invoked, so flags,
  error codes and output shapes are from the documentation, and nothing here
  shows how AWS evaluates any policy.
- **Simulator caveats.** `simulate-custom-policy` with a resource policy may
  refuse a caller that does not exist (P10-02 says what to do).
