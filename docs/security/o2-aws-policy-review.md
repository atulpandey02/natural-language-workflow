# O-2 AWS policy review (local, structural; NOT validated by AWS)

Scope: every IAM, trust, bucket, KMS and CloudTrail template in
[dataset-s3-provisioning.md](../runbooks/dataset-s3-provisioning.md), read
against ADR-033, the S3 store (`nlw.storage.s3`), credential handling
(`nlw.storage.s3_credentials`), migration 0028 and the dataset alert rules.

## Assurance model (round 6)

**Scope: a synthetic-data staging pilot (E16, decided by the owner).** Every
object D6 writes is synthetic; no customer, personal or production data may
reach the proof account or staging until a later review. Residual risks
R15–R21 are accepted for that scope only and are blockers before real data;
the gate record must say `data_scope: synthetic-only` in every mode.

**The dedicated proof account limits the blast radius (E14).** D6 runs only
in an AWS account that is none of the staging or production accounts and
holds no production resource. The six roles are created trusting only that
account's principals, and P03-11, P03-15 and P15-03 check it; nothing stops
the provisioner from re-creating a role with another trust, or rewriting the
dataset bucket policy to grant another account, between those checks (R16,
R17). P00-02, P01-01 and P01-03 refuse any other account. The account does
not replace least privilege inside it.

**Three separated functions, three machines (E9).**

| Function | May | May never |
|---|---|---|
| provisioner | create the six roles with their trust, exact inline policies and exact boundaries; the dataset bucket and key, the instance, the budget; **operate the proof instance, and through it use the API and ingest roles (R15)**; delete and re-create four roles (R17) | with its own permission set: assume any of the six roles; read, write or delete a dataset object; touch the trail, audit bucket, audit key or alias; update a trust policy in place; change or remove a boundary |
| dataset operator | assume the operator role, bounded to listing, reading and version-aware deletion under `versions/` | any IAM change, including to its own role; anything on the audit side |
| audit administrator / reader | assume the audit roles; read (never change) the six roles and the proof policies | any IAM change, including to its own roles; the dataset roles, bucket and key |

- **Enforced by policy, as written** ([provisioning §3.6–3.7](../runbooks/dataset-s3-provisioning.md#36-proof-identities-boundaries-and-the-deny-policy-dedicated-proof-account-mandatory-for-d6)):
  the operator and audit permission sets deny every IAM write
  (`NeverChangeIam`); the provisioner denies itself the proof roles, dataset
  objects and the audit side; every created role carries its own exact
  boundary, which equals that role's reviewed Allows; the provisioner may
  create a role only with its own boundary, and nobody can change one. AWS
  has not evaluated any of it.
- **Attested, not enforced:** that three different people hold the three
  functions (IAM sees permission-set roles, not people), or, in single-owner
  mode (R21), that one authorized owner uses a separate OS account, profiles
  and sessions per function; that Identity
  Center requires MFA (R11); that the account's administrators hold none of
  the functions.
- **Machines:** each machine's configuration holds only its own profiles,
  and every step refuses a machine whose configuration or CLI cache holds a
  profile or session **named** for another persona; another permission set's
  profile under a different name is not detected (R19). Values move between
  machines only as schema-checked handoff files: proof id, commit, ledger
  values, expected events and evidence hashes. The sender is not
  authenticated and the evidence hashes are carried, not verified (R20).
- **Residual authority (R13, R14):** the account root, the organization's
  management account and Identity Center administrators can override all of
  this; the provisioner shapes the six roles, which the audit side checks
  independently at P03-15 and again at P15-03 (R14, R17).
- **Gate:** D6 is **blocked** until the owner approves the dedicated account,
  its identities and the three people, and an independent verifier records
  them (E15). P00-02 reads the record from the reviewed commit on
  `origin/main` with `git show`, binds it to its parent procedure commit with
  a rename-disabled diff, and refuses any mismatch. Templates and steps are
  rendered from the reviewed commit, never from the working tree.

**Boundaries are upper bounds.** The permission-set boundary's actions are
the union of the four permission sets' actions; it is broader than
that union by resource only where a resource is not known before the run
(bucket names, key ids, EC2 resources, and IAM reads of arbitrary E12
principals), each listed in §3.6. Each role boundary equals its role's
Allows with only those substitutions.

**What the tests are.** Regression evidence, not proof of isolation:

- **Template checks:** strict parsing; every role's and permission set's
  Allows pinned exactly; every Deny, Sid set, lifecycle rule and event
  selector pinned; the permission-set boundary's actions equal to the union
  of the four permission sets; each role boundary equal to its role.
- **Procedure checks:** every `render` names an existing template and every
  template is rendered; every session name comes from one helper; each
  machine's configuration holds only its own profiles; an allow-list of the
  AWS changes the procedure may make.
- **Execution against a stub `aws`.** P00-02 runs on each machine and every
  step on its own machine through `run-step`; the run fails at once on any
  answer-independent error. Each executed call is matched against one
  reviewed tuple of step, machine, profile, service, operation, resource
  values and argument names. **The stub run does not observe
  every possible AWS call:** a branch the stub's answers never take, an API
  call made inside a composite CLI command (`validate-logs`, `wait`), or a
  call the static scan fails to recognise, is not seen. It is regression
  evidence, not a security boundary.

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
| No operator-role assumption by the instance role | Bootstrap allows `sts:AssumeRole` on exactly the API and ingest roles and denies every other role (`NotResource`); the operator trust (`trust-human`) allows only the named operator permission-set roles with a run-scoped session name, denies every principal that is not an Identity Center role, and denies the bootstrap and runtime roles by name. MFA is not checked by any policy (R11) | `test_the_instance_role_can_never_become_the_operator`, `test_human_roles_admit_only_identity_center_sessions` | P12 |
| Separation of the three functions (E9) | Operator and audit permission sets deny every IAM write family; the provisioner's permission set denies itself the proof roles, dataset objects and the audit side; each created role carries its own exact boundary; boundaries cannot change and trust cannot be updated in place. **Not enforced:** the provisioner uses the API and ingest roles through the instance (R15) and can re-create four roles (R17); different people are attested | `test_operator_and_audit_sides_are_separated`, `test_every_created_role_has_an_exact_boundary`, `test_negative_control_a_replaced_role_is_caught_at_the_end` | P01-02, P03-11, P03-15, P15-03 |
| Dedicated proof account (E14) | P00-02 gate (`dedicated`, distinct from listed staging and production ids), P01-01 and P01-03 (caller account, organization against the gate, no production-named or production-tagged resource) | `test_d6_is_blocked_until_an_independent_verification_record_exists`, P00-02 executed controls | P01 |
| CloudTrail and audit-bucket tamper protection | Every dataset role denies the trail, audit bucket and audit key, and denies altering any trail; the audit bucket denies dataset roles and every delete or retention change except by the audit administrator; Object Lock; log-file validation; no statement grants scheduling the audit key's deletion, so that needs a key-policy change first, which the account root and delegated administrators can make and the management-event trail must record | existing audit tests, `test_audit_tamper_protection_is_complete`, `test_every_deny_and_every_sid_is_pinned` (every audit Deny pinned exactly, including its condition) | P11, P13 |
| API and ingest credential separation | Separate roles, trust policies requiring different session names, separate credential files and mounts; only the API may generate data keys, in both the role policies and the key policy | `test_api_and_ingest_credentials_are_separate` | P14, P15 |
| No IMDS fallback | The SDK credential chain is replaced by one provider that reads only the file (`s3_credentials._session`); IMDSv2 with hop limit 1; host firewall drop | existing `test_the_sdk_chain_is_pinned_to_the_file_and_never_falls_back`; `test_the_credential_chain_has_no_fallback`; `test_the_proof_instance_requires_imdsv2_with_hop_limit_one`. P14-04 shows only that a missing file is refused with IMDS reachable; mid-run expiry with IMDS reachable is untested until P14-05 runs | P03-14, P14-04, P14-05 |

## Findings fixed in this change

| Id | Finding | Fix |
|---|---|---|
| **F1** | The dataset key policy granted `kms:GenerateDataKey` to the ingest and operator roles. A key-policy statement naming a role is sufficient on its own in the same account, so the role policies' narrower grants did not limit it. The D6 item "the ingest role cannot generate data keys" would have failed. | Split into an API statement (`GenerateDataKey`, `Decrypt`) and a decrypt-only statement for ingest and operator. |
| **F2** | The operator role had no cross-environment deny. The ingest role's deny covered buckets but not keys. The API's bucket deny depended on a resource tag. | All four dataset roles now carry an unconditional deny on every `nlw-<OTHER_ENV>-*` bucket and object; roles with KMS access also deny keys not tagged for their environment. |
| **F3** | Trust policies existed only as prose, so MFA and the bootstrap-to-operator boundary were not reviewable or testable. | Templates `trust-bootstrap`, `trust-api`, `trust-ingest` and `trust-human-mfa`. **Superseded in round 3:** `trust-human-mfa` became `trust-human`, which admits only Identity Center permission-set roles; its MFA conditions were removed because chained Identity Center sessions carry no MFA key. No policy enforces MFA (R11). |
| **F4** | The bootstrap role's limits were only the absence of grants. Another attached policy could have widened them. | Explicit denies: every role except API and ingest (`NotResource`), and all S3 and KMS. |
| **F5** | The key policies showed one statement each. The administration statement, and whether the account root could use the keys, were unstated. | A full dataset key policy and an audit key administration statement: root and the administrator may manage but never use the key; no statement grants the audit key's deletion, so it needs a key-policy change first (residual risk R3). |
| **F6** | `CopyObject` was possible: the API role's `PutObject` and `GetObject` grants allow a server-side copy of one stored object to another key. | `DenyServerSideCopy` on any request with `x-amz-copy-source`. |
| **F7** | The audit administrator and audit reader roles had no templates; the audit lifecycle rule was prose. | Templates `role-audit-admin`, `role-audit-reader` and `audit-bucket-lifecycle`. |

## Accepted residual risks (unchanged by this review)

| Id | Risk | Why accepted | Evidence in the proof |
|---|---|---|---|
| **R1** | The API role can read object bytes, because `HeadObject` requires `s3:GetObject`. | ADR-033 note 1: the code calls only head and attributes; every read is a data event. | P08-01 records it as allowed and audited |
| **R2** | The ingest role can read any object under `versions/`, across workspaces. | ADR-033 note 2: exact-object access is enforced in the application against the claimed version; every read is a data event. | P09-02 records it as allowed and audited |
| **R3** | The account root (through delegated IAM administrators) and the key's administrator may rewrite a key policy, and with it grant themselves use. In D6 the provisioner's own policy grants no `kms:PutKeyPolicy`; the audit-admin role may change the audit key's. | Recoverability of the key; such a change is a management event in the account trail (decision E7). | none; reviewed with E7 |
| **R4** | Whether the encryption denies refuse `UploadPart` or `CompleteMultipartUpload` is not stated by AWS documentation. | No exception is added; a refusal stops the proof (S3) and changes the design instead. | P07 |
| **R5** | The production-side cross-environment checks are simulations: production resources do not exist. | Creating production-named principals for a staging proof is refused. | P10 |
| **R6** | The credential refresher is not built. The stand-in cannot show systemd scheduling, retry and backoff, ownership and mode, tmpfs, reboot behaviour or the refresh-failure alert. | It ships with O-6, where those become proof items. | P14 shows application-side rotation and expiry only |
| **R7** | API and ingest containers both run as uid 10001; isolation between their credentials rests on separate read-only mounts. | Acceptable while the refresher is unbuilt; O-6 must give them separate runtime users. | none |
| **R8** | Principals of the proof account other than the proof's own (its administrators) may pass the bootstrap role or launch an instance with it, and so obtain API and ingest credentials. | In the dedicated account they are the account's administrators (R13); the proof principals may pass only the bootstrap role, only to EC2 (decision E12). | P03-11 checks the principals E12 lists |
| **R9** | `CreateBucket` in us-east-1 succeeds for a bucket the account already owns. A same-account principal racing the proof between `HeadBucket` and `CreateBucket` with an empty, unconfigured bucket would pass the pristine checks. | The random proof suffix makes accidental collision negligible; a deliberate race needs an insider who could alter the bucket anyway, and the management trail records it. | P03-06, P03-07 |
| **R11** | **No policy in this package enforces MFA.** Whether sign-in requires it is an IAM Identity Center setting, which IAM policy cannot see and nothing here checks. | Identity Center sessions carry no `aws:MultiFactorAuthPresent` after role chaining; the independent gate record attests the setting (E15). | none; attested only |
| **R12** | The stub run of the procedure is not exhaustive (round-3 F1). | Production isolation rests on the dedicated account; the stub run, its executed-call allow-list and the static scan are regression evidence. | none |
| **R13** | The proof account's root user, the organization's management account and Identity Center administrators can change the boundaries, the deny policy, the permission sets and their assignments, and so undo every control inside the account, including E9 separation. | They are outside the proof. The gate records that they hold none of the three functions (E15); their changes are management events in the account trail (E7). | P01-02 and P03-15 compare every proof identity and policy with its template |
| **R14** | The provisioner shapes the six roles: it can rewrite their inline policies (within each role's own boundary) and delete and re-create the four dataset roles. Its permission set cannot assume any of them, update a trust policy in place, or change a boundary; it does use the API and ingest roles through the proof instance (R15), and re-creation can change a trust (R17). | Someone must provision IAM; for a synthetic-data pilot (E16) this keeps that power away from the operator and audit people. | P03-15 and P15-03 check every role with the audit reader's identity (P15-03 also its `RoleId`); the account trail records every change |
| **R15** | **The provisioner operates the proof instance** (P03-10 to P03-14 over SSH, P04–P11, P12-02, P14 and P15), whose instance profile is the bootstrap role, so it exercises the API and ingest roles there, including reading and writing dataset objects under `versions/`. Its own permission set cannot, but that does not separate the person from the data. P13-01 checks only that expected events exist. | Synthetic data only (E16). P13-01 lists object events no expected line explains (`p13-unexplained.txt`) for the audit person to explain; it sees events up to P12 only, not P14–P15. **Blocker before real data:** give the instance to an identity the provisioner does not hold. | P13-01 (observation) |
| **R16** | The dataset bucket policy and the dataset key policy are compared with the templates only by the provisioner (P03-11). The provisioner's permission set may rewrite the bucket policy at any time; a grant to another account (for example `s3:DeleteObjectVersion`, which needs no KMS access) would not be caught by the audit side, whose permission sets deny every dataset bucket and key action. | Synthetic data only (E16); bucket-policy and key-policy changes are management events in the account trail (E7). **Blocker before real data:** an audit-side read of both policies, which needs a reviewed carve-out of the audit denies. | P03-11 (provisioner only) |
| **R17** | No IAM condition can constrain a trust policy's content. With `RemoveTheDatasetRoles` and the create statements, the provisioner can delete the bootstrap, API, ingest and operator roles and re-create them with any trust (another account included), each still with its own boundary. P03-15 and P15-03 check every role, and P15-03 also requires the `RoleId` P03-15 recorded, so a replacement before P15-03 is caught; one between P15-03 and cleanup is not. Re-running P03-15 (a recovery path) re-records the role ids, so a replacement before that re-run is re-baselined; the journal records each P03-15 run. | Synthetic data only (E16); role deletion and creation are management events (E7). **Blocker before real data:** deny `iam:DeleteRole` to the provisioner until cleanup, or verify at cleanup too. | P03-15, P15-03 |
| **R18** | The executed-call allow-list pins only resource-option values and argument names. Values of `--ip-permissions`, `--public-access-block-configuration`, `--metadata-options`, `--action-names`, `--ssekms-key-id` and object keys are not pinned, so a change to them passes the stub run; P03-11 does not inspect the security group's ingress. | It is regression evidence only (stated). Those values come from the reviewed text, which reviewers read. **Before real data:** pin them, and add the security group to P03-11. | none |
| **R19** | `isolation.py` recognises another persona's profile, SSO token or cached role session by the proof's own names; the same permission set configured under another name on the wrong machine is not detected. | Separation of people is attested (E9, E15), not enforced; the policies still constrain each identity. | P00-02, every step (by name only) |
| **R20** | Handoff files are not authenticated: whoever carries one can choose any schema-valid values (for example which object keys the operator deletes). The evidence SHA-256 and the step are carried but never verified on import, and the credential patterns cannot detect every secret in a free-text event field. | Values are schema- and pattern-checked; the operator deletes only keys under the proof's prefixes, which X01/X02 check; synthetic data only (E16). | `handoff_import` (schema and patterns only) |
| **R21** | **Single-owner mode** (`separation: single-owner`, E9): if three real participants are unavailable, one authorized owner holds the provisioner, operator and audit functions, each from its own OS account, profiles and sessions. The identities and policies stay separate; the people are not, so nothing separates provisioning, operating and auditing. | Synthetic data only: the gate record must say `data_scope: synthetic-only` (E16) in every mode, and P00-02 refuses anything else. **Blocks real customer data** until three people hold the functions. The independent verifier (E15) is still required. | P00-02 gate (`separation`, `people`, `data_scope`) |
| **R10** | Whether the data-event selector records bucket-level `ListBucket`/`ListBucketVersions` is not established. | Decision E13 after P13 observes it. | P13 |

## Unresolved AWS behaviour (D6 decides; nothing is inferred)

| Id | Question | Where the proof answers it |
|---|---|---|
| **I1** | Whether CloudTrail delivers log and digest files into an Object Lock bucket whose default encryption is SSE-KMS under a key policy that conditions on `aws:cloudtrail:arn` | P13 (S6), including `validate-logs` |
| **I2** | Whether an alias, a bare key id or a non-existent key ARN in the encryption header is refused with `AccessDenied` (bucket policy) or a KMS error | P06-01; a KMS error is S9, not a security failure |
| **I3** | IAM cannot stop the API from re-creating a key whose versions were all purged (`If-None-Match` succeeds when no version exists); only the database guard prevents reuse | not an AWS proof item |
| **I4** | The API may abort any multipart upload whose id it knows; listing is denied, so this is denial of service at most | not an AWS proof item |
| E-MPU | Whether the encryption-header denies refuse `UploadPart` or `CompleteMultipartUpload` (R4) | P07 (S3) |
| M5 | Whether KMS applies `aws:ResourceTag` conditions to the tag-on-create authorization in `TagOnlyUntaggedKeys`, and in the provisioner's `TagOnlyNewDatasetKeys` | P03-02, P03-04 |
| **I5** | That Identity Center provisions a permission set's inline policy as exactly one role policy named `AwsSSOInlinePolicy`, its customer-managed policy as an attached managed policy, and its boundary as the role's permissions boundary, and that `aws:PrincipalArn` of its sessions is the `aws-reserved/sso.amazonaws.com/` role ARN | P01-02 (a difference is S9; nothing is relaxed) |
| **I6** | Whether `AddRoleToInstanceProfile` checks `iam:PassRole`, and with what `iam:PassedToService` | P03-01 (a refusal is S10) |
| **I7** | That the boundaries are complete for every call each step makes, including actions a CLI command needs implicitly (for example `create-key` with tags, `create-bucket` with Object Lock, `run-instances` with tag specifications and an encrypted volume, `validate-logs`' `GetBucketLocation`) | P03, P13 (a refusal is S10; a boundary is changed only by review) |
| **I8** | Whether `GetBucketLifecycleConfiguration` returns fields beyond `Rules` (for example `TransitionDefaultMinimumObjectSize`); the comparison uses only `Rules` either way | P03-11, P03-15 |

## Security review of PR #60 (round 1) — dispositions

| Finding | Correction | Test or negative control |
|---|---|---|
| **H1** existing-bucket takeover in us-east-1 | `HeadBucket` absence in the same block; random proof suffix; pristine checks (no tags, no policy, no versions) before any configuration; ledger bound to the proof id; S2 on difference; race documented (R9) | `test_bucket_creation_is_guarded_in_the_same_block`; controls for a missing absence check, a configuration before the pristine checks, and a non-random suffix |
| **H2** tests accepted privilege escalations | Round 1 checked every statement whose `Effect` was exactly `Allow` against principal allow-lists and pinned role Allows. **Round 2 (N1, N2) found that a lowercase or duplicated `Effect`, duplicate JSON keys, or a neutralised Deny still passed;** see the round-2 table. | the seven escalations from the review |
| **M1** production via a variable | Round 1 resolved variables statically. **Round 2 (N3) found that substitutions, indirect or case-converted variables, ledger values and helper functions still passed;** the procedure is now executed against a stub `aws`. | `$OTHER_BUCKET`, `${PROD_KEY}`, concatenation |
| **M2** unledgered objects after an unexpected success | R-OBJ: X10 (operator, exact proof prefixes, post-start versions only) and X11 (administrator, one exact key); recovered ids feed X04; X05 still refuses anything unrecorded | controls for a widened prefix, a missing start-time check, and X05 removed |
| **M3** Identity Center and MFA | Decision E11, required before D6. **Superseded in round 3:** P00-02 now refuses anything but `identity-center`, and no policy enforces MFA (R11) | decision and guard tests |
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
| **N9** human lists unvalidated; drift unchecked | **Superseded in round 3:** the lists are now Identity Center permission-set role ARNs, checked by `validate_principals sso`. Originally `validate_humans` (IAM users of the approved account; no wildcard, root, role, other account, duplicate or operator/audit-admin overlap) runs before any role is created; `render` validates and re-serialises the list; P03-11 compares every trust, inline, key, bucket and lifecycle policy and the selectors after normalisation **Round 3 (F2, F5, F7):** P03-11 also checks each role's attached policies and boundary, the keys' grants, both buckets' controls, both keys' rotation and the audit bucket's encryption; simulations fail closed; the lists are matched in full (no trailing newline, F9). | eleven validation cases executed through `lib.sh`; four `render` refusals including injection; normaliser equivalence and drift; comparison removed |
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

It is regression evidence. Since round 4 the dedicated account is the
control; before that it was the boundary (round 3).

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

## Security review of PR #60 (round 3 follow-up, fresh reviewer at `0fc24f1`) — dispositions

| Finding | Correction | Tests and negative controls |
|---|---|---|
| **H1** P03-01 rendered the removed `trust-human-mfa` | Every `render` now names a template that exists, and every template is rendered | `test_every_render_names_an_existing_template_and_every_template_is_rendered` (static, loops and `make_role` resolved); the stub run fails at once on a missing template (S10) |
| **H2** P12-03 expected the old session name | One helper, `session_name`, builds every session name; P12-03 checks the exact ARN `…:assumed-role/nlw-staging-dataset-operator/nlw-d6-<PROOF_ID>-operator` | `test_every_session_name_is_proof_scoped_and_matches_its_profile`; the stub answers identities from the generated `aws-config`, so a wrong name stops the run |
| **L2** the stub run masked broken steps | The stub run uses the real `lib.sh` exit semantics: a render failure, missing template, S10, malformed `aws-config`, identity mismatch or other answer-independent stop fails the run immediately | missing template, wrong session name, unexpected command failure, malformed configuration |
| **F2** executed calls were not checked | **Partly fixed in round 4; completed in round 5 (N6).** Round 4 compared every executed call with `EXECUTED_CALLS` but checked service, operation, steps, profiles and resource values independently and missed `--opt=value` and `--cli-input-json`; records are written atomically, one file each, and a malformed or incomplete record fails the run; static scanning refuses calls through variables, absolute paths, wrappers, subprocesses and SDK/SigV4 code as defence in depth | `cli=aws; "$cli" ssm send-command`; unexpected STS, IAM, KMS, S3 and CloudTrail operations; an allowed operation from the wrong step; an allowed operation on an unexpected resource; an absolute path; `boto3` in a heredoc |
| **B1–B3** boundary too broad; name patterns; no permission-set policies | **E14 now requires a dedicated proof account**, which limits the blast radius. The boundary is an upper bound naming the six exact role ARNs; a separate deny policy carries the mandated denies; four permission sets have exact inline policies. (Round 4 called the boundary "exactly the union"; it is that by action only, and broader by resource where listed in §3.6.) | allow-list pinned per Sid and equal to the identity union by action; one control per mandated deny; exact role ARNs |
| **B4** E9 separation unenforced | **Not closed in round 4** (round-5 N1): each side could rewrite the roles it administered, and those roles carried only the shared boundary. Superseded by the round-5 identity model | — |
| **M1** gate read from the working tree | `git show "$REVIEWED_COMMIT:…"`; the record must be tracked, name the parent procedure commit, and be the only change; no untracked or ignored file under `docs/runbooks` or `docs/evidence`; the record must say `approved` | `.git/info/exclude`, an untracked replacement, a working-tree edit, a gate from another commit, a gate commit that also changes the procedure, a mismatched commit inside the gate |
| **L1** `sed` broke on `#` | `render-config.py` fills each value literally after a per-value pattern check and requires the result to parse | an SSO URL with `#` renders byte for byte; a newline is refused |
| **F6 leftover** dead `AKIA` case in X01 | removed | text check |
| **Executability, found by the stricter run** | Defects the old stub run hid, each now fixed: the instance bundle lacked `aws-config`, so `run-step` failed on the instance (P03-12 now renders it and writes the bundle's own manifest); the instance had no `evidence/` directory, so P14-02 and P14-03 would fail (P03-13 creates it); P15-01 treated a missing probe line as S10 instead of S9; X12 looked for the absence note after P16 had sanitised the account id out of the journal (the note is now written in sanitised form). Found by reading: both key policies and the audit-admin role lacked `kms:ListGrants` for P03-11, and the audit-key alias needed IAM permission before phase 2 (`AuditKeyAlias`) | the stub run executes every step, including the instance steps, through `run-step` and fails on each of these |

**Overclaims corrected:** the claim that the boundary refused every escalation route; MFA described as
enforced (P03-04, P12, X10, provisioning §3.5, E11); the round-1 F3 and M3
and round-2 N9 rows (now marked superseded); the owner's administrator role
(A.1 and "How to read the commands"); E9's separation of duties; E15's
"in the reviewed commit"; P01-02 "re-checks effective permissions" (it
compares the policies and runs spot-check simulations); P03-11's scope (it
now lists what it does not check); and the stub run's coverage.

## Security review of PR #60 (round 4, fresh reviewer at `c800e61`) — dispositions

| Finding | Correction | Tests and negative controls |
|---|---|---|
| **N1** separation bypassable through the roles each side administered | **Corrected in round 6:** the provisioner does use the API and ingest roles through the instance (R15), and re-creation can change a trust (R17); the claims below are its permission set's. Three functions. The operator and audit permission sets deny every IAM write (`NeverChangeIam`) and create no role; the provisioner creates all six roles, may assume none (`NeverUseTheProofRoles`), reads no dataset object (`NeverDatasetObjects`), touches nothing of the audit side, and has no `UpdateAssumeRolePolicy`. Every created role carries its own exact boundary (`boundary-<role>`, equal to its Allows); the provisioner may create a role only with its own boundary, and nobody can change or remove one. P03-11 and, with the audit reader's identity, P03-15 check every role's trust, inline policy, managed policies, boundary and tags, and both keys' grants | each identity rewriting itself or another, a role boundary widened or missing, a created role without its boundary, `UpdateAssumeRolePolicy` granted, the provisioner assuming a role or reading an object; `verify_created_role` against a fake `aws` for every field |
| **N2** both people's sessions on one workstation | **Corrected in round 6:** detection is by the proof's own names (R19), and handoffs are not authenticated (R20). Provisioner, operator and audit machines; each `aws-config` holds only its persona's profiles; `isolation.py` (P00-02 and every step) refuses another persona's profile, SSO token or role session; steps are labelled with their machine and `run-step` refuses another machine's step; values move only as schema-checked handoffs | mixed profiles, a foreign SSO token, a foreign role session, a foreign profile in `~/.aws/config`, a step run on the wrong machine; handoffs with another run, commit or direction, an unreviewed name, a malformed value, a credential |
| **N3** `validate-logs` needs `GetBucketLocation` | `LocateAuditBucket` on the audit reader and its boundary, the exact audit bucket only | the reader's Allows pinned; no other bucket-level or object action added |
| **N4** lifecycle responses carry extra fields | `same_rules` compares only `Rules`, each rule whole and in ID order; both lifecycle documents are pinned whole | an extra response field passes; a missing, extra or altered rule (status, filter, expiry, noncurrent, abort-multipart) is S9 |
| **N5** templates rendered from the working tree | `render` reads `git show "$REVIEWED_COMMIT:…"`; P00-02 and `verify_reviewed_commit` refuse skip-worktree and assume-unchanged files and a working tree differing from the commit; the reviewed commit must be on `origin/main`; the ledger schema, `ledger.py`, `isolation.py`, `steps.json` and the session configuration are in the manifest, and the ledger is parsed, never sourced | skip-worktree, assume-unchanged, an ignored replacement, a differing working-tree template, a commit not on `origin/main`, a drifted session variable, a ledger line outside the schema |
| **N6** allow-list bypasses and cross products | **Corrected in round 6:** argument values other than resources are not pinned (R18); regression evidence only. Each executed call must match one reviewed tuple: step, machine, profile, service, operation, resource values and argument names together; `--opt=value` is split; `--cli-input-json` and any unreviewed argument fail; `file://` arguments must name reviewed files; high-level `aws s3` fails | the same operation in the wrong step, as the wrong persona, on the wrong bucket; `--bucket=other`; `--cli-input-json`; a foreign `file://` |
| **N7** rename-blind only-change check | `git diff --name-only --no-renames` | a file renamed into the gate path |
| **N8** simulations without region context | Every simulation carries `aws:RequestedRegion=us-east-1`; `sim_expect` requires exactly one expected decision per action (`explicitDeny`, `implicitDeny` or `allowed`); an error, an empty, short or unknown result, or a different deny, is S9 | empty, error, short, ambiguous and wrong-deny results through a fake `aws` |
| **N9** operational readiness | The boundary is described as an upper bound with every resource broadening listed; the reviewed commit's relation to `main` is checked against `origin/main` as fetched, and its limits stated; P03-13 waits for cloud-init; `verify_tools` pins the AWS CLI per machine (the gate records both pins) and checks `jq`, `python3`, `git` and Docker | an unpinned or different CLI, a missing tool, cloud-init not finished |

**Overclaims corrected in round 5:** "exactly the union" (by action only);
"F2 fixed" in round 4 (partly; completed here); B4 in round 4 (not closed);
the round-4 E9 wording; the "owner's administrator" and "proof
administrator" descriptions; and the claim that the account alone is what
matters (it limits blast radius; least privilege is separate).

## Security review of PR #60 (round 6, fresh reviewer at `4e03f83`) — dispositions

Round 6 also integrated `main` at `f57f75d` (PRs #61–#63) and rescoped D6 to a
synthetic-data staging pilot (E16). Each finding is corrected, or stated as a
residual risk where it cannot be enforced in this package.

| Finding | Correction | Tests and negative controls |
|---|---|---|
| **F1** the provisioner uses the API and ingest roles through the instance; "touches no dataset object" was false | Every such claim corrected (proof intro, P01-02, P03-01, provisioning §3.6, E8, E9, this review); residual **R15**; P13-01 now lists object events no expected line explains (`p13-unexplained.txt`) for the audit person | text and label tests; P13-01 runs in the stub harness |
| **F2** dataset bucket and key policies checked only by the provisioner | Residual **R16**, with a blocker before real data (an audit-side read needs a reviewed carve-out of the audit denies) | — |
| **F3** trust unconstrained at creation; roles re-creatable after the independent check | **P15-03** (audit machine, audit reader, after the last role-using step P15-02; P13-02 in `50ee8e0`, moved after the final review) repeats the six-role check and requires each role's `RoleId` to equal the one P03-15 recorded; residual **R17** for the window after P15-03 | a re-created role (new `RoleId`), nothing recorded, no role id now, a malformed recorded id; P15-03's order, machine, identity and mode; P15-03's 31 calls added to the executed-call allow-list |
| **F4** `git replace` defeated every reviewed-tree check | P00-02 and `lib.sh` export `GIT_NO_REPLACE_OBJECTS=1` and unset `GIT_GRAFT_FILE`, `GIT_DIR`, `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES` and `GIT_REPLACE_REF_BASE` before any git call, and refuse replace refs, a grafts file and a shallow clone; `verify_reviewed_commit` (and so `render`) does the same, resolving git's directory as an absolute path | a replaced template blob, `info/grafts`, a shallow clone (P00-02); a replaced blob and a grafts file under `render`; the export and the unset precede every git call in both blocks |
| **F5** operator multipart listing under an unsupported `s3:prefix` condition | Fixed on `main` (#61) and integrated: `ListInProgressUploads` on the bucket, filtered in the application; `boundary-operator` split the same way | `main`'s template tests; PR #60's role and boundary pins |
| **F6** executed-call tuples pin only resource values | Stated, not hidden: residual **R18**; "N6 fixed" corrected | — |
| **F7** `isolation.py` detects only proof-named profiles | Wording corrected (proof rules, assurance model, E9); residual **R19** | — |
| **F8** handoff evidence hashes and step unverified; sender unauthenticated; "refuses anything credential-like" | Wording corrected; residual **R20** | — |
| **F9** `NeverChangeIam` omitted `iam:Disable*` and `iam:Generate*` | Both added to all three permission sets' `NeverChangeIam`; the IAM-write list in the separation test now includes both families | pins; the separation test |
| **F10** no step installs the pinned CLI on the instance | Stated: the verifier pins the CLI of the day's AMI; P03-13 stops if it moved (fail closed); installing one would be a new reviewed step | existing `verify_tools` controls |

**Final review of round 6 (at `50ee8e0`): dispositions.** Merge verdict YES,
no Critical or High finding. Factual errors are fixed; lower-severity points
are recorded here.

| Finding | Disposition |
|---|---|
| **M1** the role re-check ran before P14–P15, which still use the roles, while the text said "after every step that used the roles"; R15's step list and the unexplained-events scope omitted P12-02, P14 and P15 | **Fixed:** the check moved to **P15-03**, after P15-02 (the last role-using step), with the same identity and `RoleId` comparison; R15 now lists P12-02, P14 and P15, and `p13-unexplained.txt` is stated to cover events up to P12 only |
| **L1** `lib.sh`'s grafts check used a relative path and could never fire | **Fixed:** `rev-parse --path-format=absolute --git-common-dir`; a grafts file under `render` now stops (test) |
| **L2** re-running P03-15 re-records the role ids | **Recorded** under R17 (a recovery path; the journal records each run) |
| **L3** E16 rendered outside the table; the runbook index said "E1–E15 … OPEN" | **Fixed** |
| **I** `GIT_GRAFT_FILE` and the object-directory variables were honoured | **Fixed:** unset in both blocks (test) |
| **I** P13-01's unexplained filter ignores the error code; the latest-AMI choice will often trip the CLI pin | Recorded: no impact (ingest has no `PutObject`); F10 already fails closed |
| **New:** if three real participants are unavailable | **Single-owner mode** (E9 (b), R21): one authorized owner, a separate OS account, profiles and sessions per function; every gate must say `data_scope: synthetic-only`, so real customer data stays blocked |

**IAM template changes in round 6** (every one; nothing else changed):

| Template | Change | Why |
|---|---|---|
| `role-operator` | `ListVersionsBounded` no longer holds `s3:ListBucketMultipartUploads`; new `ListInProgressUploads` grants it on the bucket ARN only, no condition | F5, merged from `main` (#61) |
| `boundary-operator` | the same split, on the proof bucket pattern `…-us-east-1-d6*` | must equal `role-operator`'s Allows |
| `permission-set-operator`, `permission-set-audit-admin`, `permission-set-audit-reader` | `NeverChangeIam` adds `iam:Disable*` and `iam:Generate*` | F9 |

## Limits of this local validation

- **No AWS evaluation.** Syntax, action names, condition keys and their
  behaviour for each S3 operation are as read, not as AWS evaluates them.
- **Sizes are counted locally.** Every template is rendered by the proof's
  own `render` helper with dummy values and measured without whitespace
  against AWS's documented limits. The tightest are the proof boundary and
  the proof deny policy (managed policies, 6,144 characters each), the
  provisioner permission set's inline policy (10,240) and the human
  trust policy (2,048); the test prints none, it only asserts each limit.
  AWS's own counter was not consulted.
- **No AWS command was run.** The proof's shell is syntax-checked (`bash -n`)
  and executed end to end against a stub `aws` (bash 3.2 locally, bash 5 in
  CI); every template renders completely; the probe's offline refusals run
  against the application code. The real AWS CLI was never invoked, so flags,
  error codes and output shapes are from the documentation, and nothing here
  shows how AWS evaluates any policy.
- **Simulator caveats.** `simulate-custom-policy` with a resource policy may
  refuse a caller that does not exist (P10-02 says what to do).
