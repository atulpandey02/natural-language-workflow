# O-2 AWS policy review (local, structural; NOT validated by AWS)

Scope: every IAM, trust, bucket, KMS and CloudTrail template in
[dataset-s3-provisioning.md](../runbooks/dataset-s3-provisioning.md), read
against ADR-033, the S3 store (`nlw.storage.s3`), credential handling
(`nlw.storage.s3_credentials`), migration 0028 and the dataset alert rules.

**What this review is.** A reading of the JSON as written, plus contract tests
that parse it and check its structure: `test_dataset_s3_provisioning_templates.py`
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
| No runtime deletion | API, ingest and bootstrap hold no `s3:Delete*`; bucket `DenyDeleteExceptOperator` | `test_runtime_roles_can_never_delete` | P11 |
| No operator-role assumption by the instance role | Bootstrap allows `sts:AssumeRole` on exactly the API and ingest roles and denies every other role (`NotResource`); the operator trust allows only named humans with MFA, denies any session without MFA context, and denies the bootstrap and runtime roles by name | `test_the_instance_role_can_never_become_the_operator`, `test_human_roles_require_mfa` | P12 |
| CloudTrail and audit-bucket tamper protection | Every dataset role denies the trail, audit bucket and audit key, and denies altering any trail; the audit bucket denies dataset roles and every delete or retention change except by the audit administrator; Object Lock; log-file validation; the audit key cannot be scheduled for deletion | existing audit tests, `test_audit_tamper_protection_is_complete` | P11, P13 |
| API and ingest credential separation | Separate roles, trust policies requiring different session names, separate credential files and mounts; only the API may generate data keys, in both the role policies and the key policy | `test_api_and_ingest_credentials_are_separate` | P14, P15 |
| No IMDS fallback | The SDK credential chain is replaced by one provider that reads only the file (`s3_credentials._session`); IMDSv2 with hop limit 1; host firewall drop | existing `test_the_sdk_chain_is_pinned_to_the_file_and_never_falls_back`; `test_the_proof_instance_requires_imdsv2_with_hop_limit_one` | P03-14, P14-04 |

## Findings fixed in this change

| Id | Finding | Fix |
|---|---|---|
| **F1** | The dataset key policy granted `kms:GenerateDataKey` to the ingest and operator roles. A key-policy statement naming a role is sufficient on its own in the same account, so the role policies' narrower grants did not limit it. The D6 item "the ingest role cannot generate data keys" would have failed. | Split into an API statement (`GenerateDataKey`, `Decrypt`) and a decrypt-only statement for ingest and operator. |
| **F2** | The operator role had no cross-environment deny. The ingest role's deny covered buckets but not keys. The API's bucket deny depended on a resource tag. | All four dataset roles now carry an unconditional deny on every `nlw-<OTHER_ENV>-*` bucket and object; roles with KMS access also deny keys not tagged for their environment. |
| **F3** | Trust policies existed only as prose, so MFA and the bootstrap-to-operator boundary were not reviewable or testable. | Templates `trust-bootstrap`, `trust-api`, `trust-ingest` and `trust-human-mfa`. MFA is enforced by an Allow condition and by two denies, one for a missing MFA key (`Null`) and one for `false`, keeping the template free of `…IfExists`. |
| **F4** | The bootstrap role's limits were only the absence of grants. Another attached policy could have widened them. | Explicit denies: every role except API and ingest (`NotResource`), and all S3 and KMS. |
| **F5** | The key policies showed one statement each. The administration statement, and whether the account root could use the keys, were unstated. | A full dataset key policy and an audit key administration statement: root and the administrator may manage but never use the key; the audit key cannot be scheduled for deletion. |
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
| **R6** | The credential refresher is not built. | It ships with O-6; P14 uses a stand-in with the same file contract. | P14 |

## Limits of this local validation

- **No AWS evaluation.** Syntax, action names, condition keys and their
  behaviour for each S3 operation are as read, not as AWS evaluates them.
- **Sizes are counted locally.** Every template is rendered by the proof's
  own `render` helper with dummy values and measured without whitespace
  against AWS's documented limits. The largest are the bucket policy (3,063
  of 20,480 characters), the audit-admin role (2,008 of 10,240) and the human
  trust policy (888 of 2,048). AWS's own counter was not consulted.
- **Commands are unexecuted.** The proof's shell is syntax-checked
  (`bash -n`), every template renders completely, and the probe's offline
  refusals (missing, expired, exposed and static credentials) run locally
  against the application code. No AWS CLI command was run, so flags, error
  codes and output shapes are from the documentation.
- **Simulator caveats.** `simulate-custom-policy` with a resource policy may
  refuse a caller that does not exist (P10-02 says what to do).
