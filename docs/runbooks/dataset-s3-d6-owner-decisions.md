# Dataset S3 D6 owner decisions (OPEN — not chosen by engineering)

Status: **every decision below is open.** The
[D6 proof](dataset-s3-d6-proof.md) may not start until each row has the
owner's answer and the session is authorized in writing. Each item gives the
options and an engineering recommendation; the recommendation is not a
decision.

Answers that are identifiers (E5, E8, E9) are given to the operator running
the proof and are **never committed** to this repository.

| Id | Decision | Options | Recommendation |
|---|---|---|---|
| **E1** | CloudTrail audit retention (`<AUDIT_RETENTION_DAYS>`) | (a) 90 days, the proof only; (b) 400 days, covering a year of access review plus a margin; (c) a period set by O-3/O-5 legal retention | **(a) for the proof**, with the bucket's default retention raised to the O-3/O-5 value before any customer object is stored. Retention can be lengthened later but, in COMPLIANCE mode, never shortened. |
| **E2** | Object Lock mode on the audit bucket | (a) GOVERNANCE: the audit administrator can shorten retention with `s3:BypassGovernanceRetention`; (b) COMPLIANCE: nobody, including the account root, can delete a log or shorten retention before it ends | **(a) GOVERNANCE for the proof.** COMPLIANCE makes every proof log, and the bucket itself, undeletable for E1's full period. Choose COMPLIANCE for the long-lived staging and production audit buckets, once E1 is final. |
| **E3** | Proof resources after the proof | (a) delete: X06 and X07 remove the dataset bucket, runtime roles, dataset key and trail; (b) retain: they become the staging dataset resources for O-6 | **(b) retain**, if the proof passes cleanly. It avoids re-provisioning and a second proof of identical templates, and the retained cost is small (E4). Choose (a) if the proof fails or the templates change. The proof instance and objects are always removed; the audit bucket, audit key and audit roles are always retained. |
| **E4** | Monthly cost ceiling | (a) USD 10; (b) USD 25; (c) another figure | **(b) USD 25**, enforced with an AWS Budgets alert at 80% before P03. Expected retained cost is a few dollars a month (two KMS keys, a small trail, near-empty buckets); the proof day adds the proof instance's hours and request charges. Prices must be confirmed at provisioning time. |
| **E5** | Approved AWS account id | the account that holds staging today, or a separate staging-data account | **The account that already holds the staging host**, so the instance-profile design applies unchanged. A separate account would need cross-account trust, which ADR-033 does not cover. |
| **E6** | Final staging bucket naming (`<SUFFIX>`) | (a) no suffix: `nlw-staging-datasets-<ACCOUNT>-us-east-1`; (b) a short suffix, such as `-a1` | **(a) no suffix.** The account id already makes the name unique. A suffix is needed only if the name is taken, which P02 detects. The application accepts both forms. |
| **E7** | An account-wide management-event trail already exists | (a) yes, multi-region, protected; (b) yes, but unprotected or single-region; (c) no | Confirm before P03 from P02's `p02-existing-trails.txt`. **If (b) or (c), stop:** bucket-policy, key-policy and IAM changes would go unrecorded. Creating that trail is a separate, account-level change. |
| **E8** | `<ADMIN_ROLE>`: the role that provisions and administers the dataset bucket and key | the owner's existing administration role, or a new, narrower provisioning role | **The existing administration role**, reached through the owner's MFA-protected sign-in. Record its exact ARN, including any path such as an IAM Identity Center prefix, because the bucket policy compares it exactly. |
| **E9** | Human principals for the operator, audit-admin and audit-reader roles | named people or groups for each | **Two different people** for operator and audit administrator, so no one person can both purge data and alter its audit record. The audit reader may be either. Each must have an MFA device. |
| **E10** | Where the proof runs | (a) a disposable proof instance (P03-10) in the default VPC; (b) the staging host itself | **(a) the disposable instance.** It needs no change to the staging host, and the proof can be torn down without touching it. Steps P14 and P15 are repeated on the staging host when the refresher ships (O-6). If the account has no default VPC, the owner names a subnet instead. |

**Sign-off:** owner, date, and the authorized proof window.
