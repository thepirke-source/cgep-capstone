# Acme Health — Capstone Write-up

## §1 Framework decision

Acme Health is a 50-person telehealth company. The Patient Intake API in the starter handles Protected Health Information (PHI). The threat model and the regulatory hook are the same data. **Primary framework: HIPAA Security Rule (45 CFR §164.302–§164.318).**

Rejected alternatives:
- **SOC 2 Type II** — broader than the actual risk surface. Earns enterprise trust but doesn't directly govern PHI. Better as a Year-2 overlay once the HIPAA baseline holds.
- **CMMC Level 2** — scoped to CUI in federal contracts. Starter has no CUI model. Would inflate scope (supply-chain, NIST 800-171 §3.x families) for no near-term business gain.
- **ISO 27001** — not on the brief's list. OSCAL catalog mismatch would auto-fail Layer 4. Out.

HIPAA maps cleanly to the NIST 800-53 controls already enforced by labs 2.3 through 5.2 (SC-28, AC-3, AU-3, AU-6, CM-6, SC-12/13, AU-11). Auditor traversal stays short: §164.312 → NIST control → Rego rule → signed evidence JSON.

## §2 HIPAA → NIST 800-53 → Implementation map

| HIPAA spec | NIST 800-53 | Implementation | Evidence |
|---|---|---|---|
| §164.312(a)(1) Access Control | AC-3 | S3 public access block (4 flags), IAM least-privilege | plan.json: `public_access_block` + IAM policy docs |
| §164.312(a)(2)(iv) Encryption (addressable) | SC-28 | KMS CMK on uploads bucket, DynamoDB, evidence vault | plan.json: `sse_algorithm == "aws:kms"` |
| §164.312(b) Audit Controls | AU-2, AU-3, AU-12 | CloudTrail multi-region + log-file-validation; S3 access logging | trail config + access-logs/ prefix in evidence bundle |
| §164.312(c)(1) Integrity | SI-7, AU-9 | Cosign signature on evidence bundle, Object Lock retention | bundle.sig + cosign verify-blob output |
| §164.312(d) Person/Entity Authentication | IA-2 | IAM + MFA on root; no long-lived keys (OIDC) | starter's auth code + OIDC trust policy |
| §164.312(e)(1) Transmission Security | SC-8 | TLS-only bucket policy, API GW TLS 1.2+ | plan.json: bucket policy `aws:SecureTransport` |
| §164.308(a)(1)(ii)(D) Information System Activity Review | AU-6 | CloudTrail → CloudWatch Logs; Security Hub findings | log group + SH standards subscriptions |
| §164.308(a)(7)(ii)(A) Data Backup | CP-9 | S3 versioning on uploads + evidence buckets | plan.json: `versioning_configuration.status == "Enabled"` |
| §164.310(d)(2)(iv) Data Disposal | MP-6 | KMS key deletion window 7d; bucket lifecycle expiry | KMS key config |
| §164.312(a)(2)(i) Unique User Identification | IA-2 | Per-user IAM, no shared accounts | IAM users list |

## §3 Layer mapping (4 layers, 1 repo)

### Layer 1 — Terraform baseline
Reused module: `lab-2-3/terraform/primitives/compliant-s3` as the override template.
New for capstone:
- `terraform/modules/kms-cmk` — wraps `aws_kms_key` + rotation, used by every encrypted resource
- `terraform/modules/evidence-vault` — from `lab-2-5`, COMPLIANCE-mode object-lock for prod
- `terraform/cloudtrail.tf` — from `lab-5-2`, multi-region + log-file-validation + CW Logs
- `terraform/overrides/` — closes GAPS.md: starter's S3 SSE→KMS, Lambda→VPC, IAM `dynamodb:*` → action-scoped

### Layer 2 — OPA policy suite
Five Rego policies, all metadata-tagged `framework: HIPAA Security Rule`:

| Policy | HIPAA cite | Gap closed |
|---|---|---|
| `hipaa_164_312_a_2_iv_encryption.rego` | §164.312(a)(2)(iv) | GAP-01 S3 unencrypted |
| `hipaa_164_312_a_1_access.rego` | §164.312(a)(1) | GAP-02 public bucket policy |
| `hipaa_164_312_b_audit.rego` | §164.312(b) | GAP-03 no CloudTrail |
| `hipaa_164_312_e_1_transit.rego` | §164.312(e)(1) | GAP-04 missing TLS-only policy |
| `hipaa_164_308_a_1_ii_d_review.rego` | §164.308(a)(1)(ii)(D) | GAP-05 IAM `dynamodb:*` wildcard |

Each: deny rule cites control ID + remediation in message. Each: `_test.rego` with pass + fail fixtures.

### Layer 3 — Pipeline (`grc-gate.yml`)
Five named steps, fail-closed:
1. **plan** — `terraform plan -out=tfplan && terraform show -json tfplan > plan.json`
2. **policy** — `conftest test plan.json --policy policies/`
3. **apply** — `terraform apply` (only on merge to `main`, only if step 2 passed)
4. **sign** — `cosign sign-blob --yes evidence.tar.gz` (keyless via GitHub OIDC)
5. **upload** — `aws s3 cp evidence.tar.gz s3://acme-evidence-vault/...`

Two PRs in history:
- Green: closes a real gap, all policies pass
- Red: re-introduces GAP-01 (drops SSE), conftest blocks, no apply

### Layer 4 — OSCAL
One `oscal/components/acme-intake-v1/component-definition.json`:
- Real UUIDv4s (uuidgen, not copied)
- `control-implementation.source` → `https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json`
- Each `implemented-requirement` references actual TF resource ARN via `props`
- `links[].href` → signed `s3://acme-evidence-vault/<sha>/bundle.tar.gz`
- `oscal/profiles/acme-hipaa-baseline.json` selects the controls in the map above
- Validates with `trestle validate -f oscal/components/acme-intake-v1/component-definition.json`

## §4 Design decisions and trade-offs

- **Object Lock mode: COMPLIANCE** (not GOVERNANCE) for the prod evidence vault. Prod PHI evidence must not be overridable, even by root. The module (`terraform/modules/evidence-vault`) takes mode + retention as inputs; the root sets COMPLIANCE / 6-year for `environment = prod`, enforced by a variable validation rule (`terraform/variables.tf`). The lab vault stays GOVERNANCE / 1-day for cleanup. Same module, different mode — proving the control is parameterised, not hard-coded.
- **Retention: 6 years** (HIPAA §164.316(b)(2)(i) — PHI documentation retained 6yr from creation), wired as `evidence_vault_retention_days >= 2190` for prod.
- **Apply gate: auto-apply on merge to `main`, after the policy gate passes.** Faster than per-PR human apply, still fail-closed on Conftest.
- **Single AWS account.** 30-day budget. Separate evidence-vault account is the cleaner Year-2 move (see §6 segregation of duties).
- **Region: us-east-1.** HIPAA-eligible, all services available.
- **Live deploy of the workload deferred (cost trade-off).** The starter ships a NAT Gateway for its private subnets (~$32/mo standing cost). For a sandbox capstone that is pure burn, so the full `terraform apply` of VPC/NAT/Lambda/DynamoDB/API GW was not run. The configuration **validates** and produces a **clean, gate-passing plan** (`evidence/plan.json`, verified by `conftest`), and a real signed evidence bundle from a prior pipeline run is in the vault. What is *not* yet live: the prod COMPLIANCE/6yr vault and a fresh bundle in it. Both follow from one `terraform apply` when a deploy budget is approved.

## §5 What I'd do with another sprint

- Move evidence vault to a separate AWS account with cross-account write-only role (defense in depth against insider compromise)
- Add AWS Config conformance pack for HIPAA (`Operational-Best-Practices-for-HIPAA-Security`)
- Add Macie scan job over uploads bucket (PHI classification)
- Add automated `oscal-assemble` step in the pipeline so component-definition stays in sync with TF state
- SOC 2 overlay profile selecting a superset of controls

## §6 Honest gaps

- **Workload not live-applied.** The deploy was deferred for cost (NAT Gateway). Terraform validates and the plan passes every policy gate, but the running API, the prod COMPLIANCE/6yr vault, and a fresh bundle in it are not stood up. The existing signed bundle in the lab vault (GOVERNANCE/1-day, run `26288596607`) demonstrates the chain of custody; its Object Lock retention window has lapsed. This is a budget gap, not a design gap — one `apply` closes it.
- KMS keys are not yet split per environment (one CMK serves dev + prod buckets — should be two)
- No formal BAA template in repo (operational, not technical, but cited in §164.308(b))
- No DR runbook beyond bucket versioning (RPO/RTO documented but not tested)
- Rego policies cover 5 of the 18 implementation specs in §164.312–§164.316. Audit-defensible for graded scope; not full HIPAA coverage

### Segregation of duties — the structural gap

This implementation places the **IaC author**, the **pipeline operator**, and the **evidence signer** in a single role. The same principal who writes the Terraform also triggers the `apply`, also signs the evidence bundle, also owns the OSCAL component-definition that asserts what controls are in place.

In a real SOC 2 / ISO 27001 / HIPAA production environment, those functions belong to different people:

| Function | Real-world role |
|---|---|
| Write Terraform + Rego | Platform / DevSecOps Engineer (first line of defense) |
| Operate the pipeline + run apply | CI service account, governed by branch protection + required reviewers |
| Own the control catalog and OSCAL | **GRC Engineer** (second line of defense, read-only on prod) |
| Review signed evidence + sign off | **GRC Analyst** or external auditor |
| Approve framework choice + risk acceptance | GRC Manager / CISO |

Collapsing all of these into one role violates **SOC 2 CC1.3**, **ISO 27001 A.5.3**, and **NIST 800-53 AC-5** (Separation of Duties). It is also the single most common audit finding in early-stage compliance programs.

The capstone's single-account, single-role model is a **lab simplification**, not a target operating model. A production-grade rebuild would:

- Split into at least two AWS accounts: a workload account where engineering applies infrastructure, and an evidence/audit account where GRC reads but cannot write.
- Replace the broad CI role's `s3:*`, `kms:*`, `iam:*` grants with workload-scoped permissions and a separate, narrower role for cross-account evidence uploads.
- Move OSCAL component-definition ownership to a separate GRC-owned repository with branch protection requiring GRC review, decoupling "the controls we claim" from "the code that implements them."
- Require the signed evidence bundle to be **counter-signed** by a GRC reviewer key before it leaves the staging vault, formalizing the AU-10 non-repudiation chain across roles, not within one role.

I am calling this out explicitly because the broader "GRC Engineer" framing of this course conflates two distinct roles. The IaC + PaC + pipeline work in Layers 1–3 is **Platform / DevSecOps** work. The OSCAL catalog ownership and evidence review in Layer 4 is **GRC** work. Production teams separate them deliberately. Anyone reading this write-up as a template should plan that separation from day one, not retrofit it after their first audit.
