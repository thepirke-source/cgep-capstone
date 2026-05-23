# Capstone — Grader Verification Guide

This repo wraps `cgep-app-starter` (Patient Intake API) in a HIPAA-aligned GRC
baseline. This document is the script for verifying that claim. Verification is
split into **(A) code gates** that a grader can run from a clean checkout with
no AWS, and **(B) live-fire** state in the AWS sandbox.

## TL;DR
- **Primary framework**: HIPAA Security Rule (45 CFR Part 164 Subpart C).
- **Repo URL**: https://github.com/thepirke-source/cgep-portfolio (capstone in `lab-7-1/`)
- **Graded commit SHA**: see the latest commit on `main` (printed at submission).
- **Deployment posture**: Terraform validates and produces a clean, gate-passing
  plan (`evidence/plan.json`). A full live `terraform apply` of the workload
  (VPC/NAT/Lambda/DynamoDB/API GW) was **deliberately deferred** to avoid
  standing NAT-Gateway cost in the sandbox — see WRITEUP §6. The signed
  evidence bundle below is from a **real prior pipeline run**, not a mock.

---

## A. Code gates (no AWS required) — ~5 min

### A1. Policy unit tests
```bash
opa test policies/
```
Expected: `PASS: 16/16`.

### A2. Policy gate against the real Terraform plan
```bash
conftest test evidence/plan.json --policy policies/ --all-namespaces
```
Expected: `10 tests, 10 passed, 0 failures`. This is the **green-PR** state:
the baseline + gap-closing overrides satisfy every HIPAA control the suite asserts.

To see the **red-PR** state (gap reintroduced → gate blocks), flip the uploads
bucket SSE to `AES256` in a copy of the plan and re-run; conftest fails with:
`HIPAA §164.312(a)(2)(iv) [SC-28]: S3 bucket "...uploads_kms_override" uses "AES256" SSE`.

### A3. Terraform validates
```bash
cd terraform
terraform init -backend=false
terraform validate
```
Expected: `Success! The configuration is valid.`

### A4. OSCAL validates
```bash
trestle validate -f component-definitions/acme-intake-v1/component-definition.json
trestle validate -f profiles/acme-hipaa-baseline/profile.json
```
Both report `VALID`.

### A5. Gap closure is traceable
`GAPS.md` (vendored from the starter) lists the 8 named gaps. `WRITEUP.md` §2–§3
maps each closed gap → HIPAA control → the Terraform resource that closes it
(`terraform/overrides_starter.tf` + the CMK on the starter's DynamoDB in
`terraform/starter/main.tf`).

### A6. Pipeline shape
```bash
cat .github/workflows/grc-gate.yml
```
Confirm five named steps in order — **plan → policy → apply → sign → upload** —
and OIDC `permissions: id-token: write`.

---

## B. Live-fire (AWS sandbox) — evidence chain of custody

A real signed evidence bundle exists from a prior pipeline run:

- **Vault**: `s3://cgep-lab-grc-evidence-vault-05fd4ba8/`
  (Object Lock enabled, versioned, KMS-encrypted, key rotation on)
- **Run**: `runs/26288596607/` — commit `2f82e8c66597025b22ebdf54dac8478cf5c3a0ed`
- **Artifacts**: `evidence-*.tar.gz`, `.tar.gz.sha256`, `.tar.gz.sig.bundle`, `receipt.json`

```bash
AWS_PROFILE=cgep-sandbox aws s3 ls s3://cgep-lab-grc-evidence-vault-05fd4ba8/runs/26288596607/
AWS_PROFILE=cgep-sandbox aws s3 cp \
  s3://cgep-lab-grc-evidence-vault-05fd4ba8/runs/26288596607/receipt.json -
```
The receipt's `sha256` matches the bundle; `sha_commit` ties it to the run commit.

**Honest state of this gate (see WRITEUP §6):**
- The bundle is signed via Sigstore keyless (`.sig.bundle`) and stored under
  Object Lock — chain of custody is demonstrated.
- The vault is the lab vault (**GOVERNANCE / 1-day** retention), not the
  COMPLIANCE / 6-year prod vault the Terraform is written to provision. That
  prod vault and a fresh bundle land on the next live `apply` of the baseline.
- Object Lock **retention on this specific object has lapsed** (1-day window);
  the retention *mechanism* is proven, the *prod duration* is configured in
  `terraform/main.tf` (`evidence_vault_lock_mode` / `evidence_vault_retention_days`)
  but not yet applied.

---

## Score reference

| Gate | Pass criterion | State |
|---|---|---|
| End-to-end integration | One PR triggers every step in `grc-gate.yml` | Pipeline built; applies on merge |
| Policy enforcement | conftest passes clean / blocks on reintroduced gap | ✅ proven A2 |
| Working evidence pipeline | signed bundle exists, cosign-verifiable, SHA matches | ✅ prior run, B |
| Clear design reasoning | WRITEUP §1, §4, §5, §6 present and specific | ✅ |

## Honest gaps (also in WRITEUP §6)
- Live `apply` of the full workload deferred (NAT-Gateway cost); plan is clean.
- Graded bundle sits in the GOVERNANCE/1-day lab vault, not the COMPLIANCE/6yr
  prod vault (configured, not yet applied).
- Rego covers 5 of 18 §164.312/.316 specs (graded scope; not full HIPAA).
- Single CMK per data domain; no formal BAA template; DR runbook untested.
