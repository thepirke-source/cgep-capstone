# Capstone Execution Plan

## Day 0 — Bootstrap
```bash
git clone https://github.com/GRCEngClub/cgep-app-starter
cd cgep-app-starter
make deploy AWS_PROFILE=<sandbox>
make test   AWS_PROFILE=<sandbox>
# Expect: {"submission_id":"...","status":"received"}
```
If `make test` fails → fix before anything else.

## Week 1 — Design
- [ ] Read `GAPS.md` + `FRAMEWORKS.md` in starter
- [ ] Pick primary framework (write decision in WRITEUP §1)
- [ ] Sketch repo structure (terraform/, policies/, .github/workflows/, oscal/)
- [ ] Map each `GAPS.md` gap → "fix in TF" or "enforce in policy"

## Week 2 — Terraform baseline
Reuse from labs:
- `lab-2-3/terraform/primitives/compliant-s3/` → adapt to uploads bucket override (GAP-S3)
- `lab-2-5/terraform/` → evidence vault pattern (Object Lock, KMS)
- `lab-5-2/main.tf` → CloudTrail + Config + GuardDuty baseline

Required new resources:
- KMS key(s) with rotation
- S3 evidence bucket w/ Object Lock (decide COMPLIANCE vs GOVERNANCE)
- CloudTrail multi-region + log-file-validation
- Hardening overrides on starter's S3, Lambda, IAM, DynamoDB

Apply once by hand from feature branch. Don't start pipeline until clean apply.

## Week 3 — Policy + pipeline
Reuse:
- `lab-3-3/policies/` → template metadata format
- `lab-3-4/scripts/policy-gate.sh` → CI gate
- `lab-4-3/.github/workflows/grc-gate.yml` → base workflow
- `lab-4-4/scripts/verify-evidence.sh` → cosign verify

Write 5+ Rego policies, each:
- Cites framework + control ID
- Has `_test.rego` (pass + fail fixture)
- Catches a real `GAPS.md` gap
- Deny message names the control

Build pipeline (5 named steps): plan → policy → apply → sign → upload.

Produce 2 PRs in history: 1 green, 1 red.

## Week 4 — OSCAL + write-up
Reuse:
- `lab-6-1/component-definitions/compliant-s3-v1/component-definition.json` → skeleton

Modify:
- Real UUIDs (`uuidgen`)
- `control-implementation.source` → your framework catalog URL
- Implementation statements reference Terraform addresses/ARNs as `props`
- Evidence `links[].href` → signed objects in your vault (`s3://...`)
- Validate: `trestle validate -f oscal/components/<name>.json`

Write `WRITEUP.md` sections:
1. Framework choice + why
2. Control coverage (which gap → which mechanism)
3. Trade-offs accepted
4. What you'd do with another sprint
5. Honest gaps

## Submit
Repo URL + commit SHA. Done.

## Lab → capstone artifact map

| Lab | Capstone use |
|---|---|
| 2.3 | S3 hardening overrides |
| 2.4 | Reusable module pattern (wrap KMS+S3) |
| 2.5 | Evidence vault + capture-evidence.sh |
| 3.3 | Rego library starting point |
| 3.4 | policy-gate.sh |
| 4.3 | grc-gate.yml workflow |
| 4.4 | Cosign + Object Lock signing pattern |
| 5.2 | CloudTrail + Config baseline |
| 6.1 | component-definition skeleton |
