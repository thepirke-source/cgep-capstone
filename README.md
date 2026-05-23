# Acme Health — CGEP Capstone

A HIPAA-aligned GRC baseline wrapped around the `cgep-app-starter` Patient
Intake API. Infrastructure as code, policy as code, a CI evidence pipeline, and
an OSCAL component — one repo.

**Primary framework:** HIPAA Security Rule (45 CFR Part 164 Subpart C).

## Layout

| Path | Layer |
|---|---|
| `terraform/starter/` | Vendored starter workload (VPC, Lambda, DynamoDB, S3, API GW) |
| `terraform/overrides_starter.tf` | Gap-closing overrides (GAP-01/03/04/07) on the starter |
| `terraform/` (root, modules) | KMS CMKs, evidence vault (Object Lock), CloudTrail, GitHub OIDC |
| `policies/` | 5 Rego policies + tests, each citing a HIPAA control |
| `.github/workflows/grc-gate.yml` | Pipeline: plan → policy → apply → sign → upload |
| `component-definitions/`, `profiles/` | OSCAL component + HIPAA profile |
| `WRITEUP.md` | Design decisions, control coverage, trade-offs, honest gaps |
| `GRADER.md` | Step-by-step verification (code gates + live-fire) |
| `GAPS.md`, `FRAMEWORKS.md` | From the starter — the 8 named gaps + framework primers |

## Verify (no AWS needed)

```bash
opa test policies/                                     # 16/16
conftest test evidence/plan.json --policy policies/ --all-namespaces   # 10/10
cd terraform && terraform init -backend=false && terraform validate
trestle validate -f component-definitions/acme-intake-v1/component-definition.json
```

See `GRADER.md` for the full script, including the signed evidence bundle in the
sandbox vault and the deploy posture (live `apply` deferred — see WRITEUP §6).
