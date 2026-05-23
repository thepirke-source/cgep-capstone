# HIPAA Security Rule → NIST 800-53 → Capstone Implementation

Source: 45 CFR §164.302 – §164.318. NIST mappings per [NIST SP 800-66r2](https://csrc.nist.gov/pubs/sp/800/66/r2/final) crosswalk.

## §164.308 Administrative safeguards

| HIPAA spec | R/A | NIST 800-53 | Capstone mechanism |
|---|---|---|---|
| 308(a)(1)(i) Security Management Process | R | PM-9, RA-3 | WRITEUP §1 + risk register |
| 308(a)(1)(ii)(A) Risk Analysis | R | RA-3 | OSCAL component-definition links resources → controls |
| 308(a)(1)(ii)(B) Risk Management | R | PM-4, PM-9 | Rego policies enforce risk-treatment baselines |
| 308(a)(1)(ii)(D) Info Sys Activity Review | R | AU-6, AU-12 | CloudTrail → CW Logs → Security Hub findings |
| 308(a)(3)(i) Workforce Security | R | PS-3, PS-4 | Out of scope (HR process) |
| 308(a)(4)(i) Info Access Management | R | AC-2, AC-3, AC-6 | IAM roles, least-privilege Rego rule |
| 308(a)(5)(i) Security Awareness | R | AT-2, AT-3 | Out of scope (training) |
| 308(a)(6)(i) Security Incident Procedures | R | IR-4, IR-5 | Security Hub findings + runbook stub |
| 308(a)(7)(i) Contingency Plan | R | CP-2, CP-9, CP-10 | S3 versioning + Object Lock + KMS rotation |
| 308(a)(8) Evaluation | R | CA-2, CA-7 | Pipeline runs PaC on every PR |

## §164.310 Physical safeguards

| HIPAA spec | R/A | NIST 800-53 | Capstone mechanism |
|---|---|---|---|
| 310(a)(1) Facility Access | R | PE-3 | Inherited from AWS SOC 2 (responsibility model) |
| 310(b) Workstation Use | R | AC-11, AC-19 | Out of scope (endpoint) |
| 310(d)(2)(i) Disposal | R | MP-6 | KMS deletion window + bucket lifecycle |
| 310(d)(2)(ii) Media Re-use | R | MP-6 | S3 + KMS — no physical media |

## §164.312 Technical safeguards — CORE LAB SCOPE

| HIPAA spec | R/A | NIST 800-53 | Capstone mechanism | Rego rule |
|---|---|---|---|---|
| **312(a)(1) Access Control** | R | AC-3 | S3 public access block + IAM least-priv | `hipaa_164_312_a_1_access.rego` |
| **312(a)(2)(i) Unique User ID** | R | IA-2 | IAM users + MFA | (out-of-PaC, policy-doc) |
| 312(a)(2)(ii) Emergency Access | R | CP-2 | Break-glass IAM role + SCP | — |
| 312(a)(2)(iii) Auto Logoff | A | AC-12 | Session token TTL via STS | — |
| **312(a)(2)(iv) Encryption at Rest** | A | SC-28 | KMS CMK on every S3 + DynamoDB | `hipaa_164_312_a_2_iv_encryption.rego` |
| **312(b) Audit Controls** | R | AU-2, AU-3, AU-12 | CloudTrail multi-region + log-file-validation | `hipaa_164_312_b_audit.rego` |
| **312(c)(1) Integrity** | R | SI-7, AU-9 | Cosign signed evidence + Object Lock | (verification step in pipeline) |
| 312(c)(2) Authenticate ePHI | A | SI-7(7) | Cosign verify-blob | — |
| 312(d) Person/Entity Auth | R | IA-2 | IAM + MFA, OIDC for CI | — |
| **312(e)(1) Transmission Security** | R | SC-8, SC-13 | TLS-only bucket policy, API GW TLS 1.2+ | `hipaa_164_312_e_1_transit.rego` |
| 312(e)(2)(ii) Encryption in Transit | A | SC-8(1) | covered by 312(e)(1) | — |

## §164.316 Documentation

| HIPAA spec | R/A | NIST 800-53 | Capstone mechanism |
|---|---|---|---|
| 316(a) Policies + Procedures | R | PL-1, PL-2 | WRITEUP.md + repo README |
| 316(b)(1) Documentation | R | AU-11 | All policy + evidence in repo |
| 316(b)(2)(i) Retain 6 years | R | AU-11 | Object Lock retention 2190d (prod vault) |

## Legend
- **R** = Required
- **A** = Addressable (must implement or document equivalent + rationale)
- **Bold rows** = enforced by Rego in capstone
