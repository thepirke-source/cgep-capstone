# Acme Health capstone — Layer 1 root.
# Wires the starter's resources to the HIPAA-compliant baseline.

# ──────────────────────────────────────────────────────────────────────────
# Vendored starter workload (Patient Intake API). The capstone repo IS the
# fork: the starter's VPC/Lambda/DynamoDB/S3/API GW are applied here, and the
# gap-closing overrides (overrides_starter.tf) bind to its outputs.
# ──────────────────────────────────────────────────────────────────────────
module "starter" {
  source                  = "./starter"
  submissions_kms_key_arn = module.kms_dynamodb.key_arn
}

# ──────────────────────────────────────────────────────────────────────────
# KMS keys — one per data domain
# ──────────────────────────────────────────────────────────────────────────
module "kms_uploads" {
  source = "./modules/kms-cmk"
  alias  = "acme-uploads"
  description = "CMK for the starter's S3 uploads bucket (ePHI)."
}

module "kms_dynamodb" {
  source = "./modules/kms-cmk"
  alias  = "acme-submissions"
  description = "CMK for the starter's DynamoDB Submissions table (ePHI)."
}

module "kms_evidence" {
  source = "./modules/kms-cmk"
  alias  = "acme-evidence"
  description = "CMK for the evidence vault."
}

module "kms_cloudtrail" {
  source = "./modules/kms-cmk"
  alias  = "acme-cloudtrail"
  description = "CMK for CloudTrail mgmt trail."
  allow_cloudwatch_logs = true
  allow_cloudtrail      = true
}

# ──────────────────────────────────────────────────────────────────────────
# Evidence vault (Object Lock + KMS + access logging)
# ──────────────────────────────────────────────────────────────────────────
module "evidence_vault" {
  source         = "./modules/evidence-vault"
  name_prefix    = "acme-evidence"
  kms_key_arn    = module.kms_evidence.key_arn
  lock_mode      = var.evidence_vault_lock_mode
  retention_days = var.evidence_vault_retention_days
}

# ──────────────────────────────────────────────────────────────────────────
# GitHub OIDC trust (Layer 3 prereq)
# ──────────────────────────────────────────────────────────────────────────
module "github_oidc" {
  source      = "./modules/github-oidc"
  github_repo = var.github_repo
  role_name   = "acme-grc-gate"
}

# ──────────────────────────────────────────────────────────────────────────
# CloudTrail multi-region — HIPAA §164.312(b)
# Reuses lab-5-2 pattern. See terraform/cloudtrail.tf for the full block.
# ──────────────────────────────────────────────────────────────────────────

output "evidence_vault" { value = module.evidence_vault.vault_bucket }
output "ci_role_arn"    { value = module.github_oidc.role_arn }
output "api_url"        { value = module.starter.api_url }
output "uploads_bucket" { value = module.starter.uploads_bucket }
output "intake_table"   { value = module.starter.intake_table }
output "kms_keys" {
  value = {
    uploads     = module.kms_uploads.key_arn
    dynamodb    = module.kms_dynamodb.key_arn
    evidence    = module.kms_evidence.key_arn
    cloudtrail  = module.kms_cloudtrail.key_arn
  }
}
