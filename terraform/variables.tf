variable "aws_region" {
  type        = string
  description = "AWS region. HIPAA-eligible regions only."
  default     = "us-east-1"

  validation {
    condition     = contains(["us-east-1", "us-east-2", "us-west-2"], var.aws_region)
    error_message = "Region must be a HIPAA-eligible region in the BAA scope."
  }
}

variable "environment" {
  type        = string
  description = "Deployment environment."
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "evidence_vault_retention_days" {
  type        = number
  description = "Object Lock retention for the evidence vault. HIPAA: 6yr (2190d) for prod; 1d for lab."
  default     = 1

  validation {
    condition     = var.evidence_vault_retention_days >= 1
    error_message = "Retention must be at least 1 day."
  }
}

# HIPAA §164.316(b)(2)(i): prod evidence must be retained >= 6yr. Enforced as a
# cross-variable precondition (TF disallows referencing other vars inside a
# variable's own validation block).
check "prod_evidence_retention" {
  assert {
    condition     = var.environment != "prod" || var.evidence_vault_retention_days >= 2190
    error_message = "Prod evidence vault retention must be >= 2190d (HIPAA §164.316(b)(2)(i))."
  }
}

variable "evidence_vault_lock_mode" {
  type        = string
  description = "Object Lock mode. GOVERNANCE for lab, COMPLIANCE for prod."
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.evidence_vault_lock_mode)
    error_message = "Must be GOVERNANCE or COMPLIANCE."
  }
}

variable "github_repo" {
  type        = string
  description = "owner/repo for GitHub OIDC trust."
  default     = "thepirke-source/cgep-portfolio"
}
