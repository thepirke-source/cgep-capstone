# SC-12 / SC-13 / SC-28: customer-managed KMS key with rotation.
# Reused by every encrypted resource in the capstone.

variable "alias" {
  type        = string
  description = "Short alias (no prefix). 'alias/' is added."
}

variable "description" {
  type    = string
  default = "Acme Health ePHI CMK"
}

variable "deletion_window_in_days" {
  type    = number
  default = 7
}

variable "key_policy_json" {
  type        = string
  description = "Optional override of the key policy. If empty, the module emits a default that grants root + service-conditional access."
  default     = ""
}

variable "allow_cloudwatch_logs" {
  type        = bool
  description = "Grant the regional CloudWatch Logs service principal encrypt/decrypt on this key (needed for CloudTrail→CW Logs)."
  default     = false
}

variable "allow_cloudtrail" {
  type        = bool
  description = "Grant the CloudTrail service principal GenerateDataKey/Decrypt on this key (needed to KMS-encrypt trail log files)."
  default     = false
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  cw_logs_all = [{
    Sid       = "AllowCloudWatchLogs"
    Effect    = "Allow"
    Principal = { Service = "logs.${data.aws_region.current.name}.amazonaws.com" }
    Action = [
      "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
      "kms:GenerateDataKey*", "kms:DescribeKey"
    ]
    Resource = "*"
  }]
  cw_logs_statement = [for s in local.cw_logs_all : s if var.allow_cloudwatch_logs]

  cloudtrail_all = [
    {
      Sid       = "AllowCloudTrailEncrypt"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "kms:GenerateDataKey*"
      Resource  = "*"
      Condition = {
        StringLike = {
          "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
        }
      }
    },
    {
      Sid       = "AllowCloudTrailDescribe"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "kms:DescribeKey"
      Resource  = "*"
    }
  ]
  cloudtrail_statement = [for s in local.cloudtrail_all : s if var.allow_cloudtrail]

  base_statement = [{
    Sid       = "EnableRootPermissions"
    Effect    = "Allow"
    Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
    Action    = "kms:*"
    Resource  = "*"
  }]

  default_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = concat(local.base_statement, local.cw_logs_statement, local.cloudtrail_statement)
  })
}

resource "aws_kms_key" "this" {
  description             = var.description
  enable_key_rotation     = true
  deletion_window_in_days = var.deletion_window_in_days
  policy                  = var.key_policy_json != "" ? var.key_policy_json : local.default_policy
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.alias}"
  target_key_id = aws_kms_key.this.key_id
}

output "key_arn"   { value = aws_kms_key.this.arn }
output "key_id"    { value = aws_kms_key.this.key_id }
output "alias_arn" { value = aws_kms_alias.this.arn }
