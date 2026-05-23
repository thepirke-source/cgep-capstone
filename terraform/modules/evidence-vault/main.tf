# HIPAA §164.312(c)(1) Integrity + §164.316(b)(2)(i) Retention.
# S3 + Object Lock + KMS + access logging. The pipeline writes signed
# evidence bundles here. Object Lock makes them immutable.

terraform {
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

variable "name_prefix"      { type = string }
variable "kms_key_arn"      { type = string }
variable "lock_mode"        { type = string }  # GOVERNANCE | COMPLIANCE
variable "retention_days"   { type = number }

resource "random_id" "suffix" { byte_length = 4 }

locals {
  vault_name = "${var.name_prefix}-vault-${random_id.suffix.hex}"
  log_name   = "${var.name_prefix}-vault-logs-${random_id.suffix.hex}"
}

# ── Vault bucket ────────────────────────────────────────────────────────────
resource "aws_s3_bucket" "vault" {
  bucket              = local.vault_name
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "vault" {
  bucket = aws_s3_bucket.vault.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    default_retention {
      mode = var.lock_mode
      days = var.retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.vault]
}

resource "aws_s3_bucket_public_access_block" "vault" {
  bucket                  = aws_s3_bucket.vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# TLS-only access (HIPAA §164.312(e)(1))
#tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_s3_bucket_policy" "vault" {
  bucket = aws_s3_bucket.vault.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = ["${aws_s3_bucket.vault.arn}", "${aws_s3_bucket.vault.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# ── Log bucket (audit-of-audit) ─────────────────────────────────────────────
resource "aws_s3_bucket" "log" { bucket = local.log_name }

resource "aws_s3_bucket_ownership_controls" "log" {
  bucket = aws_s3_bucket.log.id
  rule { object_ownership = "BucketOwnerPreferred" }
}

resource "aws_s3_bucket_acl" "log" {
  depends_on = [aws_s3_bucket_ownership_controls.log]
  bucket     = aws_s3_bucket.log.id
  acl        = "log-delivery-write"
}

resource "aws_s3_bucket_versioning" "log" {
  bucket = aws_s3_bucket.log.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log" {
  bucket = aws_s3_bucket.log.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "log" {
  bucket                  = aws_s3_bucket.log.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "vault" {
  bucket        = aws_s3_bucket.vault.id
  target_bucket = aws_s3_bucket.log.id
  target_prefix = "access-logs/"
}

output "vault_bucket"     { value = aws_s3_bucket.vault.id }
output "vault_arn"        { value = aws_s3_bucket.vault.arn }
output "log_bucket"       { value = aws_s3_bucket.log.id }
