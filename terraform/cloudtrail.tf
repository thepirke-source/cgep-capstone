# HIPAA §164.312(b) — Audit Controls.
# Multi-region trail, log-file-validation, CW Logs, KMS-encrypted.
# Pattern from lab-5-2/main.tf, tightened.

data "aws_caller_identity" "ct_current" {}

resource "random_id" "ct_suffix" { byte_length = 4 }

locals {
  ct_trail_bucket = "acme-cloudtrail-${random_id.ct_suffix.hex}"
  ct_log_bucket   = "acme-cloudtrail-logs-${random_id.ct_suffix.hex}"
  ct_log_group    = "/aws/cloudtrail/acme-mgmt"
}

resource "aws_s3_bucket" "trail" {
  bucket        = local.ct_trail_bucket
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = module.kms_cloudtrail.key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Audit-of-audit: dedicated log bucket for the trail bucket
resource "aws_s3_bucket" "ct_log" { bucket = local.ct_log_bucket }

resource "aws_s3_bucket_ownership_controls" "ct_log" {
  bucket = aws_s3_bucket.ct_log.id
  rule { object_ownership = "BucketOwnerPreferred" }
}

resource "aws_s3_bucket_acl" "ct_log" {
  depends_on = [aws_s3_bucket_ownership_controls.ct_log]
  bucket     = aws_s3_bucket.ct_log.id
  acl        = "log-delivery-write"
}

resource "aws_s3_bucket_versioning" "ct_log" {
  bucket = aws_s3_bucket.ct_log.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ct_log" {
  bucket = aws_s3_bucket.ct_log.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "ct_log" {
  bucket                  = aws_s3_bucket.ct_log.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "trail" {
  bucket        = aws_s3_bucket.trail.id
  target_bucket = aws_s3_bucket.ct_log.id
  target_prefix = "access-logs/"
}

#tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = ["${aws_s3_bucket.trail.arn}", "${aws_s3_bucket.trail.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.ct_current.account_id}:trail/acme-mgmt"
          }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.ct_current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.ct_current.account_id}:trail/acme-mgmt"
          }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "trail" {
  name              = local.ct_log_group
  retention_in_days = 365
  kms_key_id        = module.kms_cloudtrail.key_arn
}

#tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_iam_role" "trail_cw" {
  name = "acme-cloudtrail-cw-${random_id.ct_suffix.hex}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

#tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_iam_role_policy" "trail_cw" {
  role = aws_iam_role.trail_cw.id
  # ":*" on a log group ARN is the AWS-documented scoping form.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.trail.arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "mgmt" {
  name                          = "acme-mgmt"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = module.kms_cloudtrail.key_arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_cw.arn

  depends_on = [aws_s3_bucket_policy.trail, aws_iam_role_policy.trail_cw]
}
