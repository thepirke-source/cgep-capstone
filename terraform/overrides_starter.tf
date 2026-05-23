# Capstone overrides — close GAPS.md items on the vendored starter workload
# (./starter). The starter module is applied in the same root, so resources are
# referenced directly via module outputs (no remote_state / data lookups, no
# deploy-ordering fragility).
#
# GAP-02 (DynamoDB CMK) is closed inside the starter module itself via
# var.submissions_kms_key_arn — see ./starter/main.tf. GAP-01/03/04/07 below.

# ── GAP-01: starter's uploads bucket SSE → customer CMK ────────────────────
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads_kms_override" {
  bucket = module.starter.uploads_bucket
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = module.kms_uploads.key_arn
    }
    bucket_key_enabled = true
  }
}

# ── GAP-03: TLS-only bucket policy (deny non-SecureTransport) ──────────────
resource "aws_s3_bucket_policy" "uploads_tls_override" {
  bucket = module.starter.uploads_bucket
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        module.starter.uploads_bucket_arn,
        "${module.starter.uploads_bucket_arn}/*"
      ]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# ── (defense in depth) public access block on uploads ──────────────────────
resource "aws_s3_bucket_public_access_block" "uploads_pab_override" {
  bucket                  = module.starter.uploads_bucket
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── GAP-04: versioning on uploads ──────────────────────────────────────────
resource "aws_s3_bucket_versioning" "uploads_versioning_override" {
  bucket = module.starter.uploads_bucket
  versioning_configuration { status = "Enabled" }
}

# ── GAP-07: least-privilege replacement for the starter's removed wildcards ─
resource "aws_iam_role_policy" "lambda_dynamodb_scoped" {
  name = "intake-dynamodb-scoped"
  role = module.starter.lambda_role_name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "dynamodb:Query",
        "dynamodb:UpdateItem"
      ]
      Resource = module.starter.intake_table_arn
    }]
  })
}

resource "aws_iam_role_policy" "lambda_s3_scoped" {
  name = "intake-s3-scoped"
  role = module.starter.lambda_role_name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:GetObject"]
      Resource = "${module.starter.uploads_bucket_arn}/*"
    }]
  })
}

# Bringing the data stores under customer CMKs (GAP-01/02) means the workload
# identity must be granted use of those keys — least-privilege, scoped to the
# two data-domain CMKs only, just the verbs S3/DynamoDB SSE needs.
resource "aws_iam_role_policy" "lambda_kms_scoped" {
  name = "intake-kms-scoped"
  role = module.starter.lambda_role_name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["kms:Decrypt", "kms:GenerateDataKey"]
      Resource = [
        module.kms_uploads.key_arn,
        module.kms_dynamodb.key_arn
      ]
    }]
  })
}
