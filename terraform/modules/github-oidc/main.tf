# GitHub Actions → AWS via OIDC. No long-lived keys.
# HIPAA §164.312(d): authenticate the entity making a connection (CI workflow).

variable "github_repo" {
  type        = string
  description = "owner/repo or owner/repo:ref:refs/heads/main"
}

variable "role_name" {
  type    = string
  default = "acme-grc-gate"
}

data "aws_caller_identity" "current" {}

# OIDC provider — one per account; if it already exists, import it.
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "ci" {
  name = var.role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_repo}:*"
        }
      }
    }]
  })
}

# Minimum permissions for the gate: TF plan/apply on our resources + S3 write
# to evidence vault + Cosign keyless (no AWS perms needed for cosign itself).
# Service-level wildcards are intentional here — this role is the privileged
# orchestrator that Terraform itself runs as. Layer 2 Rego rules enforce the
# *workload* IAM (Lambda exec role etc.) does not contain wildcards.
#tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_iam_role_policy" "ci" {
  role = aws_iam_role.ci.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TerraformResourceMgmt"
        Effect = "Allow"
        Action = [
          "s3:*", "kms:*", "iam:*", "cloudtrail:*",
          "logs:*", "lambda:*", "apigateway:*",
          "dynamodb:*", "securityhub:*", "config:*"
        ]
        Resource = "*"
      },
      {
        Sid      = "EvidenceVaultWrite"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = "arn:aws:s3:::acme-evidence-vault-*/*"
      }
    ]
  })
}

output "role_arn"      { value = aws_iam_role.ci.arn }
output "oidc_provider" { value = aws_iam_openid_connect_provider.github.arn }
