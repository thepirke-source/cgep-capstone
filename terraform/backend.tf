# Remote state — S3 backend with DynamoDB lock.
# The state bucket + lock table are bootstrapped out-of-band (see
# bootstrap/ ) because a backend cannot create its own storage. CI and local
# share this state so the pipeline plans against real infrastructure.
terraform {
  backend "s3" {
    bucket         = "acme-tfstate-0f147130"
    key            = "capstone/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "acme-tfstate-lock"
    encrypt        = true
  }
}
