package hipaa.encryption_test

import data.hipaa.encryption

# Pass: KMS encryption
test_kms_passes if {
	plan := {"resource_changes": [{
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"change": {"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]}},
	}]}
	count(encryption.deny) == 0 with input as plan
}

# Fail: AES256 only
test_aes256_fails if {
	plan := {"resource_changes": [{
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"change": {"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]}},
	}]}
	count(encryption.deny) > 0 with input as plan
}

# Fail: DynamoDB without KMS
test_dynamo_no_kms_fails if {
	plan := {"resource_changes": [{
		"type": "aws_dynamodb_table",
		"address": "aws_dynamodb_table.submissions",
		"change": {"after": {"server_side_encryption": [{"enabled": true}]}},
	}]}
	count(encryption.deny) > 0 with input as plan
}
