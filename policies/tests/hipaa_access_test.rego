package hipaa.access_test

import data.hipaa.access

# Pass: bucket + PAB with all four flags true
test_compliant_passes if {
	plan := {"resource_changes": [
		{"type": "aws_s3_bucket", "address": "aws_s3_bucket.uploads", "change": {"after": {"bucket": "x"}}},
		{
			"type": "aws_s3_bucket_public_access_block",
			"address": "aws_s3_bucket_public_access_block.uploads",
			"change": {"after": {
				"block_public_acls": true,
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			}},
		},
	]}
	count(access.deny) == 0 with input as plan
}

# Fail: bucket without PAB
test_no_pab_fails if {
	plan := {"resource_changes": [{"type": "aws_s3_bucket", "address": "aws_s3_bucket.uploads", "change": {"after": {"bucket": "x"}}}]}
	count(access.deny) > 0 with input as plan
}

# Fail: PAB with one flag false
test_one_flag_false_fails if {
	plan := {"resource_changes": [
		{"type": "aws_s3_bucket", "address": "aws_s3_bucket.uploads", "change": {"after": {"bucket": "x"}}},
		{
			"type": "aws_s3_bucket_public_access_block",
			"address": "aws_s3_bucket_public_access_block.uploads",
			"change": {"after": {
				"block_public_acls": true,
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": false,
			}},
		},
	]}
	count(access.deny) > 0 with input as plan
}
