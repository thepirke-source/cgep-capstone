package hipaa.transit_test

import data.hipaa.transit

tls_deny_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "DenyInsecureTransport",
		"Effect": "Deny",
		"Action": "s3:*",
		"Principal": "*",
		"Resource": "*",
		"Condition": {"Bool": {"aws:SecureTransport": "false"}},
	}],
})

no_tls_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "AllowAll",
		"Effect": "Allow",
		"Action": "s3:GetObject",
		"Principal": "*",
		"Resource": "*",
	}],
})

# Pass: bucket policy with TLS deny
test_tls_deny_passes if {
	plan := {"resource_changes": [{
		"type": "aws_s3_bucket_policy",
		"address": "aws_s3_bucket_policy.uploads",
		"change": {"after": {"policy": tls_deny_policy}},
	}]}
	count(transit.deny) == 0 with input as plan
}

# Fail: bucket policy without TLS deny
test_no_tls_deny_fails if {
	plan := {"resource_changes": [{
		"type": "aws_s3_bucket_policy",
		"address": "aws_s3_bucket_policy.uploads",
		"change": {"after": {"policy": no_tls_policy}},
	}]}
	count(transit.deny) > 0 with input as plan
}

# Fail: API GW with TLS < 1.2
test_apigw_old_tls_fails if {
	plan := {"resource_changes": [{
		"type": "aws_api_gateway_domain_name",
		"address": "aws_api_gateway_domain_name.api",
		"change": {"after": {"security_policy": "TLS_1_0"}},
	}]}
	count(transit.deny) > 0 with input as plan
}
