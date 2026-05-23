# METADATA
# title: HIPAA §164.312(e)(1) — Transmission Security
# description: |
#   ePHI in transit must be encrypted. Every S3 bucket policy must include
#   a Deny on `s3:*` when `aws:SecureTransport` is false. API Gateway must
#   reject TLS < 1.2.
# custom:
#   framework: HIPAA Security Rule
#   control: 45 CFR §164.312(e)(1)
#   nist_800_53: SC-8, SC-13
#   severity: HIGH
#   remediation: |
#     Attach an aws_s3_bucket_policy with a statement:
#       Effect: Deny
#       Action: s3:*
#       Condition: { Bool: { aws:SecureTransport: false } }
package hipaa.transit

import rego.v1

bucket_policies contains bp if {
	bp := input.resource_changes[_]
	bp.type == "aws_s3_bucket_policy"
}

deny contains msg if {
	bp := bucket_policies[_]
	policy_json := json.unmarshal(bp.change.after.policy)
	not has_tls_deny(policy_json)

	msg := sprintf(
		"HIPAA §164.312(e)(1) [SC-8]: bucket policy %q has no Deny-on-insecure-transport statement.",
		[bp.address],
	)
}

has_tls_deny(policy) if {
	stmt := policy.Statement[_]
	stmt.Effect == "Deny"
	stmt.Condition.Bool["aws:SecureTransport"] == "false"
}

# API Gateway TLS minimum
deny contains msg if {
	stage := input.resource_changes[_]
	stage.type == "aws_api_gateway_domain_name"
	stage.change.after.security_policy != "TLS_1_2"

	msg := sprintf(
		"HIPAA §164.312(e)(1) [SC-8]: API GW domain %q allows TLS < 1.2. Set security_policy = \"TLS_1_2\".",
		[stage.address],
	)
}
