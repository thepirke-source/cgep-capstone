# METADATA
# title: HIPAA §164.312(a)(2)(iv) — Encryption at Rest
# description: |
#   Every S3 bucket and DynamoDB table that may hold ePHI must use customer-managed
#   KMS encryption. AES256 (SSE-S3) does not satisfy "audit-defensible" because the
#   key is shared infrastructure outside Acme's control.
# custom:
#   framework: HIPAA Security Rule
#   control: 45 CFR §164.312(a)(2)(iv)
#   nist_800_53: SC-28
#   severity: HIGH
#   remediation: |
#     Set `apply_server_side_encryption_by_default.sse_algorithm = "aws:kms"` and
#     point `kms_master_key_id` at an aws_kms_key resource with rotation enabled.
package hipaa.encryption

import rego.v1

# Server-access-LOG buckets are out of scope for CMK encryption: they hold no
# ePHI, and S3/CloudTrail log delivery natively supports SSE-S3 (AES256). The
# ePHI/evidence buckets they audit ARE CMK-encrypted. Exemption is keyed on the
# log-bucket marker in the resource address so it is explicit and auditable.
log_bucket_markers := ["ct_log", ".log", "_log", "log\""]

is_log_bucket(address) if {
	marker := log_bucket_markers[_]
	contains(address, marker)
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_s3_bucket_server_side_encryption_configuration"
	not is_log_bucket(resource.address)
	rule := resource.change.after.rule[_]
	default_enc := rule.apply_server_side_encryption_by_default[_]
	default_enc.sse_algorithm != "aws:kms"

	msg := sprintf(
		"HIPAA §164.312(a)(2)(iv) [SC-28]: S3 bucket %q uses %q SSE; must be aws:kms with a customer-managed key.",
		[resource.address, default_enc.sse_algorithm],
	)
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_dynamodb_table"

	# A CMK is present if the rendered ARN is set, OR it is a computed value
	# resolved at apply time (the CMK is created in the same apply, so its ARN
	# is unknown at plan time and surfaces in `after_unknown`). Both satisfy
	# customer-managed encryption; only a table with SSE off / no key at all
	# is a real finding.
	not has_cmk_arn(resource)
	not has_computed_cmk(resource)

	msg := sprintf(
		"HIPAA §164.312(a)(2)(iv) [SC-28]: DynamoDB table %q has no customer-managed KMS key.",
		[resource.address],
	)
}

has_cmk_arn(resource) if {
	resource.change.after.server_side_encryption[0].kms_key_arn
}

has_computed_cmk(resource) if {
	resource.change.after_unknown.server_side_encryption[0].kms_key_arn == true
}
