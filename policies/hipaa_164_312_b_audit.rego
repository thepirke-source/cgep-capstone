# METADATA
# title: HIPAA §164.312(b) — Audit Controls
# description: |
#   The system must record activity touching ePHI. A multi-region CloudTrail with
#   log-file-validation enabled is the minimum bar. Missing trail or single-region
#   trail is non-compliant.
# custom:
#   framework: HIPAA Security Rule
#   control: 45 CFR §164.312(b)
#   nist_800_53: AU-2, AU-3, AU-12, AU-10
#   severity: HIGH
#   remediation: |
#     Add aws_cloudtrail with:
#       is_multi_region_trail = true
#       enable_log_file_validation = true
#       include_global_service_events = true
package hipaa.audit

import rego.v1

trails contains trail if {
	trail := input.resource_changes[_]
	trail.type == "aws_cloudtrail"
}

deny contains msg if {
	count(trails) == 0

	msg := "HIPAA §164.312(b) [AU-2/AU-12]: no aws_cloudtrail resource in the plan. Audit trail is mandatory."
}

deny contains msg if {
	trail := trails[_]
	trail.change.after.is_multi_region_trail != true

	msg := sprintf(
		"HIPAA §164.312(b) [AU-12]: trail %q is not multi-region. ePHI access can come from any region.",
		[trail.address],
	)
}

deny contains msg if {
	trail := trails[_]
	trail.change.after.enable_log_file_validation != true

	msg := sprintf(
		"HIPAA §164.312(b) [AU-10]: trail %q has log-file-validation disabled. Integrity of audit records is unprovable.",
		[trail.address],
	)
}
