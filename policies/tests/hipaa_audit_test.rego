package hipaa.audit_test

import data.hipaa.audit

# Pass: multi-region trail w/ log-file-validation
test_compliant_passes if {
	plan := {"resource_changes": [{
		"type": "aws_cloudtrail",
		"address": "aws_cloudtrail.mgmt",
		"change": {"after": {
			"is_multi_region_trail": true,
			"enable_log_file_validation": true,
			"include_global_service_events": true,
		}},
	}]}
	count(audit.deny) == 0 with input as plan
}

# Fail: no trail at all
test_no_trail_fails if {
	plan := {"resource_changes": []}
	count(audit.deny) > 0 with input as plan
}

# Fail: single-region trail
test_single_region_fails if {
	plan := {"resource_changes": [{
		"type": "aws_cloudtrail",
		"address": "aws_cloudtrail.mgmt",
		"change": {"after": {
			"is_multi_region_trail": false,
			"enable_log_file_validation": true,
		}},
	}]}
	count(audit.deny) > 0 with input as plan
}

# Fail: missing log-file-validation
test_no_lfv_fails if {
	plan := {"resource_changes": [{
		"type": "aws_cloudtrail",
		"address": "aws_cloudtrail.mgmt",
		"change": {"after": {
			"is_multi_region_trail": true,
			"enable_log_file_validation": false,
		}},
	}]}
	count(audit.deny) > 0 with input as plan
}
