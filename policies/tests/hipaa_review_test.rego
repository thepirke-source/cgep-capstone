package hipaa.review_test

import data.hipaa.review

wildcard_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Action": "dynamodb:*",
		"Resource": "*",
	}],
})

star_action_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Action": "*",
		"Resource": "*",
	}],
})

scoped_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Action": ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Query"],
		"Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/Submissions",
	}],
})

# Pass: scoped verbs
test_scoped_passes if {
	plan := {"resource_changes": [{
		"type": "aws_iam_role_policy",
		"address": "aws_iam_role_policy.lambda",
		"change": {"after": {"policy": scoped_policy}},
	}]}
	count(review.deny) == 0 with input as plan
}

# Fail: dynamodb:* wildcard
test_service_wildcard_fails if {
	plan := {"resource_changes": [{
		"type": "aws_iam_role_policy",
		"address": "aws_iam_role_policy.lambda",
		"change": {"after": {"policy": wildcard_policy}},
	}]}
	count(review.deny) > 0 with input as plan
}

# Fail: Action: "*"
test_star_action_fails if {
	plan := {"resource_changes": [{
		"type": "aws_iam_role_policy",
		"address": "aws_iam_role_policy.lambda",
		"change": {"after": {"policy": star_action_policy}},
	}]}
	count(review.deny) > 0 with input as plan
}
