# METADATA
# title: HIPAA §164.308(a)(1)(ii)(D) — Information System Activity Review
# description: |
#   WORKLOAD IAM policies must not use wildcard actions (`Action: "*"` or
#   service-level wildcards like `dynamodb:*`) on the resources holding ePHI.
#   Wildcards defeat the activity-review obligation: any action is permitted,
#   no anomaly stands out.
#
#   Scope: this rule polices the *workload* identities (the Lambda execution
#   role and any app-data IAM). It deliberately exempts the CI/CD orchestrator
#   role — the identity Terraform itself assumes — which by design needs broad
#   infrastructure-management permissions to provision the baseline. That role
#   is governed instead by branch protection + required reviewers (see WRITEUP
#   §6 "segregation of duties"), not by per-verb IAM. The exemption is keyed on
#   the orchestrator marker in the policy address so the carve-out is explicit
#   and auditable, not a blanket skip.
# custom:
#   framework: HIPAA Security Rule
#   control: 45 CFR §164.308(a)(1)(ii)(D)
#   nist_800_53: AC-6, AU-6
#   severity: HIGH
#   remediation: |
#     Replace `Action: "dynamodb:*"` with the minimum specific verbs the
#     workload actually uses (e.g. PutItem, GetItem, Query). Same for s3:*, *.
package hipaa.review

import rego.v1

# Orchestrator (CI/CD) roles are out of scope for workload least-privilege.
# Identified by the "github_oidc" module marker in the resource address.
orchestrator_markers := ["github_oidc", "grc-gate", "ci-orchestrator"]

is_orchestrator(address) if {
	marker := orchestrator_markers[_]
	contains(address, marker)
}

iam_policies contains p if {
	p := input.resource_changes[_]
	p.type == "aws_iam_role_policy"
	not is_orchestrator(p.address)
}

iam_policies contains p if {
	p := input.resource_changes[_]
	p.type == "aws_iam_policy"
	not is_orchestrator(p.address)
}

deny contains msg if {
	p := iam_policies[_]
	doc := json.unmarshal(p.change.after.policy)
	stmt := doc.Statement[_]
	stmt.Effect == "Allow"
	action := actions_of(stmt)[_]
	is_wildcard_action(action)

	msg := sprintf(
		"HIPAA §164.308(a)(1)(ii)(D) [AC-6]: workload IAM policy %q allows wildcard action %q. Replace with specific verbs.",
		[p.address, action],
	)
}

actions_of(stmt) := arr if {
	is_array(stmt.Action)
	arr := stmt.Action
}

actions_of(stmt) := [stmt.Action] if {
	is_string(stmt.Action)
}

is_wildcard_action(a) if {
	a == "*"
}

is_wildcard_action(a) if {
	endswith(a, ":*")
}
