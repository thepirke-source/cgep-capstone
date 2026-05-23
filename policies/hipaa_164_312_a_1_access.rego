# METADATA
# title: HIPAA §164.312(a)(1) — Access Control
# description: |
#   No S3 bucket holding ePHI or its evidence may be publicly accessible.
#   All four public-access-block flags must be true; AWS treats them as independent.
# custom:
#   framework: HIPAA Security Rule
#   control: 45 CFR §164.312(a)(1)
#   nist_800_53: AC-3
#   severity: CRITICAL
#   remediation: |
#     Add an aws_s3_bucket_public_access_block with all four flags = true:
#     block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets.
package hipaa.access

import rego.v1

required_flags := {
	"block_public_acls",
	"block_public_policy",
	"ignore_public_acls",
	"restrict_public_buckets",
}

# Find every S3 bucket
s3_buckets contains bucket if {
	bucket := input.resource_changes[_]
	bucket.type == "aws_s3_bucket"
}

# Find every PAB and the bucket it points at (best-effort by name suffix).
pabs contains pab if {
	pab := input.resource_changes[_]
	pab.type == "aws_s3_bucket_public_access_block"
}

deny contains msg if {
	bucket := s3_buckets[_]
	bucket_addr := bucket.address
	not pab_covers_bucket(bucket_addr)

	msg := sprintf(
		"HIPAA §164.312(a)(1) [AC-3]: S3 bucket %q has no aws_s3_bucket_public_access_block.",
		[bucket_addr],
	)
}

deny contains msg if {
	pab := pabs[_]
	flag := required_flags[_]
	pab.change.after[flag] != true

	msg := sprintf(
		"HIPAA §164.312(a)(1) [AC-3]: PAB %q has %s=%v; must be true.",
		[pab.address, flag, pab.change.after[flag]],
	)
}

pab_covers_bucket(bucket_addr) if {
	pab := pabs[_]
	# heuristic: PAB resource address shares its suffix with the bucket's
	contains(pab.address, suffix(bucket_addr))
}

suffix(addr) := s if {
	parts := split(addr, ".")
	s := parts[count(parts) - 1]
}
