package terraform.s3

import rego.v1

deny contains msg if {
  some rc in input.resource_changes
  rc.type == "aws_s3_bucket_public_access_block"
  rc.change.after.block_public_acls != true
  msg := sprintf("%s must block public ACLs", [rc.address])
}
deny contains msg if {
  some rc in input.resource_changes
  rc.type == "aws_s3_bucket_public_access_block"
  rc.change.after.block_public_policy != true
  msg := sprintf("%s must block public bucket policies", [rc.address])
}
deny contains msg if {
  some rc in input.resource_changes
  rc.type == "aws_s3_bucket_public_access_block"
  rc.change.after.ignore_public_acls != true
  msg := sprintf("%s must ignore public ACLs", [rc.address])
}
deny contains msg if {
  some rc in input.resource_changes
  rc.type == "aws_s3_bucket_public_access_block"
  rc.change.after.restrict_public_buckets != true
  msg := sprintf("%s must restrict public buckets", [rc.address])
}
deny contains msg if {
  some rc in input.resource_changes
  rc.type == "aws_s3_bucket_server_side_encryption_configuration"
  not rc.change.after.rule[0].apply_server_side_encryption_by_default.sse_algorithm in {"AES256", "aws:kms"}
  msg := sprintf("%s must configure AES256 or aws:kms encryption", [rc.address])
}
deny contains msg if {
  some rc in input.resource_changes
  rc.type == "aws_s3_bucket_versioning"
  rc.change.after.versioning_configuration[0].status != "Enabled"
  msg := sprintf("%s must enable versioning", [rc.address])
}
