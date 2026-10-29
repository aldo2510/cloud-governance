# cloud-governance

Policy as Code for the GenAI Infrastructure Platform lab.

## S3 controls

The policy in policy/s3.rego evaluates Terraform plan JSON and requires all S3 public-access-block settings to be enabled, server-side encryption to use AES256 or AWS KMS, and bucket versioning to be enabled.

## Run locally

```bash
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
opa test policy tests -v
opa eval --data policy/s3.rego --input plan.json 'data.terraform.s3.deny'
```

The policy must be tested against representative plan JSON fixtures before production use. A policy decision is only as good as its input and the resources covered by its rules.
