# AWS Quick Deploy

This Terraform stack provisions one Ubuntu EC2 instance, installs Docker, clones this repo, builds the API image, and runs the FastAPI service on port `8000`.

## What It Creates

- 1 EC2 instance in the default VPC
- 1 security group
- 1 IAM role + instance profile for AWS Systems Manager access

## Before You Start

1. Push this project to a Git repository the EC2 instance can clone.
2. Install Terraform and configure AWS credentials locally.
3. Decide which IP ranges should reach the API and, if needed, SSH.

## Quick Start

```bash
cd deploy/aws/terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` and set:

- `repo_url`
- `groq_api_key`
- `exa_api_key` if you use Exa
- `allowed_api_cidrs`
- `allowed_ssh_cidrs` and `key_name` if you want SSH

Deploy:

```bash
terraform init
terraform plan
terraform apply
```

When apply finishes, Terraform prints:

- `api_base_url`
- `healthcheck_url`
- `instance_public_ip`

## Validate The Deployment

Health check:

```bash
curl http://YOUR_PUBLIC_DNS:8000/health
```

Trigger a detection run:

```bash
curl -X POST http://YOUR_PUBLIC_DNS:8000/run \
  -H "Content-Type: application/json" \
  -d "{\"mode\":\"detect\",\"log_paths\":\"/var/log/auth.log,/var/log/syslog\",\"scan_hours\":24}"
```

## Notes

- This is a fast EC2-based deployment, not a full production platform.
- The app uses Ubuntu log locations like `/var/log/auth.log` and `/var/log/syslog`, so the instance is intentionally Ubuntu-based.
- API keys land in Terraform state and on the instance `.env` file in this quick setup. For a hardened production deployment, move them to AWS Secrets Manager or SSM Parameter Store and fetch them at runtime.
- SSH is optional. If you leave `allowed_ssh_cidrs = []`, the instance is still reachable through AWS Systems Manager.

## Tear Down

```bash
terraform destroy
```
