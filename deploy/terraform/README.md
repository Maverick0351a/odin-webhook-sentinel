# Terraform Deployment (ECS Fargate)

Minimal example to run Sentinel as an ECS Fargate service.

## Variables
- region
- image (pin digest!)
- subnets (list)
- security_groups (list)
- desired_count (default 1)

## Example
```hcl
module "sentinel" {
  source          = "./deploy/terraform"
  region          = "us-east-1"
  image           = "ghcr.io/Maverick0351a/odin-webhook-sentinel:1.0.0"
  subnets         = ["subnet-abc", "subnet-def"]
  security_groups = ["sg-123"]
}
```

Add secret injection via AWS Secrets Manager by extending `environment` or using `secrets` in `container_definitions`.
