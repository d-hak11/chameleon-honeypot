terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# Credentials come from the ambient AWS config (~/.aws/credentials) and are
# never placed in this repository. The instance itself uses an instance
# profile, so no key material is written to the honeypot host either.
provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project = "chameleon-honeypot"
    }
  }
}

# AWS publishes the AWS/Billing EstimatedCharges metric ONLY in us-east-1,
# regardless of where the resources being billed actually live. The cost
# alarm therefore needs an aliased provider; everything else stays in
# var.region.
provider "aws" {
  alias  = "billing"
  region = "us-east-1"

  default_tags {
    tags = {
      Project = "chameleon-honeypot"
    }
  }
}
