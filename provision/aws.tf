variable "aws_region" {
  description = "AWS region to provision infrastructure in"
}

variable "aws_access_key_id" {
  description = "AWS access key ID"
}

variable "aws_secret_access_key" {
  description = "AWS secret access key"
}

provider "aws" {
  region     = var.aws_region
  access_key = var.aws_access_key_id
  secret_key = var.aws_secret_access_key
}
