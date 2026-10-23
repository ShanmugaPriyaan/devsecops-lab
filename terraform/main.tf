# Deliberately misconfigured AWS resources for the CSPM lab.
# Deploy only from the tag v0-insecure, and run `terraform destroy` the same day.

terraform {
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.0" }
  }
}

provider "aws" {
  region = "ca-central-1"
  default_tags {
    tags = { Project = "cspm-lab", Owner = "shanmuga", DataClass = "test" }
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

# FLAW: bucket with public access block turned off and a public-read policy
resource "aws_s3_bucket" "lab" {
  bucket        = "cspm-lab-public-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "lab" {
  bucket                  = aws_s3_bucket.lab.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_read" {
  bucket     = aws_s3_bucket.lab.id
  depends_on = [aws_s3_bucket_public_access_block.lab]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.lab.arn}/*"
    }]
  })
}

# FLAW: SSH open to the whole internet (in the default VPC)
resource "aws_security_group" "ssh_any" {
  name        = "cspm-lab-ssh-any"
  description = "Lab: deliberately open SSH"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

output "bucket_name" {
  value = aws_s3_bucket.lab.id
}
