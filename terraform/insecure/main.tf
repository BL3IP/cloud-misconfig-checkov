# DELIBERATELY INSECURE Terraform for a Checkov demo. DO NOT DEPLOY.
# Each resource intentionally violates common CIS / Checkov controls.

provider "aws" {
  region = "us-east-1"
}

# S3 bucket: no encryption, no versioning, no logging, public access allowed
resource "aws_s3_bucket" "data" {
  bucket = "snapvault-insecure-demo"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Security group: SSH open to the entire internet
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "web sg"

  ingress {
    description = "SSH from anywhere (BAD)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# RDS: public, unencrypted, no backups
resource "aws_db_instance" "db" {
  allocated_storage   = 20
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = "Password123!" # hard-coded secret (BAD)
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}
