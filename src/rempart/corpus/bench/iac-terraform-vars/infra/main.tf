variable "admin_cidr" {
  type    = string
  default = "0.0.0.0/0"
}

variable "trusted_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

locals {
  imds = "optional"
}

# rempart-expect: TF-NET-ADMIN-PORT-OPEN
resource "aws_security_group" "admin" {
  name = "admin"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
}

# rempart-safe: TF-NET-ADMIN-PORT-OPEN
resource "aws_security_group" "ops" {
  name = "ops"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.trusted_cidr]
  }
}

# rempart-expect: TF-EC2-IMDSV1
resource "aws_instance" "batch" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = local.imds
  }
}
