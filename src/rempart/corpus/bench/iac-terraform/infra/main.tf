# rempart-expect: TF-NET-ADMIN-PORT-OPEN
resource "aws_security_group" "bastion" {
  name = "bastion"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# rempart-safe: TF-NET-ADMIN-PORT-OPEN, TF-NET-ALL-PORTS-OPEN, TF-NET-DATA-PORT-OPEN
resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# rempart-safe: TF-NET-ADMIN-PORT-OPEN
resource "aws_security_group" "internal_ssh" {
  name = "internal-ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

# rempart-expect: TF-S3-PUBLIC-ACL
resource "aws_s3_bucket_acl" "assets" {
  bucket = "assets"
  acl    = "public-read"
}

# rempart-safe: TF-S3-PUBLIC-ACL
resource "aws_s3_bucket_acl" "logs" {
  bucket = "logs"
  acl    = "private"
}

# rempart-expect: TF-EC2-IMDSV1
resource "aws_instance" "worker" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "optional"
  }
}

# rempart-safe: TF-EC2-IMDSV1
resource "aws_instance" "api" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "required"
  }
}

# rempart-expect: TF-IAM-WILDCARD
resource "aws_iam_policy" "ci" {
  name = "ci"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# rempart-safe: TF-IAM-WILDCARD
resource "aws_iam_policy" "reader" {
  name = "reader"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::assets/*"
    }]
  })
}

# rempart-expect: TF-DB-PUBLIC, TF-DATA-UNENCRYPTED
resource "aws_db_instance" "main" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
  storage_encrypted   = false
  username            = "app"
  password            = var.db_password
}
