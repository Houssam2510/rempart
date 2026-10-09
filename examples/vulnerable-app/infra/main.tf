resource "aws_s3_bucket_acl" "uploads" {
  bucket = "demo-uploads"
  acl    = "public-read"
}

resource "aws_security_group" "db" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  publicly_accessible = true
  storage_encrypted   = false
}

resource "aws_iam_policy" "ci" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_instance" "worker" {
  ami = "ami-00000000"
}
