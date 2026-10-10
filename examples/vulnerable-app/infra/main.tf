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

resource "aws_iam_role" "worker" {
  name               = "worker"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy_attachment" "worker_ci" {
  role       = aws_iam_role.worker.name
  policy_arn = aws_iam_policy.ci.arn
}

resource "aws_iam_instance_profile" "worker" {
  role = aws_iam_role.worker.name
}

resource "aws_instance" "worker" {
  ami                  = "ami-00000000"
  iam_instance_profile = aws_iam_instance_profile.worker.name
  user_data            = "docker run -d -p 80:8000 demo/api:latest"
}
