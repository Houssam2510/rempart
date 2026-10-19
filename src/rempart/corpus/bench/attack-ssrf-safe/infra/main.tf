resource "aws_instance" "api" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  user_data     = "docker run -p 80:5000 registry.example/api:latest"
  metadata_options {
    http_tokens = "required"
  }
}
