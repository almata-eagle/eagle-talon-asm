# Eagle Talon — minimal AWS demo host
# One t3.small running Docker Compose (nginx + FastAPI). Good enough for a
# stakeholder demo; NOT a hardened production topology (see README for the
# real ECS Fargate + ALB + CloudFront path once you're past prototype stage).

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

variable "aws_region"    { default = "us-east-1" }
variable "instance_type" { default = "t3.small" }
variable "key_name"      { description = "Existing EC2 key pair name for SSH access" }
variable "my_ip_cidr"    { description = "Your IP in CIDR form, e.g. 203.0.113.4/32 — restricts SSH/demo access" }

provider "aws" { region = var.aws_region }

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

resource "aws_security_group" "eagle_talon" {
  name        = "eagle-talon-demo"
  description = "Eagle Talon prototype demo host"

  ingress {
    description = "SSH"
    from_port = 22, to_port = 22, protocol = "tcp"
    cidr_blocks = [var.my_ip_cidr]
  }
  ingress {
    description = "HTTP (UI)"
    from_port = 80, to_port = 80, protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "API (direct, optional)"
    from_port = 8000, to_port = 8000, protocol = "tcp"
    cidr_blocks = [var.my_ip_cidr]
  }
  egress {
    from_port = 0, to_port = 0, protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "eagle_talon" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = var.key_name
  vpc_security_group_ids = [aws_security_group.eagle_talon.id]

  user_data = <<-EOF
    #!/bin/bash
    apt-get update -y
    apt-get install -y docker.io docker-compose-plugin
    systemctl enable --now docker
    usermod -aG docker ubuntu
  EOF

  tags = { Name = "eagle-talon-demo" }
}

output "public_ip" {
  value = aws_instance.eagle_talon.public_ip
}

output "next_steps" {
  value = "scp -r ../.. ubuntu@${aws_instance.eagle_talon.public_ip}:~/eagle-talon && ssh ubuntu@${aws_instance.eagle_talon.public_ip} 'cd eagle-talon/deploy && docker compose up -d --build'"
}
