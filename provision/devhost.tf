variable "bastion_ssh_pubkey" {
  description = "Public key for SSH keypair that can access bastion host"
}

# this setup is based on https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html#nat-gateway-testing-example

# create small EC2 instance running Amazon Linux 2 in public subnet to act as bastion
data "aws_ami" "amazon-linux-2" {
  most_recent = true
  owners = ["amazon"]
  filter {
    name = "name"
    values = ["amzn2-ami-hvm*"]
  }
}
resource "aws_instance" "bastion" {
  ami = data.aws_ami.amazon-linux-2.id
  instance_type = "t3.nano"
  subnet_id = aws_subnet.public-subnet.0.id
  vpc_security_group_ids = [aws_security_group.instance-security-group.id]
  key_name = aws_key_pair.devhost-key.key_name
  tags = {
    Name = "bastion"
  }
}
resource "aws_eip" "bastion-ip-address" {
  vpc = true
  instance = aws_instance.bastion.id
  tags = {
    Name = "bastion-ip-address"
  }
}

# create medium EC2 instance running Amazon Linux 2 in private subnet to act as dev host
resource "aws_instance" "devhost" {
  ami = data.aws_ami.amazon-linux-2.id
  instance_type = "t3.medium"
  subnet_id = aws_subnet.private-subnet.0.id
  vpc_security_group_ids = [aws_security_group.instance-security-group.id]
  key_name = aws_key_pair.devhost-key.key_name
  private_ip = "10.0.2.90"  # this is fixed because otherwise the private IP may change whenever the instance reboots
  root_block_device {
    volume_size = 20
  }
  tags = {
    Name = "devhost"
  }
}
resource "aws_key_pair" "devhost-key" {
  key_name = "devhost-key"
  public_key = var.bastion_ssh_pubkey
}
resource "aws_security_group" "instance-security-group" {
  name = "instance-security-group"
  description = "Allow all outbound traffic and inbound SSH traffic"
  vpc_id = aws_vpc.vpc.id
  ingress {
    from_port = 22
    to_port = 22
    protocol = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
