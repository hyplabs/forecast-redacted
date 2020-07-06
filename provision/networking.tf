# The VPC contains a public subnet and a private subnet.
# The public subnet contains an internet gateway (which is a routing target that goes to the internet), and we route all non-local traffic in the public subnet to the internet gateway, where it then goes to the internet.
# The public subnet also contains a NAT gateway (which is a routing target for other subnets to get traffic into the public subnet).
# The private subnet routes all non-local traffic to the NAT gateway, where it then goes into the public subnet, where it then goes to the internet. The reason for this is that NAT can protect the private subnet from traffic originating from the internet.

variable "num_availability_zones" {
  description = "Number of availability zones to use, must be at least 2"
}

# get a list of all availability zones in the current region
data "aws_availability_zones" "availability-zones" {}

# create VPC for everything to run inside
resource "aws_vpc" "vpc" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "vpc"
  }
}

#################
# PUBLIC SUBNET #
#################

# create public subnet in the VPC with a routing table that allows things in the public subnet to access the internet via the internet gateway
resource "aws_subnet" "public-subnet" {
  count = var.num_availability_zones
  vpc_id = aws_vpc.vpc.id
  cidr_block = cidrsubnet(aws_vpc.vpc.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.availability-zones.names[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name = "public-subnet"
  }
}
resource "aws_route_table" "public-routing-table" {
  count = var.num_availability_zones
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.internet-gateway.id
  }
  tags = {
    Name = "public-routing-table"
  }
}
resource "aws_route_table_association" "public-subnet-routing-table" {
  count = var.num_availability_zones
  subnet_id = element(aws_subnet.public-subnet.*.id, count.index)
  route_table_id = element(aws_route_table.public-routing-table.*.id, count.index)
}

# create an internet gateway in the public subnet and route any non-local traffic in the public subnet to the internet gateway, allowing non-local traffic to reach the internet
resource "aws_internet_gateway" "internet-gateway" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "internet-gateway"
  }
}

# create NAT gateway in the public subnet (the private subnet routes to this gateway, allowing the private subnet to connect to the internet while being protected from traffic from the internet by the NAT)
# note that we need one NAT gateway per availability zone, whereas we only need one internet gateway per VPC
resource "aws_eip" "nat-gateway-ip-address" {
  vpc = true
  count = var.num_availability_zones
  depends_on = [aws_internet_gateway.internet-gateway]
  tags = {
    Name = "nat-gateway-ip-address"
  }
}
resource "aws_nat_gateway" "nat-gateway" {
  count = var.num_availability_zones
  subnet_id = element(aws_subnet.public-subnet.*.id, count.index)
  allocation_id = element(aws_eip.nat-gateway-ip-address.*.id, count.index)
  tags = {
    Name = "nat-gateway"
  }
}

##################
# PRIVATE SUBNET #
##################

# create private subnet in the VPC with a routing table that allows things in the private subnet to access the public subnet (and by extension, the internet) via the NAT gateway
resource "aws_subnet" "private-subnet" {
  count = var.num_availability_zones
  vpc_id = aws_vpc.vpc.id
  cidr_block = cidrsubnet(aws_vpc.vpc.cidr_block, 8, var.num_availability_zones + count.index)
  availability_zone = data.aws_availability_zones.availability-zones.names[count.index]
  tags = {
    Name = "private-subnet"
  }
}
resource "aws_route_table" "private-routing-table" {
  count = var.num_availability_zones
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = element(aws_nat_gateway.nat-gateway.*.id, count.index)
  }
  tags = {
    Name = "private-routing-table"
  }
}
resource "aws_route_table_association" "private-subnet-routing-table" {
  count = var.num_availability_zones
  subnet_id = element(aws_subnet.private-subnet.*.id, count.index)
  route_table_id = element(aws_route_table.private-routing-table.*.id, count.index)
}

###########
# OUTPUTS #
###########

output "vpc-id" {
  value = aws_vpc.vpc.id
}
