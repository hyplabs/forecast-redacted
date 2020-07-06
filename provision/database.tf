variable "db_master_password" {
  description = "DB master password"
}

resource "aws_rds_cluster" "database" {
  cluster_identifier = "database"
  database_name = "forecast"
  deletion_protection = true
  master_password = var.db_master_password
  master_username = "postgres"
  engine = "aurora-postgresql"
  engine_mode = "serverless"
  backup_retention_period = 20
  scaling_configuration {
    auto_pause = false
    max_capacity = 384
    min_capacity = 2
  }
  db_subnet_group_name = aws_db_subnet_group.database-subnet-group.id
  vpc_security_group_ids = [aws_security_group.database-security-group.id]
}

resource "aws_db_subnet_group" "database-subnet-group" {
  name = "database-subnet-group"
  subnet_ids = aws_subnet.private-subnet.*.id
}

resource "aws_security_group" "database-security-group" {
  name = "database-security-group"
  description = "Allow all outbound traffic and inbound PostgreSQL traffic"
  vpc_id = aws_vpc.vpc.id
  ingress {
    from_port = 5432
    to_port = 5432
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

output "database-url" {
  value = "postgresql://postgres:${var.db_master_password}@${aws_rds_cluster.database.endpoint}/${aws_rds_cluster.database.database_name}"
}
