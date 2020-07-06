resource "aws_elasticache_replication_group" "redis" {
  replication_group_id = "redis"
  replication_group_description = "Redis cluster-mode cache"
  node_type = "cache.t2.small"
  automatic_failover_enabled = true
  subnet_group_name = aws_elasticache_subnet_group.redis-subnet-group.name
  security_group_ids = [aws_security_group.redis-security-group.id]

  cluster_mode {
    replicas_per_node_group = 1
    num_node_groups = 3
  }
}

resource "aws_elasticache_subnet_group" "redis-subnet-group" {
  name = "redis-subnet-group"
  subnet_ids = aws_subnet.private-subnet.*.id
}

resource "aws_security_group" "redis-security-group" {
  name = "redis-security-group"
  description = "Allow all outbound traffic and inbound Redis traffic"
  vpc_id = aws_vpc.vpc.id
  ingress {
    from_port = 6379
    to_port = 6379
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

output "redis-url" {
  value = "redis+cluster://${aws_elasticache_replication_group.redis.configuration_endpoint_address}:6379"
}
