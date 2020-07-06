variable "backend_image_port" {
  description = "Port that backend container instances should receive traffic on"
}

variable "backend_cpu" {
  description = "vCPUs to assign to backend container instances, in increments of 1/1024 vCPUs"
}

variable "backend_memory" {
  description = "RAM to assign to backend container instances, in MB"
}

variable "admin_image_port" {
  description = "Port that admin container instances should receive traffic on"
}

variable "TWILIO_ACCOUNT_SID" {
  description = "Twilio account ID"
}

variable "TWILIO_FROM_PHONE_NUMBER" {
  description = "Phone number that Twilio SMS messages will come from"
}

variable "SENDGRID_FROM_EMAIL" {
  description = "Email address that SendGrid emails will come from"
}

variable "FRONTEND_URL" {
  description = "URL of main website"
}

variable "ADMIN_URL" {
  description = "URL of admin website"
}

#######
# ECS #
#######

resource "aws_ecs_cluster" "fargate-cluster" {
   name = "fargate-cluster"
   setting {
     name = "containerInsights"
     value = "enabled"
   }
}

# create an AWS IAM execution role with a policy attached that allows ECS tasks to execute
data "aws_iam_policy_document" "allow-ecs-tasks-to-assume-fargate-iam-role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}
resource "aws_iam_role" "fargate-iam-role" {
  name = "fargate-iam-role"
  assume_role_policy = data.aws_iam_policy_document.allow-ecs-tasks-to-assume-fargate-iam-role.json
}
resource "aws_iam_role_policy_attachment" "fargate-iam-role-task-execution-policy" {
  role = aws_iam_role.fargate-iam-role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy" # hardcoded ARN, but it's an AWS-managed policy so shouldn't change anytime soon
}
resource "aws_iam_role_policy_attachment" "fargate-iam-role-secrets-policy" {
  role = aws_iam_role.fargate-iam-role.name
  policy_arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite" # hardcoded ARN, but it's an AWS-managed policy so shouldn't change anytime soon
}

# create container repository to store our container images
resource "aws_ecr_repository" "backend-repository" {
  name = "backend-repository"
}

# backend service
resource "aws_ecs_service" "backend-service" {
  name = "backend-service"
  cluster = aws_ecs_cluster.fargate-cluster.id
  launch_type = "FARGATE"
  task_definition = aws_ecs_task_definition.backend-task-definition.arn
  desired_count = 1  # initial value, will be adjusted by autoscaler afterwards
  network_configuration {
    assign_public_ip = false
    security_groups = [aws_security_group.backend-security-group.id]
    subnets = aws_subnet.private-subnet.*.id
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.load-balancer-target.arn
    container_name = "backend-container"
    container_port = var.backend_image_port
  }
  depends_on = [aws_lb_listener.load-balancer-http-listener, aws_lb_listener.load-balancer-https-listener, aws_iam_role_policy_attachment.fargate-iam-role-task-execution-policy]
  lifecycle {
    ignore_changes = [desired_count]  # the autoscaler will adjust this field, so ignore any discrepencies in this value
  }
}
resource "aws_ecs_task_definition" "backend-task-definition" {
  family = "backend-task-definition"
  execution_role_arn = aws_iam_role.fargate-iam-role.arn
  requires_compatibilities = ["FARGATE"]
  network_mode = "awsvpc"
  cpu = var.backend_cpu
  memory = var.backend_memory
  container_definitions = <<EOF
    [
      {
        "name": "backend-container",
        "image": "${aws_ecr_repository.backend-repository.repository_url}",
        "portMappings": [{"containerPort": ${var.backend_image_port}}],
        "environment": [
          {"name": "TWILIO_ACCOUNT_SID", "value": "${var.TWILIO_ACCOUNT_SID}"},
          {"name": "TWILIO_FROM_PHONE_NUMBER", "value": "${var.TWILIO_FROM_PHONE_NUMBER}"},
          {"name": "SENDGRID_FROM_EMAIL", "value": "${var.SENDGRID_FROM_EMAIL}"},
          {"name": "FRONTEND_URL", "value": "${var.FRONTEND_URL}"}
        ],
        "ulimits": [{"name": "nofile", "softLimit": 32768, "hardLimit": 65536}],
        "secrets": [
          {"name": "FLASK_SECRET_KEY", "valueFrom": "${aws_secretsmanager_secret.secret-FLASK_SECRET_KEY.arn}"},
          {"name": "TWILIO_AUTH_TOKEN", "valueFrom": "${aws_secretsmanager_secret.secret-TWILIO_AUTH_TOKEN.arn}"},
          {"name": "SENDGRID_API_KEY", "valueFrom": "${aws_secretsmanager_secret.secret-SENDGRID_API_KEY.arn}"},
          {"name": "DATABASE_URL", "valueFrom": "${aws_secretsmanager_secret.secret-DATABASE_URL.arn}"},
          {"name": "REDIS_URL", "valueFrom": "${aws_secretsmanager_secret.secret-REDIS_URL.arn}"}
        ],
        "logConfiguration": {
          "logDriver": "awslogs",
          "options": {
            "awslogs-region": "${var.aws_region}",
            "awslogs-group": "/ecs/backend",
            "awslogs-stream-prefix": "ecs"
          }
        }
      }
    ]
  EOF
  depends_on = [aws_rds_cluster.database, aws_elasticache_replication_group.redis]
}
resource "aws_security_group" "backend-security-group" {
  name = "backend-security-group"
  description = "Allow all outbound traffic and inbound HTTP traffic on backend container port"
  vpc_id = aws_vpc.vpc.id
  ingress {
    from_port = var.backend_image_port
    to_port = var.backend_image_port
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

# price update service
resource "aws_ecs_service" "price-updater-service" {
  name = "price-updater-service"
  cluster = aws_ecs_cluster.fargate-cluster.id
  launch_type = "FARGATE"
  task_definition = aws_ecs_task_definition.price-updater-task-definition.arn
  desired_count = 1
  network_configuration {
    assign_public_ip = false
    security_groups = [aws_security_group.price-updater-security-group.id]
    subnets = aws_subnet.private-subnet.*.id
  }
  depends_on = [aws_iam_role_policy_attachment.fargate-iam-role-task-execution-policy]
}
resource "aws_ecs_task_definition" "price-updater-task-definition" {
  family = "price-updater-task-definition"
  execution_role_arn = aws_iam_role.fargate-iam-role.arn
  requires_compatibilities = ["FARGATE"]
  network_mode = "awsvpc"
  cpu = 1024
  memory = 2048
  container_definitions = <<EOF
    [
      {
        "name": "price-updater-container",
        "image": "${aws_ecr_repository.backend-repository.repository_url}",
        "command": ["bash", "-c", "while true; do python3 price_updater.py; done"],
        "secrets": [
          {"name": "DATABASE_URL", "valueFrom": "${aws_secretsmanager_secret.secret-DATABASE_URL.arn}"},
          {"name": "REDIS_URL", "valueFrom": "${aws_secretsmanager_secret.secret-REDIS_URL.arn}"}
        ],
        "logConfiguration": {
          "logDriver": "awslogs",
          "options": {
            "awslogs-region": "${var.aws_region}",
            "awslogs-group": "/ecs/price_updater",
            "awslogs-stream-prefix": "ecs"
          }
        }
      }
    ]
  EOF
  depends_on = [aws_rds_cluster.database, aws_elasticache_replication_group.redis]
}
resource "aws_security_group" "price-updater-security-group" {
  name = "price-updater-security-group"
  description = "Allow all outbound traffic and no inbound traffic"
  vpc_id = aws_vpc.vpc.id
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# admin service
resource "aws_ecs_service" "admin-service" {
  name = "admin-service"
  cluster = aws_ecs_cluster.fargate-cluster.id
  launch_type = "FARGATE"
  task_definition = aws_ecs_task_definition.admin-task-definition.arn
  desired_count = 1
  network_configuration {
    assign_public_ip = false
    security_groups = [aws_security_group.admin-security-group.id]
    subnets = aws_subnet.private-subnet.*.id
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.admin-load-balancer-target.arn
    container_name = "admin-container"
    container_port = var.admin_image_port
  }
  depends_on = [aws_iam_role_policy_attachment.fargate-iam-role-task-execution-policy]
}
resource "aws_ecs_task_definition" "admin-task-definition" {  # TODO: re-enable webauthn when we go live
  family = "admin-task-definition"
  execution_role_arn = aws_iam_role.fargate-iam-role.arn
  requires_compatibilities = ["FARGATE"]
  network_mode = "awsvpc"
  cpu = 1024
  memory = 2048
  container_definitions = <<EOF
    [
      {
        "name": "admin-container",
        "image": "${aws_ecr_repository.backend-repository.repository_url}",
        "portMappings": [{"containerPort": ${var.admin_image_port}}],
        "workingDirectory": "/app/backend/admin",
        "command": ["gunicorn", "admin:app", "--pythonpath", "..", "--bind", "0.0.0.0:${var.admin_image_port}", "--access-logfile", "-"],
        "environment": [
          {"name": "ADMIN_URL", "value": "${var.ADMIN_URL}"}
        ],
        "secrets": [
          {"name": "DATABASE_URL", "valueFrom": "${aws_secretsmanager_secret.secret-DATABASE_URL.arn}"},
          {"name": "REDIS_URL", "valueFrom": "${aws_secretsmanager_secret.secret-REDIS_URL.arn}"},
          {"name": "ADMIN_FLASK_SECRET_KEY", "valueFrom": "${aws_secretsmanager_secret.secret-ADMIN_FLASK_SECRET_KEY.arn}"},
          {"name": "ADMIN_USERS", "valueFrom": "${aws_secretsmanager_secret.secret-ADMIN_USERS.arn}"}
        ],
        "logConfiguration": {
          "logDriver": "awslogs",
          "options": {
            "awslogs-region": "${var.aws_region}",
            "awslogs-group": "/ecs/admin",
            "awslogs-stream-prefix": "ecs"
          }
        }
      }
    ]
  EOF
  depends_on = [aws_rds_cluster.database, aws_elasticache_replication_group.redis]
}
resource "aws_security_group" "admin-security-group" {
  name = "admin-security-group"
  description = "Allow all outbound traffic and inbound HTTP traffic on admin container port"
  vpc_id = aws_vpc.vpc.id
  ingress {
    from_port = var.admin_image_port
    to_port = var.admin_image_port
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

###########
# OUTPUTS #
###########

data "aws_caller_identity" "current" {}

output "backend-repository-url" {
  value = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${aws_ecr_repository.backend-repository.name}"
}
