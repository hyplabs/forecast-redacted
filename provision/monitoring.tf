# logs are written here by container instances defined by "backend-task-definition"
resource "aws_cloudwatch_log_group" "backend-log-group" {
  name = "/ecs/backend"
}

# logs are written here by container instances defined by "price-updater-task-definition"
resource "aws_cloudwatch_log_group" "price-updater-log-group" {
  name = "/ecs/price_updater"
}

# logs are written here by container instances defined by "admin-task-definition"
resource "aws_cloudwatch_log_group" "admin-log-group" {
  name = "/ecs/admin"
}

resource "aws_cloudwatch_dashboard" "main-dashboard" {
  dashboard_name = "Main"
  dashboard_body = <<EOF
{
    "widgets": [
    ]
}
 EOF
}
