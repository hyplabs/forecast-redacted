# set up autoscaler to scale the backend service's desired instances count up or down based on CPU usage measured in Cloudwatch
resource "aws_appautoscaling_target" "backend-autoscaling-target" {
  service_namespace = "ecs"
  resource_id = "service/${aws_ecs_cluster.fargate-cluster.name}/${aws_ecs_service.backend-service.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity = 1

  # the max_capacity value is mostly limited by DB connections
  # if the Aurora Serverless DB is scaled all the way down to 2 ACUs, then max_connections will be 270
  # in models.py we've configured up to 20 DB connections at a time, so with 10 instances that's 200 connections
  # to be on the safe side, we'll leave 70 connections for admins, price updater, and devs to be able to connect to the DB
  max_capacity = 10
}

# create autoscaling policies for changing the desired_count of backend-service
resource "aws_appautoscaling_policy" "autoscale-increment-backend-desired_count" {
  name = "autoscale-increment-backend-desired_count"
  service_namespace = "ecs"
  resource_id = "service/${aws_ecs_cluster.fargate-cluster.name}/${aws_ecs_service.backend-service.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  step_scaling_policy_configuration {
    adjustment_type = "ChangeInCapacity"
    cooldown = 60
    metric_aggregation_type = "Maximum"
    step_adjustment {
      metric_interval_lower_bound = 0
      scaling_adjustment = 1
    }
  }
  depends_on = [aws_appautoscaling_target.backend-autoscaling-target]
}
resource "aws_appautoscaling_policy" "autoscale-decrement-backend-desired_count" {
  name = "autoscale-decrement-backend-desired_count"
  service_namespace = "ecs"
  resource_id = "service/${aws_ecs_cluster.fargate-cluster.name}/${aws_ecs_service.backend-service.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  step_scaling_policy_configuration {
    adjustment_type = "ChangeInCapacity"
    cooldown = 60
    metric_aggregation_type = "Maximum"
    step_adjustment {
      metric_interval_upper_bound = 0
      scaling_adjustment = -1
    }
  }
  depends_on = [aws_appautoscaling_target.backend-autoscaling-target]
}

# set up Cloudwatch alarms that trigger the autoscaling policies, which in turn change the desired_count of backend-service
resource "aws_cloudwatch_metric_alarm" "backend-cpu-usage-too-high-alarm" {
  alarm_name = "backend-cpu-usage-too-high-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods = "2"
  metric_name = "CPUUtilization"  # TODO: memory utilization too
  namespace = "AWS/ECS"
  period = "60"
  statistic = "Average"
  threshold = "80"
  dimensions = {
    ClusterName = aws_ecs_cluster.fargate-cluster.name
    ServiceName = aws_ecs_service.backend-service.name
  }
  alarm_actions = [aws_appautoscaling_policy.autoscale-increment-backend-desired_count.arn]
}
resource "aws_cloudwatch_metric_alarm" "backend-cpu-usage-too-low-alarm" {
  alarm_name = "backend-cpu-usage-too-low-alarm"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods = "20"
  metric_name = "CPUUtilization"
  namespace = "AWS/ECS"
  period = "60"
  statistic = "Average"
  threshold = "10"
  dimensions = {
    ClusterName = aws_ecs_cluster.fargate-cluster.name
    ServiceName = aws_ecs_service.backend-service.name
  }
  alarm_actions = [aws_appautoscaling_policy.autoscale-decrement-backend-desired_count.arn]
}