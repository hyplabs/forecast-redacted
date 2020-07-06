variable "backend_image_healthcheck_path" {
  description = "Path to healthcheck endpoint for backend container instances"
}

variable "admin_image_healthcheck_path" {
  description = "Path to healthcheck endpoint for admin container instances"
}

##################
# LOAD BALANCING #
##################

resource "aws_lb" "load-balancer" {
  name = "load-balancer"
  subnets = aws_subnet.public-subnet.*.id
  security_groups = [aws_security_group.load-balancer-security-group.id]
}

# define a group of targets that the load balancer can send traffic to ("backend-service" has configuration that will add the backend container instances to this group)
resource "aws_lb_target_group" "load-balancer-target" {
  name = "load-balancer-target"
  port = var.backend_image_port
  protocol = "HTTP"
  target_type = "ip"
  vpc_id = aws_vpc.vpc.id
  health_check {
    path = var.backend_image_healthcheck_path
  }
  stickiness {  # stickiness is required to allow websocket connections to always be routed to the same machine
    type = "lb_cookie"
  }
  depends_on = [aws_lb.load-balancer]
}

# define a group of targets that the load balancer can send traffic to ("admin-service" has configuration that will add the admin container instances to this group)
resource "aws_lb_target_group" "admin-load-balancer-target" {
  name = "admin-load-balancer-target"
  port = var.admin_image_port
  protocol = "HTTP"
  target_type = "ip"
  vpc_id = aws_vpc.vpc.id
  health_check {
    path = var.admin_image_healthcheck_path
  }
  depends_on = [aws_lb.load-balancer]
}

# redirect all HTTP traffic that this load balancer receives to HTTPS
resource "aws_lb_listener" "load-balancer-http-listener" {
  load_balancer_arn = aws_lb.load-balancer.arn
  port = "80"
  protocol = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port = "443"
      protocol = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# forward all HTTPS traffic that this load balancer receives to the load balancer target group
resource "aws_lb_listener" "load-balancer-https-listener" {
  load_balancer_arn = aws_lb.load-balancer.arn
  port = "443"
  protocol = "HTTPS"
  certificate_arn = aws_acm_certificate_validation.https-certificate-validation.certificate_arn
  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.load-balancer-target.arn
  }
}

# forward all HTTPS traffic to the admin subdomain that this load balancer receives to the admin load balancer target group
resource "aws_lb_listener_rule" "admin-load-balancer-https-listener-rule" {
  listener_arn = aws_lb_listener.load-balancer-https-listener.arn
  action {
    type = "forward"
    target_group_arn = aws_lb_target_group.admin-load-balancer-target.arn
  }
  condition {
    host_header {
      values = ["admin.forecast.example.com"]
    }
  }
}

resource "aws_security_group" "load-balancer-security-group" {
  name = "load-balancer-security-group"
  description = "Allow inbound HTTP and HTTPS and all outbound traffic"
  vpc_id = aws_vpc.vpc.id
  ingress {
    from_port = 80
    to_port = 80
    protocol = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port = 443
    to_port = 443
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

####################################
# RATE LIMITING AND REGION LOCKING #
####################################

# NOTE: "aws_wafregional_*" is for firewalling AWS API Gateway and AWS ALB, while "aws_waf_*" is for firewalling AWS Cloudfront

# create AWS WAF rule that matches IP addresses that make more than 1000 requests per 5 minutes
resource "aws_wafregional_rate_based_rule" "rate-limit-rule" {
  name = "rate-limit-rule"
  metric_name = "ratelimitrule"
  rate_key = "IP"
  rate_limit = 1000  # 1000 requests per five minutes
}

# create AWS WAF rule that matches IP addresses that are not from Korea
resource "aws_wafregional_rule" "region-lock-rule" {
  name = "region-lock-rule"
  metric_name = "regionlockrule"
  predicate {
    data_id = aws_wafregional_geo_match_set.region-lock-match-set.id
    negated = true
    type = "GeoMatch"
  }
  depends_on = [aws_wafregional_geo_match_set.region-lock-match-set]
}
resource "aws_wafregional_geo_match_set" "region-lock-match-set" {
  name = "region-lock-match-set"
  geo_match_constraint {
    type  = "Country"
    value = "KR"
  }
  geo_match_constraint {  # TODO: for development purposes, allow Canada
    type  = "Country"
    value = "CA"
  }
  geo_match_constraint {  # TODO: for development purposes, allow Singapore
    type  = "Country"
    value = "SG"
  }
}

# create AWS WAF ACL that blocks any IP addresses that match the rate limit rule or the region lock rule
resource "aws_wafregional_web_acl" "firewall-acl" {
  name = "rate-limit-acl"
  metric_name = "ratelimitacl"
  default_action {
    type = "ALLOW"
  }
  rule {
    action {
      type = "BLOCK"
    }
    priority = 1
    rule_id = aws_wafregional_rate_based_rule.rate-limit-rule.id
    type = "RATE_BASED"
  }
  rule {
    action {
      type = "BLOCK"
    }
    priority = 2
    rule_id = aws_wafregional_rule.region-lock-rule.id
  }
  depends_on = [aws_wafregional_rate_based_rule.rate-limit-rule, aws_wafregional_rule.region-lock-rule]
}
resource "aws_wafregional_web_acl_association" "attach-firewall-to-load-balancer" {
  resource_arn = aws_lb.load-balancer.arn
  web_acl_id = aws_wafregional_web_acl.firewall-acl.id
}
