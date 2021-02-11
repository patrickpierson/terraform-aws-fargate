# Main Module file

# VPC CONFIGURATION

locals {
  vpc_id = ! var.vpc_create ? var.vpc_external_id : module.vpc.vpc_id

  vpc_public_subnets = (
    length(var.vpc_public_subnets) > 0 || ! var.vpc_create ?
    var.vpc_public_subnets :
    list(
      cidrsubnet(var.vpc_cidr, 8, 1),
      cidrsubnet(var.vpc_cidr, 8, 2),
      cidrsubnet(var.vpc_cidr, 8, 3)
    )
  )

  vpc_private_subnets = (
    length(var.vpc_private_subnets) > 0 || ! var.vpc_create ?
    var.vpc_private_subnets :
    list(
      cidrsubnet(var.vpc_cidr, 8, 101),
      cidrsubnet(var.vpc_cidr, 8, 102),
      cidrsubnet(var.vpc_cidr, 8, 103)
    )
  )

  vpc_private_subnets_ids = ! var.vpc_create ? var.vpc_external_private_subnets_ids : module.vpc.private_subnets

  vpc_public_subnets_ids = ! var.vpc_create ? var.vpc_external_public_subnets_ids : module.vpc.public_subnets

  default_action = var.default_action

  services       = [for k, v in var.services : merge({ "name" : k }, v)]
  services_count = length(var.services)

}

data "aws_availability_zones" "this" {}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "2.70.0"

  create_vpc = var.vpc_create

  name = "${var.name}-${var.environment}-vpc"
  cidr = var.vpc_cidr
  azs  = data.aws_availability_zones.this.names

  public_subnets  = local.vpc_public_subnets
  private_subnets = local.vpc_private_subnets

  # NAT gateway for private subnets
  enable_nat_gateway = var.vpc_create_nat
  single_nat_gateway = var.vpc_create_nat

  # Every instance deployed within the VPC will get a hostname
  enable_dns_hostnames = true

  # Every instance will have a dedicated internal endpoint to communicate with S3
  enable_s3_endpoint = true
}

# ECS CLUSTER

resource "aws_ecs_cluster" "this" {
  name = "${var.name}-${var.environment}-cluster"
  capacity_providers = ["FARGATE_SPOT", "FARGATE"]
  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
  }
}

# ECS TASKS DEFINITIONS

resource "aws_iam_role" "tasks_execution" {
  name               = "${var.name}-${var.environment}-task-execution-role"
  assume_role_policy = file("${path.module}/policies/ecs-task-execution-role.json")
}

resource "aws_iam_policy" "tasks_execution" {
  name = "${var.name}-${var.environment}-task-execution-policy"

  policy = file("${path.module}/policies/ecs-task-execution-role-policy.json")
}

resource "aws_iam_role_policy_attachment" "tasks_execution" {
  role       = aws_iam_role.tasks_execution.name
  policy_arn = aws_iam_policy.tasks_execution.arn
}

data "template_file" "tasks_execution_ssm" {
  count = var.ssm_allowed_parameters != "" ? 1 : 0

  template = file("${path.module}/policies/ecs-task-execution-role-policy-ssm.json")

  vars = {
    ssm_parameters_arn = replace(var.ssm_allowed_parameters, "arn:aws:ssm", "") == var.ssm_allowed_parameters ? "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter${var.ssm_allowed_parameters}" : var.ssm_allowed_parameters
  }
}

resource "aws_iam_policy" "tasks_execution_ssm" {
  count = var.ssm_allowed_parameters != "" ? 1 : 0

  name = "${var.name}-${var.environment}-task-execution-ssm-policy"

  policy = data.template_file.tasks_execution_ssm[count.index].rendered
}

resource "aws_iam_role_policy_attachment" "tasks_execution_ssm" {
  count = var.ssm_allowed_parameters != "" ? 1 : 0

  role       = aws_iam_role.tasks_execution.name
  policy_arn = aws_iam_policy.tasks_execution_ssm[count.index].arn
}

data "template_file" "tasks" {
  count = local.services_count > 0 ? local.services_count : 0

  template = file("${path.cwd}/${local.services[count.index].task_definition}")

  vars = {
    container_name = local.services[count.index].name
    container_port = local.services[count.index].container_port
    repository_url = ""
    account_id     = data.aws_caller_identity.current.account_id
    log_group      = aws_cloudwatch_log_group.this[count.index].name
    region         = var.region != "" ? var.region : data.aws_region.current.name
  }
}

resource "aws_ecs_task_definition" "this" {
  count = local.services_count > 0 ? local.services_count : 0

  family                   = "${var.name}-${var.environment}-${local.services[count.index].name}"
  container_definitions    = data.template_file.tasks[count.index].rendered
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = local.services[count.index].cpu
  memory                   = local.services[count.index].memory
  execution_role_arn       = aws_iam_role.tasks_execution.arn
  task_role_arn            = lookup(local.services[count.index], "task_role_arn", null)
}

data "aws_ecs_task_definition" "this" {
  count = local.services_count > 0 ? local.services_count : 0

  task_definition = element(aws_ecs_task_definition.this[*].family, count.index)

  # This avoid fetching an unexisting task definition before its creation
  depends_on = [aws_ecs_task_definition.this]
}

resource "aws_cloudwatch_log_group" "this" {
  count = local.services_count > 0 ? local.services_count : 0

  name = "/ecs/${var.environment}-${local.services[count.index].name}"

  retention_in_days = lookup(local.services[count.index], "logs_retention_days", var.cloudwatch_logs_default_retention_days)
}

# SECURITY GROUPS

resource "aws_security_group" "web" {
  vpc_id = local.vpc_id
  name   = "${var.name}-${var.environment}-web-sg"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "services" {
  count = local.services_count > 0 ? local.services_count : 0

  vpc_id = local.vpc_id
  #name   = "${var.name}-${local.services[count.index].name}-${var.environment}-services-sg"

  ingress {
    from_port       = local.services[count.index].container_port
    to_port         = local.services[count.index].container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Cross-service Security Groups
resource "aws_security_group" "services_dynamic" {
  count = local.services_count > 0 ? local.services_count : 0

  vpc_id = local.vpc_id
  name   = "${var.name}-${local.services[count.index].name}-${var.environment}-services-sg-dynamic"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # dynamic "ingress" {
  #  for_each = [for k, v in var.services : k
  #    if k != local.services[count.index].name &&
  #  contains(lookup(local.services[count.index], "allow_connections_from", []), k)]
  
  #  content {
  #    from_port = local.services[count.index].container_port
  #    to_port   = local.services[count.index].container_port
  #    protocol  = "tcp"
  #    security_groups = [for s in aws_security_group.services : s.id
  #    if lookup(s, "name", "") == "${var.name}-${ingress.value}-${var.environment}-services-sg"]
  #  }
  # }
}

# ALBs

resource "random_id" "target_group_sufix" {
  count = local.services_count > 0 ? local.services_count : 0

  keepers = {
    container_port = local.services[count.index].container_port
  }

  byte_length = 2
}

resource "aws_lb_target_group" "this" {
  count = local.services_count > 0 ? local.services_count : 0

  name        = "${var.name}-${var.environment}-${local.services[count.index].name}-${random_id.target_group_sufix[count.index].hex}"
  port        = random_id.target_group_sufix[count.index].keepers.container_port
  protocol    = "HTTP"
  vpc_id      = local.vpc_id
  target_type = "ip"

  health_check {
    interval            = lookup(local.services[count.index], "health_check_interval", var.alb_default_health_check_interval)
    path                = lookup(local.services[count.index], "health_check_path", var.alb_default_health_check_path)
    healthy_threshold   = 3
    unhealthy_threshold = 3
    matcher             = "200-299"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb" "this" {
  name            = "${var.name}-${var.environment}-alb"
  subnets         = slice(local.vpc_public_subnets_ids, 0, min(length(data.aws_availability_zones.this.names), length(local.vpc_public_subnets_ids)))
  security_groups = [aws_security_group.web.id]
  depends_on      = [aws_s3_bucket_policy.this]
  access_logs {
    bucket  = aws_s3_bucket.this.id
    enabled = true
  }
}

resource "aws_lb_listener" "this" {
  load_balancer_arn = aws_lb.this.arn
  port              = lookup(local.services[0], "acm_certificate_arn", "") != "" ? 443 : 80
  protocol          = lookup(local.services[0], "acm_certificate_arn", "") != "" ? "HTTPS" : "HTTP"
  ssl_policy        = lookup(local.services[0], "acm_certificate_arn", "") != "" ? "ELBSecurityPolicy-FS-2018-06" : null
  certificate_arn   = lookup(local.services[0], "acm_certificate_arn", null)
  depends_on        = [aws_lb_target_group.this]

  default_action {
    type = "redirect"

    redirect {
        host        = local.default_action
        path        = "/#{path}"
        port        = "443"
        protocol    = "HTTPS"
        query       = "#{query}"
        status_code = "HTTP_301"
    }
  }
}
 
resource "aws_lb_listener" "this80" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"
  depends_on        = [aws_lb_listener.this]

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener_rule" "host_based_routing" {
  count = local.services_count > 0 ? local.services_count : 0
  listener_arn = aws_lb_listener.this.arn
  priority     = 100 - count.index

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this[count.index].arn
  }

  condition {
    host_header {
      values = [local.services[count.index].host]
    }
  }
}

# ECS SERVICES

resource "aws_ecs_service" "this" {
  count = local.services_count > 0 ? local.services_count : 0

  name          = local.services[count.index].name
  cluster       = aws_ecs_cluster.this.name
  desired_count = local.services[count.index].replicas
  launch_type   = "FARGATE"

  task_definition = "${aws_ecs_task_definition.this[count.index].family}:${max(
    aws_ecs_task_definition.this[count.index].revision,
    length(data.aws_ecs_task_definition.this) >= count.index ? data.aws_ecs_task_definition.this[count.index].revision : 1
  )}"

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  network_configuration {
    security_groups = [
      aws_security_group.services[count.index].id,
      aws_security_group.services_dynamic[count.index].id
    ]

    subnets          = var.vpc_create_nat ? local.vpc_private_subnets_ids : local.vpc_public_subnets_ids
    assign_public_ip = ! var.vpc_create_nat
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this[count.index].arn
    container_name   = local.services[count.index].name
    container_port   = local.services[count.index].container_port
  }

  depends_on = [aws_lb_target_group.this, aws_lb_listener.this]

  lifecycle {
    ignore_changes = [desired_count]
  }
}

resource "aws_iam_role" "autoscaling" {
  name               = "${var.name}-${var.environment}-appautoscaling-role"
  assume_role_policy = file("${path.module}/policies/appautoscaling-role.json")
}

resource "aws_iam_role_policy" "autoscaling" {
  name   = "${var.name}-${var.environment}-appautoscaling-policy"
  policy = file("${path.module}/policies/appautoscaling-role-policy.json")
  role   = aws_iam_role.autoscaling.id
}

resource "aws_appautoscaling_target" "this" {
  count = local.services_count > 0 ? local.services_count : 0

  max_capacity       = lookup(local.services[count.index], "auto_scaling_max_replicas", local.services[count.index].replicas)
  min_capacity       = local.services[count.index].replicas
  resource_id        = "service/${aws_ecs_cluster.this.name}/${local.services[count.index].name}"
  role_arn           = aws_iam_role.autoscaling.arn
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"

  depends_on = [aws_ecs_service.this]
}

resource "aws_appautoscaling_policy" "this" {
  count = local.services_count > 0 ? local.services_count : 0

  name               = "${local.services[count.index].name}-autoscaling-policy"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.this[count.index].resource_id
  scalable_dimension = aws_appautoscaling_target.this[count.index].scalable_dimension
  service_namespace  = aws_appautoscaling_target.this[count.index].service_namespace

  target_tracking_scaling_policy_configuration {
    target_value = lookup(local.services[count.index], "auto_scaling_requests_per_target", 10000)

    scale_in_cooldown  = 30
    scale_out_cooldown = 300

    predefined_metric_specification {
      predefined_metric_type = "ALBRequestCountPerTarget"
      resource_label = replace(aws_lb.this.id, "arn:aws:elasticloadbalancing:us-east-1:${data.aws_caller_identity.current.account_id}:loadbalancer/", "")/replace(aws_lb_target_group.this[count.index].id, "arn:aws:elasticloadbalancing:us-east-1:${data.aws_caller_identity.current.account_id}:", "")
    }
  }

  depends_on = [aws_appautoscaling_target.this]
}

# Bucket

resource "aws_s3_bucket" "this" {
  bucket        = "${var.name}-${var.environment}"
  acl           = "private"
  force_destroy = true

}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "AWSConsole-AccessLogs-Policy-1586912476128",
  "Statement": [
      {
          "Sid": "AWSConsoleStmt-1586912476128",
          "Effect": "Allow",
          "Principal": {
              "AWS": "arn:aws:iam::127311923021:root"
          },
          "Action": "s3:PutObject",
          "Resource": "arn:aws:s3:::${aws_s3_bucket.this.id}/AWSLogs/*/*"
      },
      {
          "Sid": "AWSLogDeliveryWrite",
          "Effect": "Allow",
          "Principal": {
              "Service": "delivery.logs.amazonaws.com"
          },
          "Action": "s3:PutObject",
          "Resource": "arn:aws:s3:::${aws_s3_bucket.this.id}/AWSLogs/*/*",
          "Condition": {
              "StringEquals": {
                  "s3:x-amz-acl": "bucket-owner-full-control"
              }
          }
      },
      {
          "Sid": "AWSLogDeliveryAclCheck",
          "Effect": "Allow",
          "Principal": {
              "Service": "delivery.logs.amazonaws.com"
          },
          "Action": "s3:GetBucketAcl",
          "Resource": "arn:aws:s3:::${aws_s3_bucket.this.id}"
      }
  ]
}
POLICY
}

### CLOUDWATCH BASIC DASHBOARD

data "template_file" "metric_dashboard" {
  count = local.services_count > 0 ? local.services_count : 0

  template = file("${path.module}/metrics/basic-dashboard.json")

  vars = {
    region         = var.region != "" ? var.region : data.aws_region.current.name
    alb_arn_suffix = aws_lb.this.arn_suffix
    cluster_name   = aws_ecs_cluster.this.name
    service_name   = local.services[count.index].name
  }
}

resource "aws_cloudwatch_dashboard" "this" {
  count = local.services_count > 0 ? local.services_count : 0

  dashboard_name = "${var.name}-${var.environment}-${local.services[count.index].name}-metrics-dashboard"

  dashboard_body = data.template_file.metric_dashboard[count.index].rendered
}
