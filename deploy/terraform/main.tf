terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" { type = string }
variable "image" { type = string }
variable "service_name" { type = string  default = "odin-webhook-sentinel" }
variable "cpu" { type = number default = 256 }
variable "memory" { type = number default = 512 }
variable "desired_count" { type = number default = 1 }
variable "port" { type = number default = 8787 }
variable "enable_alb" { type = bool default = true }
variable "alb_listener_port" { type = number default = 80 }
variable "autoscale_min" { type = number default = 1 }
variable "autoscale_max" { type = number default = 3 }
variable "cpu_scale_target" { type = number default = 60 } # percent
variable "memory_scale_target" { type = number default = 70 } # percent

# Simplified ECS Fargate task + service (no ALB/Ingress security for brevity)
resource "aws_ecs_cluster" "this" {
  name = var.service_name
}

resource "aws_iam_role" "task_exec" {
  name               = "${var.service_name}-task-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
}

data "aws_iam_policy_document" "ecs_task_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals { type = "Service" identifiers = ["ecs-tasks.amazonaws.com"] }
  }
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.service_name
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.task_exec.arn
  container_definitions = jsonencode([
    {
      name      = var.service_name
      image     = var.image
      essential = true
      portMappings = [{ containerPort = var.port, hostPort = var.port }]
      environment = [] # fill via TF vars or secrets manager integration expansion
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = "/ecs/${var.service_name}"
          awslogs-region        = var.region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${var.service_name}"
  retention_in_days = 14
}

resource "aws_ecs_service" "this" {
  name            = var.service_name
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"
  depends_on = [aws_cloudwatch_log_group.this]
  network_configuration {
    subnets         = var.subnets
    security_groups = var.security_groups
    assign_public_ip = true
  }
  dynamic "load_balancer" {
    for_each = var.enable_alb ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.app[0].arn
      container_name   = var.service_name
      container_port   = var.port
    }
  }
}

variable "subnets" { type = list(string) }
variable "security_groups" { type = list(string) }

# Optional ALB + autoscaling
resource "aws_lb" "app" {
  count               = var.enable_alb ? 1 : 0
  name                = "${var.service_name}-alb"
  load_balancer_type  = "application"
  subnets             = var.subnets
  security_groups     = var.security_groups
}

resource "aws_lb_target_group" "app" {
  count    = var.enable_alb ? 1 : 0
  name     = "${var.service_name}-tg"
  port     = var.port
  protocol = "HTTP"
  vpc_id   = var.vpc_id
  target_type = "ip"
  health_check {
    path                = "/healthz"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
  }
}

resource "aws_lb_listener" "app" {
  count             = var.enable_alb ? 1 : 0
  load_balancer_arn = aws_lb.app[0].arn
  port              = var.alb_listener_port
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app[0].arn
  }
}

variable "vpc_id" { type = string }

resource "aws_appautoscaling_target" "ecs" {
  max_capacity       = var.autoscale_max
  min_capacity       = var.autoscale_min
  resource_id        = "service/${aws_ecs_cluster.this.name}/${aws_ecs_service.this.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${var.service_name}-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs.service_namespace
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = var.cpu_scale_target
    scale_in_cooldown  = 60
    scale_out_cooldown = 60
  }
}

resource "aws_appautoscaling_policy" "memory" {
  name               = "${var.service_name}-memory"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs.service_namespace
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    target_value       = var.memory_scale_target
    scale_in_cooldown  = 60
    scale_out_cooldown = 60
  }
}
