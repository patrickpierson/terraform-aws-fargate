terraform {
  required_version = "~> 0.13"
}

variable "name" {}

module "fargate" {
  source = "../"

  vpc_create_nat = false
  environment = "localtest"
    default_action = "local.dev"
  name = var.name

  vpc_cidr = "10.1.0.0/16"

  services = {
    api = {
      task_definition = "api.json"
      container_port  = 3000
      cpu             = "256"
      memory          = "512"
      replicas        = 1
      registry_retention_count = 15
      logs_retention_days      = 14
      health_check_interval = 30
      health_check_path     = "/ping"
      # acm_certificate_arn = "arn:aws:acm:us-east-1:${data.aws_caller_identity.current.account_id}:certificate/0713fcea-afdb-4d36-9804-f0ec4a221857"
      auto_scaling_max_replicas = 50
      auto_scaling_requests_per_target = 4000
      host = "api.local.dev"
      # task_role_arn = aws_iam_role.api_task_role.arn
    }
  }
}
