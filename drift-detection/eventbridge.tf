resource "aws_cloudwatch_event_rule" "cron" {
  name        = "${var.name}-cron"
  description = "Trigger ${var.name} on a schedule"

  schedule_expression = var.schedule_expression

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "cron" {
  arn       = module.reporter_lambda.lambda_function_arn
  rule      = aws_cloudwatch_event_rule.cron.name
  target_id = "${module.reporter_lambda.lambda_function_name}-cron"
}
