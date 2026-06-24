output "lambda_function_arn" {
  description = "ARN of the reporter lambda function."
  value       = module.reporter_lambda.lambda_function_arn
}

output "lambda_function_name" {
  description = "Name of the reporter lambda function."
  value       = module.reporter_lambda.lambda_function_name
}
