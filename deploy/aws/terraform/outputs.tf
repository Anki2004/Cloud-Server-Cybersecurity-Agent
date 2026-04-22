output "instance_public_ip" {
  description = "Public IP address of the deployed EC2 instance."
  value       = aws_instance.app.public_ip
}

output "instance_public_dns" {
  description = "Public DNS name of the deployed EC2 instance."
  value       = aws_instance.app.public_dns
}

output "api_base_url" {
  description = "Base URL for the FastAPI service."
  value       = "http://${aws_instance.app.public_dns}:${var.api_port}"
}

output "healthcheck_url" {
  description = "Health endpoint for the deployed API."
  value       = "http://${aws_instance.app.public_dns}:${var.api_port}/health"
}
