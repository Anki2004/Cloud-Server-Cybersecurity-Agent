variable "aws_region" {
  description = "AWS region for the deployment."
  type        = string
  default     = "ap-south-1"
}

variable "project_name" {
  description = "Prefix used for resource names and tags."
  type        = string
  default     = "multi-agent-cybersec"
}

variable "instance_type" {
  description = "EC2 instance type for the API host."
  type        = string
  default     = "t3.medium"
}

variable "root_volume_size" {
  description = "Root EBS volume size in GiB."
  type        = number
  default     = 20
}

variable "repo_url" {
  description = "Git URL that the EC2 instance will clone during bootstrap."
  type        = string
}

variable "repo_branch" {
  description = "Git branch to deploy."
  type        = string
  default     = "main"
}

variable "groq_api_key" {
  description = "Groq API key passed into the running container."
  type        = string
  sensitive   = true
}

variable "exa_api_key" {
  description = "Optional Exa API key passed into the running container."
  type        = string
  default     = ""
  sensitive   = true
}

variable "model_name" {
  description = "Model name exposed to the application."
  type        = string
  default     = "llama3-70b-8192"
}

variable "api_port" {
  description = "External API port exposed on the EC2 instance."
  type        = number
  default     = 8000
}

variable "allowed_api_cidrs" {
  description = "CIDR blocks allowed to reach the FastAPI service."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed to SSH to the instance. Leave empty to disable SSH ingress."
  type        = list(string)
  default     = []
}

variable "key_name" {
  description = "Optional EC2 key pair name for SSH access."
  type        = string
  default     = ""
}
