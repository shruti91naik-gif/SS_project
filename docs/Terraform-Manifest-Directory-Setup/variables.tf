variable "region" {
  type        = string
  description = "AWS Region where the cloud resources will be provisioned."
  default     = ""
}
variable "organization_external_reference" {
  type        = string
  description = "Unique organization ID."
  default     = ""
}

variable "aws_assume_role_arn" {
  type        = string
  description = "ARN of the AWS IAM role to be assumed by Terraform to provision the required cloud resources."
  default     = ""
}

variable "vpc_cidr_range" {
  type        = string
  description = "The /20 VPC CIDR Range of the self hosted Decube Data Plane VPC. Do not specify the /20 as it is already hardcoded in the terraform manifest.This CIDR range must not overlap with eks_service_ip4_range and other peered VPCs."
  default     = ""
}

variable "eks_service_ip4_range" {
  type        = string
  description = "The /24 CIDR range for the Kubernetes service created in the AWS EKS cluster. Do not specify the /24 as it is already hardcoded in the terraform manifest. This CIDR range must not overlap with the vpc_cidr_range and other peered VPCs."
}

variable "eks_version" {
  type        = string
  description = "The self hosted Decube Data Plane AWS EKS cluster version"
  default     = "1.34"
}

variable "eks_kube_proxy_version" {
  type        = string
  description = "The self hosted Decube Data Plane AWS EKS cluster kube-proxy version"
  default     = "v1.34.0-eksbuild.2"
}

variable "eks_vpc_cni_version" {
  type        = string
  description = "The self hosted Decube Data Plane AWS EKS cluster vpc-cni version"
  default     = "v1.20.1-eksbuild.3"
}

variable "eks_coredns_version" {
  type        = string
  description = "The self hosted Decube Data Plane AWS EKS cluster coredns version"
  default     = "v1.12.3-eksbuild.1"
}

variable "eks_ebs_csi_driver_version" {
  type        = string
  description = "The self hosted Decube Data Plane AWS EKS cluster ebs-csi-driver version"
  default     = "v1.50.1-eksbuild.1"
}

variable "decube_registry" {
  type        = string
  description = "Decube private container registry host."
  default     = "registry.decube.io"
}

variable "decube_registry_username" {
  type        = string
  description = "Unique username for the customer to authentication with Decube private container registry."
  default     = ""
}

variable "decube_grafana_prometheus_host" {
  type        = string
  description = "Decube Grafana Cloud prometheus host."
  default     = ""
}

variable "decube_grafana_prometheus_username" {
  type        = string
  description = "Decube Grafana Cloud prometheus username."
  default     = ""
}

variable "decube_grafana_prometheus_password" {
  type        = string
  description = "Decube Grafana Cloud prometheus password."
  default     = ""
}

variable "decube_grafana_tempo_host" {
  type        = string
  description = "Decube Grafana Cloud tempo host."
  default     = ""
}

variable "decube_grafana_tempo_username" {
  type        = string
  description = "Decube Grafana Cloud tempo username."
  default     = ""
}

variable "decube_grafana_tempo_password" {
  type        = string
  description = "Decube Grafana Cloud tempo password."
  default     = ""
}

variable "decube_grafana_loki_host" {
  type        = string
  description = "Decube Grafana Cloud loki host."
  default     = ""
}

variable "decube_grafana_loki_username" {
  type        = string
  description = "Decube Grafana Cloud loki username."
  default     = ""
}

variable "decube_grafana_loki_password" {
  type        = string
  description = "Decube Grafana Cloud loki password."
  default     = ""
}

variable "backup_window" {
  type        = string
  description = "AWS RDS instance backup window in UTC and must not overlap with maintenance_window. It must at least be 30 minutes long. i.e. 00:00-00:30"
  default     = ""
}

variable "maintenance_window" {
  type        = string
  description = "AWS RDS instance maintenance window is required to be in this format ddd:hh24:mi-ddd:hh24:mi. Days must be either Mon, Tue, Wed, Thu, Fri, Sat, or Sun. Time is in UTC and must at least be 30 minutes long. i.e. Mon:00:00-Mon:01:00"
  default     = ""
}

variable "decube_data_plane_data_api_domain" {
  type        = string
  description = "Customer self hosted Data Plane API domain."
  default     = ""
}

variable "control_plane_ips" {
  type        = list(string)
  description = "Decube control plane static IPs."
  default     = [""]
}

variable "elasticsearch_node_group_ami" {
  type        = string
  description = "Decube self hosted data plane Elasticsearch node group AWS Bottlerocket AMI ID."
  default     = ""
}

variable "decube_azure_function_access_key" {
  type        = string
  description = "Decube azure function access key"
}
