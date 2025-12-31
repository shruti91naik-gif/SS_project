terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.72.0"
    }

    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "= 2.29.0"
    }

    random = {
      source  = "hashicorp/random"
      version = "= 3.6.0"
    }
  }

  required_version = ">= 1.2.0"
}
provider "aws" {
  region = var.region

  assume_role {
    role_arn = var.aws_assume_role_arn
  }

  default_tags {
    tags = {
      Project   = "Decube"
      CreatedBy = "Decube"
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {}

data "aws_region" "current" {}

locals {
  vpc_cidr_full_form = "${var.vpc_cidr_range}/20"
  cidr_ranges        = cidrsubnets(local.vpc_cidr_full_form, 6, 6, 2, 2)
}

resource "aws_vpc" "this" {
  cidr_block           = local.vpc_cidr_full_form
  instance_tenancy     = "default"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "decube"
  }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.this.id
  cidr_block              = local.cidr_ranges[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "decube-public-subnet-${data.aws_availability_zones.available.names[count.index]}"
  }
}

resource "aws_subnet" "private" {
  count                   = 2
  vpc_id                  = aws_vpc.this.id
  cidr_block              = local.cidr_ranges[count.index + 2]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name                              = "decube-private-subnet-${data.aws_availability_zones.available.names[count.index]}",
    "kubernetes.io/role/internal-elb" = 1
  }
}

resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.this.id
  subnet_ids = aws_subnet.public[*].id
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = "0"
    to_port    = "0"
  }

  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = "0"
    to_port    = "0"
  }

  ingress {
    protocol   = "6"
    rule_no    = 99
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = "22"
    to_port    = "22"
  }

  ingress {
    protocol   = "6"
    rule_no    = 98
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = "3389"
    to_port    = "3389"
  }

  tags = {
    Name = "decube-public-subnet-nacl"
  }
}

resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.this.id
  subnet_ids = aws_subnet.private[*].id

  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = "0"
    to_port    = "0"
  }

  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = "0"
    to_port    = "0"
  }

  ingress {
    protocol   = "6"
    rule_no    = 99
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = "22"
    to_port    = "22"
  }

  ingress {
    protocol   = "6"
    rule_no    = 98
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = "3389"
    to_port    = "3389"
  }

  tags = {
    Name = "decube-private-subnet-nacl"
  }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "decube-igw"
  }
}

resource "aws_eip" "nat" {
  count      = 2
  domain     = "vpc"
  depends_on = [aws_internet_gateway.this]

  tags = {
    Name = "decube-nat-gw-ip-${data.aws_availability_zones.available.names[count.index]}"
  }
}

resource "aws_nat_gateway" "this" {
  count         = 2
  allocation_id = element(aws_eip.nat[*].id, count.index)
  subnet_id     = element(aws_subnet.public[*].id, count.index)

  tags = {
    Name = "decube-nat-${data.aws_availability_zones.available.names[count.index]}"
  }
}

resource "aws_route_table" "public" {
  count  = 2
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "decube-public-subnet-route-table-${data.aws_availability_zones.available.names[count.index]}"
  }
}

resource "aws_route" "internet" {
  count = 2
  route_table_id            = element(aws_route_table.public[*].id, count.index)
  destination_cidr_block    = "0.0.0.0/0"
  gateway_id                = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  count = 2
  subnet_id      = element(aws_subnet.public[*].id, count.index)
  route_table_id = element(aws_route_table.public[*].id, count.index)
}

resource "aws_route_table" "private" {
  count  = 2
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "decube-private-subnet-route-table-${data.aws_availability_zones.available.names[count.index]}"
  }
}

resource "aws_route" "nat" {
  count = 2
  route_table_id            = element(aws_route_table.private[*].id, count.index)
  destination_cidr_block    = "0.0.0.0/0"
  nat_gateway_id            = element(aws_nat_gateway.this[*].id, count.index)
}

resource "aws_route_table_association" "private" {
  count = 2
  subnet_id      = element(aws_subnet.private[*].id, count.index)
  route_table_id = element(aws_route_table.private[*].id, count.index)
}

resource "aws_s3_bucket" "org_store" {
  bucket = "decube-org-store-${var.organization_external_reference}"
  force_destroy = true

  tags = {
    CreatedBy   = "Decube"
  }
}

resource "aws_kms_key" "eks" {
  description             = "AWS KMS Key used to encrypt Decube AWS EKS Cluster Secrets"
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "default-policy"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "eks" {
  name          = "alias/decube-eks"
  target_key_id = aws_kms_key.eks.key_id
}

resource "aws_iam_role" "eks_cluster" {
  name = "DecubeDataEksClusterRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      },
    ]
  })
}

data "aws_iam_policy" "eks_cluster" {
  name = "AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "eks_cluster" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = data.aws_iam_policy.eks_cluster.arn
}

resource "aws_eks_cluster" "decube" {
  name                      = "decube"
  version                   = var.eks_version
  role_arn                  = aws_iam_role.eks_cluster.arn
  enabled_cluster_log_types = ["audit"]

  access_config {
    authentication_mode = "API"
    bootstrap_cluster_creator_admin_permissions = true
  }

  kubernetes_network_config {
    service_ipv4_cidr = "${var.eks_service_ip4_range}/24"
  }

  encryption_config {
    provider  {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }

  vpc_config {
    subnet_ids              = aws_subnet.private[*].id
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = var.control_plane_ips
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster
  ]
}

resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list = ["sts.amazonaws.com"]
  thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"]
  url = aws_eks_cluster.decube.identity[0].oidc[0].issuer
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name                = aws_eks_cluster.decube.name
  addon_name                  = "kube-proxy"
  addon_version               = var.eks_kube_proxy_version
  resolve_conflicts_on_update = "OVERWRITE"
}

resource "aws_eks_addon" "vpc_cni" {
  cluster_name                = aws_eks_cluster.decube.name
  addon_name                  = "vpc-cni"
  addon_version               = var.eks_vpc_cni_version
  resolve_conflicts_on_update = "OVERWRITE"
}

resource "aws_eks_addon" "coredns" {
  depends_on                  = [aws_eks_fargate_profile.kube_system]
  cluster_name                = aws_eks_cluster.decube.name
  addon_name                  = "coredns"
  addon_version               = var.eks_coredns_version
  resolve_conflicts_on_update = "OVERWRITE"
}

resource "aws_iam_service_linked_role" "autoscaling" {
  aws_service_name = "autoscaling.amazonaws.com"
}

resource "aws_kms_key" "ebs" {
  depends_on  = [aws_iam_service_linked_role.autoscaling]
  description = "AWS KMS Key used to encrypt Decube AWS EBS Volumes"

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "default-policy"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow service-linked role use of the customer managed key"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        },
        Action   = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow attachment of persistent resources"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        },
        Action   = [
          "kms:CreateGrant"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "kms:GrantIsForAWSResource" = "true"
          }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/decube-ebs"
  target_key_id = aws_kms_key.ebs.key_id
}

data "aws_iam_policy_document" "ebs_csi_driver" {
  statement {
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]

    resources = [
      aws_kms_key.ebs.arn,
    ]
  }

  statement {
    actions = [
      "kms:CreateGrant",
      "kms:ListGrants",
      "kms:RevokeGrant",
    ]

    resources = [
      aws_kms_key.ebs.arn,
    ]

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"

      values = [
        "true"
      ]
    }
  }
}

resource "aws_iam_policy" "ebs_csi_driver_ebs_encryption" {
  name   = "decube-cmk-ebs-policy"
  policy = data.aws_iam_policy_document.ebs_csi_driver.json
}

data "aws_iam_policy" "ebs_csi_driver" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

resource "aws_iam_role" "ebs_csi_driver" {
  name = "DecubeDataEBSCSIDriverRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = "${aws_iam_openid_connect_provider.eks.arn}"
        }
        Condition = {
          StringEquals = {
            "${replace(aws_eks_cluster.decube.identity[0].oidc[0].issuer, "https://", "")}:aud" = "sts.amazonaws.com"
            "${replace(aws_eks_cluster.decube.identity[0].oidc[0].issuer, "https://", "")}:sub" = "system:serviceaccount:kube-system:ebs-csi-controller-sa"
          }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ebs_csi_driver_ebs_encryption" {
  role       = aws_iam_role.ebs_csi_driver.name
  policy_arn = aws_iam_policy.ebs_csi_driver_ebs_encryption.arn
}

resource "aws_iam_role_policy_attachment" "ebs_csi_driver" {
  role       = aws_iam_role.ebs_csi_driver.name
  policy_arn = data.aws_iam_policy.ebs_csi_driver.arn
}

resource "aws_eks_addon" "ebs_csi_driver" {
  cluster_name                = aws_eks_cluster.decube.name
  addon_name                  = "aws-ebs-csi-driver"
  addon_version               = var.eks_ebs_csi_driver_version
  service_account_role_arn    = aws_iam_role.ebs_csi_driver.arn
  resolve_conflicts_on_update = "OVERWRITE"
  configuration_values        = jsonencode({
    node = {
      nodeSelector = {
        "eks.amazonaws.com/nodegroup" = "decube-elasticsearch-bottlerocket"
      }
    }
  })
}

resource "aws_iam_role" "eks_fargate_pod_execution_role" {
  name = "DecubeDataEKSFargatePodExecutionRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks-fargate-pods.amazonaws.com"
        }
        Condition = {
          ArnLike = {
            "aws:SourceArn" = "arn:aws:eks:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:fargateprofile/${aws_eks_cluster.decube.name}/*"
          }
        }
      },
    ]
  })
}

data "aws_iam_policy" "eks_fargate_pod_execution_role_policy" {
  name = "AmazonEKSFargatePodExecutionRolePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_fargate_pod_execution_role" {
  role       = aws_iam_role.eks_fargate_pod_execution_role.name
  policy_arn = data.aws_iam_policy.eks_fargate_pod_execution_role_policy.arn
}

resource "aws_eks_fargate_profile" "traefik" {
  cluster_name           = aws_eks_cluster.decube.name
  fargate_profile_name   = "traefik"
  pod_execution_role_arn = aws_iam_role.eks_fargate_pod_execution_role.arn
  subnet_ids             = aws_subnet.private[*].id

  selector {
    namespace = "traefik"
  }
}

resource "aws_eks_fargate_profile" "cert_manager" {
  cluster_name           = aws_eks_cluster.decube.name
  fargate_profile_name   = "cert-manager"
  pod_execution_role_arn = aws_iam_role.eks_fargate_pod_execution_role.arn
  subnet_ids             = aws_subnet.private[*].id

  selector {
    namespace = "cert-manager"
  }
}

resource "aws_eks_fargate_profile" "decube" {
  cluster_name           = aws_eks_cluster.decube.name
  fargate_profile_name   = "decube"
  pod_execution_role_arn = aws_iam_role.eks_fargate_pod_execution_role.arn
  subnet_ids             = aws_subnet.private[*].id

  selector {
    namespace = "decube"
  }
}

resource "aws_eks_fargate_profile" "default" {
  cluster_name           = aws_eks_cluster.decube.name
  fargate_profile_name   = "default"
  pod_execution_role_arn = aws_iam_role.eks_fargate_pod_execution_role.arn
  subnet_ids             = aws_subnet.private[*].id

  selector {
    namespace = "default"
  }
}

resource "aws_eks_fargate_profile" "external_secrets" {
  cluster_name           = aws_eks_cluster.decube.name
  fargate_profile_name   = "external-secrets"
  pod_execution_role_arn = aws_iam_role.eks_fargate_pod_execution_role.arn
  subnet_ids             = aws_subnet.private[*].id

  selector {
    namespace = "external-secrets"
  }
}

resource "aws_eks_fargate_profile" "k8s_monitoring" {
  cluster_name           = aws_eks_cluster.decube.name
  fargate_profile_name   = "k8s-monitoring"
  pod_execution_role_arn = aws_iam_role.eks_fargate_pod_execution_role.arn
  subnet_ids             = aws_subnet.private[*].id

  selector {
    namespace = "k8s-monitoring"
  }
}

resource "aws_eks_fargate_profile" "kube_system" {
  cluster_name           = aws_eks_cluster.decube.name
  fargate_profile_name   = "kube-system"
  pod_execution_role_arn = aws_iam_role.eks_fargate_pod_execution_role.arn
  subnet_ids             = aws_subnet.private[*].id

  selector {
    namespace = "kube-system"
  }
}

resource "aws_eks_fargate_profile" "teleport_agent" {
  cluster_name           = aws_eks_cluster.decube.name
  fargate_profile_name   = "teleport-agent"
  pod_execution_role_arn = aws_iam_role.eks_fargate_pod_execution_role.arn
  subnet_ids             = aws_subnet.private[*].id

  selector {
    namespace = "teleport-agent"
  }
}

resource "aws_security_group" "decube_worker_node" {
  name   = "decube-worker-node-security-group"
  vpc_id = aws_vpc.this.id
  ingress {
    description      = "Allow communication from AWS EKS Control Plane to Managed Worker Node pods"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    security_groups  = [aws_eks_cluster.decube.vpc_config[0].cluster_security_group_id]
  }

  ingress {
    description      = "Allow Pod to Pod communication for pods scheduled in the AWS EKS Managed Node Group"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    self             = true
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_security_group_ingress_rule" "cluster_security_group" {
  security_group_id             = aws_eks_cluster.decube.vpc_config[0].cluster_security_group_id
  referenced_security_group_id  = aws_security_group.decube_worker_node.id
  ip_protocol                   = "-1"
  description                   = "Allow communication from Managed Worker Node pods to AWS EKS Control Plane"
}

resource "aws_launch_template" "elasticsearch" {
  name        = "decube-elasticsearch-bottlerocket"
  description = "Decube elasticsearch node group"

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = 4
      volume_type           = "gp2"
      delete_on_termination = true
      encrypted             = true
      kms_key_id            = aws_kms_key.ebs.arn
    }
  }

  block_device_mappings {
    device_name = "/dev/xvdb"

    ebs {
      volume_size           = 100
      volume_type           = "gp2"
      delete_on_termination = true
      encrypted             = true
      kms_key_id            = aws_kms_key.ebs.arn
    }
  }

  image_id    = var.elasticsearch_node_group_ami
  user_data   = "${base64encode(trimspace(templatefile("${path.module}/templates/user-data-bottlerocket.sh.tpl", { EKS_CLUSTER_ENDPOINT = aws_eks_cluster.decube.endpoint, EKS_CLUSTER_CERTIFICATE_AUTHORITY_DATA = aws_eks_cluster.decube.certificate_authority.0.data, EKS_CLUSTER_NAME = aws_eks_cluster.decube.name })))}"

  vpc_security_group_ids = [aws_security_group.decube_worker_node.id]

  instance_type = "t3.medium"

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
    http_put_response_hop_limit = 2
  }
}

resource "aws_iam_role" "worker_node_group" {
  name = "DecubeDataEksWorkerNodeRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

data "aws_iam_policy" "eks_worker_node_policy" {
  name = "AmazonEKSWorkerNodePolicy"
}

data "aws_iam_policy" "ec2_container_registry_readonly" {
  name = "AmazonEC2ContainerRegistryReadOnly"
}

data "aws_iam_policy" "eks_cni_policy" {
  name = "AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  role       = aws_iam_role.worker_node_group.name
  policy_arn = data.aws_iam_policy.eks_worker_node_policy.arn
}

resource "aws_iam_role_policy_attachment" "ec2_container_registry_readonly" {
  role       = aws_iam_role.worker_node_group.name
  policy_arn = data.aws_iam_policy.ec2_container_registry_readonly.arn
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  role       = aws_iam_role.worker_node_group.name
  policy_arn = data.aws_iam_policy.eks_cni_policy.arn
}

resource "aws_eks_node_group" "worker_node_group" {
  cluster_name    = aws_eks_cluster.decube.name
  node_group_name = "decube-elasticsearch-bottlerocket"
  node_role_arn   = aws_iam_role.worker_node_group.arn
  subnet_ids      = [aws_subnet.private[0].id]
  capacity_type   = "ON_DEMAND"

  scaling_config {
    desired_size = 1
    max_size     = 1
    min_size     = 1
  }

  update_config {
    max_unavailable = 1
  }

  launch_template {
    id = aws_launch_template.elasticsearch.id
    version = aws_launch_template.elasticsearch.latest_version
  }

  labels = {
    name = "elasticsearch"
  }

  taint {
    key    = "dedicated"
    value  = "elasticsearch"
    effect = "NO_SCHEDULE"
  }
}

resource "aws_db_subnet_group" "rds" {
  name       = "decube-rds-subnet-group"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "decube-rds-subnet-group"
  }
}

resource "random_password" "decube_data_db_password" {
  length   = 32
  special  = false
}

resource "random_password" "decube_strafe_db_password" {
  length  = 32
  special = false
}

resource "random_password" "decube_app_api_key" {
  length   = 32
  special  = false
}

resource "random_password" "decube_data_api_key" {
  length  = 32
  special = false
}

resource "random_password" "decube_data_api_secret_key" {
  length  = 32
  special = false
}

resource "random_password" "decube_sync_es_password" {
  length  = 32
  special = false
}

resource "random_password" "decube_registry_password" {
  length  = 32
  special = false
}

resource "aws_security_group" "decube_rds" {
  name   = "decube-rds-sg"
  vpc_id = aws_vpc.this.id
  ingress {
    description      = "Allow Fargate pods to communicate with decube rds"
    from_port        = 5432
    to_port          = 5432
    protocol         = "tcp"
    security_groups  = [aws_eks_cluster.decube.vpc_config[0].cluster_security_group_id]
  }
}

resource "aws_kms_key" "rds" {
  description             = "AWS KMS Key used for AWS RDS instances encryption at rest"
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "default-policy"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "rds" {
  name          = "alias/decube-rds"
  target_key_id = aws_kms_key.rds.key_id
}

resource "aws_db_instance" "metadata" {
  identifier                          = "decube-data"
  availability_zone                   = data.aws_availability_zones.available.names[0]
  allocated_storage                   = 20
  max_allocated_storage               = 100
  engine                              = "postgres"
  engine_version                      = "17.5"
  instance_class                      = "db.t3.medium"
  multi_az                            = false
  db_name                             = "decube_data"
  username                            = "postgres"
  password                            = random_password.decube_data_db_password.result
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.rds.arn
  storage_type                        = "gp3"
  db_subnet_group_name                = aws_db_subnet_group.rds.name
  vpc_security_group_ids              = [aws_security_group.decube_rds.id]
  backup_retention_period             = 7
  backup_window                       = var.backup_window
  maintenance_window                  = var.maintenance_window
  auto_minor_version_upgrade          = false
  deletion_protection                 = false
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "decube-data-final-snapshot"
  apply_immediately                   = true
  performance_insights_enabled        = true
  monitoring_interval                 = 0
  copy_tags_to_snapshot               = true
  ca_cert_identifier                  = "rds-ca-rsa2048-g1"
  iam_database_authentication_enabled = true
}

resource "aws_db_instance" "strafe" {
  identifier                          = "decube-strafe"
  availability_zone                   = data.aws_availability_zones.available.names[0]
  allocated_storage                   = 20
  max_allocated_storage               = 100
  engine                              = "postgres"
  engine_version                      = "17.5"
  instance_class                      = "db.t3.medium"
  multi_az                            = false
  db_name                             = "strafe"
  username                            = "postgres"
  password                            = random_password.decube_strafe_db_password.result
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.rds.arn
  storage_type                        = "gp3"
  db_subnet_group_name                = aws_db_subnet_group.rds.name
  vpc_security_group_ids              = [aws_security_group.decube_rds.id]
  backup_retention_period             = 7
  backup_window                       = var.backup_window
  maintenance_window                  = var.maintenance_window
  auto_minor_version_upgrade          = false
  deletion_protection                 = false
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "decube-strafe-final-snapshot"
  apply_immediately                   = true
  performance_insights_enabled        = true
  monitoring_interval                 = 0
  copy_tags_to_snapshot               = true
  ca_cert_identifier                  = "rds-ca-rsa2048-g1"
  iam_database_authentication_enabled = true
}
resource "aws_kms_key" "secrets_manager" {
  description = "AWS KMS Key used to encrypt Decube AWS Secret Manager secrets"

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "default-policy"
    Statement = [
      {
        Sid    = "Allow access through AWS Secrets Manager for all principals in the account that are authorized to use AWS Secrets Manager"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        },
        Action   = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = "${data.aws_caller_identity.current.account_id}"
            "kms:ViaService"    = "secretsmanager.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      },
      {
        Sid    = "Allow access through AWS Secrets Manager for all principals in the account that are authorized to use AWS Secrets Manager"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        },
        Action   = "kms:GenerateDataKey*"
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = "${data.aws_caller_identity.current.account_id}"
          }

          StringLike = {
            "kms:ViaService" = "secretsmanager.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      },
      {
        Sid    = "Allow direct access to key metadata to the account"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action   = [
          "kms:Describe*",
          "kms:Get*",
          "kms:List*",
          "kms:RevokeGrant"
        ]
        Resource = "*"
      },
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action   = "kms:*"
        Resource = "*"
      },
    ]
  })
}

resource "aws_kms_alias" "secrets_manager" {
  name          = "alias/decube-secrets-manager"
  target_key_id = aws_kms_key.secrets_manager.key_id
}

resource "aws_secretsmanager_secret" "decube_data_db_password" {
  name = "decube-data-db-password"
  kms_key_id = aws_kms_key.secrets_manager.key_id
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "decube_data_db_password" {
  secret_id     = aws_secretsmanager_secret.decube_data_db_password.id
  secret_string = "{\"value\": \"${random_password.decube_data_db_password.result}\"}"
}

resource "aws_secretsmanager_secret" "decube_strafe_db_password" {
  name = "decube-strafe-db-password"
  kms_key_id = aws_kms_key.secrets_manager.key_id
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "decube_strafe_db_password" {
  secret_id     = aws_secretsmanager_secret.decube_strafe_db_password.id
  secret_string = "{\"value\": \"${random_password.decube_strafe_db_password.result}\"}"
}

resource "aws_secretsmanager_secret" "decube_app_api_key" {
  name = "decube-app-api-key"
  kms_key_id = aws_kms_key.secrets_manager.key_id
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "decube_app_api_key" {
  secret_id     = aws_secretsmanager_secret.decube_app_api_key.id
  secret_string = "{\"value\": \"${random_password.decube_app_api_key.result}\"}"
}

resource "aws_secretsmanager_secret" "decube_data_api_key" {
  name = "decube-data-api-key"
  kms_key_id = aws_kms_key.secrets_manager.key_id
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "decube_data_api_key" {
  secret_id     = aws_secretsmanager_secret.decube_data_api_key.id
  secret_string = "{\"value\": \"${random_password.decube_data_api_key.result}\"}"
}

resource "aws_secretsmanager_secret" "decube_data_api_secret_key" {
  name = "decube-data-api-secret-key"
  kms_key_id = aws_kms_key.secrets_manager.key_id
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "decube_data_api_secret_key" {
  secret_id     = aws_secretsmanager_secret.decube_data_api_secret_key.id
  secret_string = "{\"value\": \"${random_password.decube_data_api_secret_key.result}\"}"
}

resource "aws_secretsmanager_secret" "decube_sync_es_password" {
  name = "decube-sync-es-password"
  kms_key_id = aws_kms_key.secrets_manager.key_id
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "decube_sync_es_password" {
  secret_id     = aws_secretsmanager_secret.decube_sync_es_password.id
  secret_string = "{\"value\": \"${random_password.decube_sync_es_password.result}\"}"
}

resource "aws_secretsmanager_secret" "decube_docker_image_pull_secrets" {
  name = "decube-docker-image-pull-secrets"
  kms_key_id = aws_kms_key.secrets_manager.key_id
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "decube_docker_image_pull_secrets" {
  secret_id     = aws_secretsmanager_secret.decube_docker_image_pull_secrets.id
  secret_string = "{\"auths\":{\"${var.decube_registry}\":{\"username\":\"${var.decube_registry_username}\",\"password\":\"${random_password.decube_registry_password.result}\"}}}"
}

resource "aws_secretsmanager_secret" "decube_prometheus_k8s_monitoring_secrets" {
  name = "decube-prometheus-k8s-monitoring"
  kms_key_id = aws_kms_key.secrets_manager.key_id
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "decube_prometheus_k8s_monitoring_secrets" {
  secret_id     = aws_secretsmanager_secret.decube_prometheus_k8s_monitoring_secrets.id
  secret_string = "{\"host\": \"${var.decube_grafana_prometheus_host}\", \"username\": \"${var.decube_grafana_prometheus_username}\", \"password\": \"${var.decube_grafana_prometheus_password}\"}"
}

resource "aws_secretsmanager_secret" "decube_tempo_k8s_monitoring_secrets" {
  name = "decube-tempo-k8s-monitoring"
  kms_key_id = aws_kms_key.secrets_manager.key_id
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "decube_tempo_k8s_monitoring_secrets" {
  secret_id     = aws_secretsmanager_secret.decube_tempo_k8s_monitoring_secrets.id
  secret_string = "{\"host\": \"${var.decube_grafana_tempo_host}\", \"username\": \"${var.decube_grafana_tempo_username}\", \"password\": \"${var.decube_grafana_tempo_password}\"}"
}

resource "aws_secretsmanager_secret" "decube_loki_k8s_monitoring_secrets" {
  name = "decube-loki-k8s-monitoring"
  kms_key_id = aws_kms_key.secrets_manager.key_id
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "decube_loki_k8s_monitoring_secrets" {
  secret_id     = aws_secretsmanager_secret.decube_loki_k8s_monitoring_secrets.id
  secret_string = "{\"host\": \"${var.decube_grafana_loki_host}\", \"username\": \"${var.decube_grafana_loki_username}\", \"password\": \"${var.decube_grafana_loki_password}\"}"
}

resource "aws_secretsmanager_secret" "decube_data_db_host" {
  name = "decube-data-db-host"
  kms_key_id = aws_kms_key.secrets_manager.key_id
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "decube_data_db_host" {
  secret_id     = aws_secretsmanager_secret.decube_data_db_host.id
  secret_string = "{\"value\": \"${aws_db_instance.metadata.address}\"}"
}

resource "aws_secretsmanager_secret" "decube_strafe_db_host" {
  name = "decube-strafe-db-host"
  kms_key_id = aws_kms_key.secrets_manager.key_id
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "decube_strafe_db_host" {
  secret_id     = aws_secretsmanager_secret.decube_strafe_db_host.id
  secret_string = "{\"value\": \"${aws_db_instance.strafe.address}\"}"
}

resource "aws_secretsmanager_secret" "decube_azure_function_access_key" {
  name = "decube-azure-function-access-key"
  kms_key_id = aws_kms_key.secrets_manager.key_id
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "decube_azure_function_access_key" {
  secret_id     = aws_secretsmanager_secret.decube_azure_function_access_key.id
  secret_string = "{\"value\": \"${var.decube_azure_function_access_key}\"}"
}

data "aws_iam_policy_document" "secrets_reader" {
  statement {
    actions = [
      "secretsmanager:GetResourcePolicy",
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:ListSecretVersionIds"
    ]

    resources = [
      "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:decube-*"
    ]
  }
}

resource "aws_iam_policy" "secrets_reader" {
  name   = "decube-data-read-secrets-manager"
  policy = data.aws_iam_policy_document.secrets_reader.json
}

resource "aws_iam_role" "secrets_reader" {
  name = "DecubeDataEKSSecrets"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = "${aws_iam_openid_connect_provider.eks.arn}"
        }
        Condition = {
          StringEquals = {
            "${replace(aws_eks_cluster.decube.identity[0].oidc[0].issuer, "https://", "")}:aud" = "sts.amazonaws.com"
            "${replace(aws_eks_cluster.decube.identity[0].oidc[0].issuer, "https://", "")}:sub" = [
              "system:serviceaccount:decube:external-secrets-sa",
              "system:serviceaccount:decube:strafe-secrets-sa",
              "system:serviceaccount:elastic-system:external-secrets-sa",
              "system:serviceaccount:k8s-monitoring:external-secrets-sa"
            ]
          }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "secrets_reader" {
  role       = aws_iam_role.secrets_reader.name
  policy_arn = aws_iam_policy.secrets_reader.arn
}

resource "aws_iam_role" "data_application" {
  name = "DecubeDataApplicationRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = "${aws_iam_openid_connect_provider.eks.arn}"
        }
        Condition = {
          StringEquals = {
            "${replace(aws_eks_cluster.decube.identity[0].oidc[0].issuer, "https://", "")}:aud" = "sts.amazonaws.com"
            "${replace(aws_eks_cluster.decube.identity[0].oidc[0].issuer, "https://", "")}:sub" = [
              "system:serviceaccount:decube:decube-data-application-sa",
              "system:serviceaccount:decube:decube-strafe-application-sa"
            ]
          }
        }
      },
    ]
  })
}

data "aws_iam_policy_document" "data_application" {
  statement {
    actions = [
      "s3:CreateBucket",
      "s3:GetBucketLocation",
      "s3:ListBucket"
    ]

    resources = [
      "arn:aws:s3:::decube-*"
    ]
  }

  statement {
    actions = [
      "s3:ListAllMyBuckets"
    ]

    resources = [
      "*"
    ]
  }

  statement {
    actions = [
      "s3:*Object"
    ]

    resources = [
      "arn:aws:s3:::decube-*/*"
    ]
  }
}

data "aws_iam_policy_document" "apms" {
  statement {
    sid    = "CreateAndDelete"

    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:DetachRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:TagRole"
    ]

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/CustomerDecubeRole*"
    ]
  }

  statement {
    sid    = "AttachRole"

    actions = [
      "iam:AttachRolePolicy"
    ]

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/CustomerDecubeRole*"
    ]

    condition {
      test     = "ArnEquals"
      variable = "iam:PolicyARN"

      values = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/AssumeCustomerSourceRolePolicy"
      ]
    }
  }
}

data "aws_iam_policy_document" "assume_customer_decube" {
  statement {
    actions = [
      "sts:AssumeRole"
    ]

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/CustomerDecubeRole*"
    ]
  }
}

resource "aws_iam_role_policy" "data_application" {
  name   = "DecubeDataApplicationPolicy"
  role   = aws_iam_role.data_application.id

  policy = data.aws_iam_policy_document.data_application.json
}

resource "aws_iam_role_policy" "apms" {
  name   = "APMSPolicy"
  role   = aws_iam_role.data_application.id

  policy = data.aws_iam_policy_document.apms.json
}

resource "aws_iam_role_policy" "assume_customer_decube" {
  name   = "AssumeCustomerDecubeRolePolicy"
  role = aws_iam_role.data_application.id

  policy = data.aws_iam_policy_document.assume_customer_decube.json
}

data "aws_iam_policy_document" "assume_customer_source" {
  statement {
    actions = [
      "sts:AssumeRole"
    ]

    resources = [
      "arn:aws:iam::*:role/*"
    ]
  }
}

resource "aws_iam_policy" "assume_customer_source" {
  name   = "AssumeCustomerSourceRolePolicy"
  policy = data.aws_iam_policy_document.assume_customer_source.json
}

resource "aws_iam_policy" "aws_load_balancer_controller" {
  name   = "decube-data-aws-load-balancer-controller"
  policy = file("${path.module}/templates/load-balancer-controller-policy.json.tpl")
}

resource "aws_iam_role" "aws_load_balancer_controller_role" {
  name = "DecubeDataLoadBalancerControllerRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = "${aws_iam_openid_connect_provider.eks.arn}"
        }
        Condition = {
          StringEquals = {
            "${replace(aws_eks_cluster.decube.identity[0].oidc[0].issuer, "https://", "")}:aud" = "sts.amazonaws.com"
            "${replace(aws_eks_cluster.decube.identity[0].oidc[0].issuer, "https://", "")}:sub" = [
              "system:serviceaccount:kube-system:aws-load-balancer-controller"
            ]
          }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "aws_load_balancer_controller" {
  role       = aws_iam_role.aws_load_balancer_controller_role.name
  policy_arn = aws_iam_policy.aws_load_balancer_controller.arn
}

resource "aws_acm_certificate" "data_api" {
  domain_name       = var.decube_data_plane_data_api_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.this.id
  service_name = "com.amazonaws.${data.aws_region.current.name}.s3"
  route_table_ids = aws_route_table.private[*].id

  tags = {
    Name = "decube-s3-gateway-endpoint"
  }
}

resource "aws_iam_role" "teleport_agent_rds_role" {
 name = "DecubeDataTeleportAgentRDSIamAuthentication"

 assume_role_policy = jsonencode({
   Version = "2012-10-17"
   Statement = [
     {
       Action = "sts:AssumeRoleWithWebIdentity"
       Effect = "Allow"
       Principal = {
         Federated = "${aws_iam_openid_connect_provider.eks.arn}"
       }
       Condition = {
         StringEquals = {
           "${replace(aws_eks_cluster.decube.identity[0].oidc[0].issuer, "https://", "")}:aud" = "sts.amazonaws.com"
           "${replace(aws_eks_cluster.decube.identity[0].oidc[0].issuer, "https://", "")}:sub" = "system:serviceaccount:teleport-agent:teleport-agent"
         }
       }
     },
   ]
 })
}

resource "aws_iam_role_policy" "teleport_agent_rds" {
  name = "aws-rds-iam-authentication"
  role = aws_iam_role.teleport_agent_rds_role.id

  policy = templatefile("${path.module}/templates/teleport-rds-policy.json.tpl", {RESOURCES = [
  "arn:aws:rds-db:${var.region}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_db_instance.metadata.resource_id}/*",
  "arn:aws:rds-db:${var.region}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_db_instance.strafe.resource_id}/*"
  ]})
}
