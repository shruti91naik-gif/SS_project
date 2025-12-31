# DTS Installation – Infrastructure Setup Guide  
### Terraform Configuration & Initial Folder Structure

**Project:** DTS  
**Prepared By:** Shruti  
**Purpose:** Infrastructure setup for DTS deployment  

---

##  Objective

- Establish a clean and standardized directory structure for DTS  
- Organize Terraform infrastructure code in a dedicated location  
- Prepare the environment for infrastructure provisioning  
- Ensure **Decube-provided Terraform files** are correctly placed and used  

---

## Directory Structure Setup

### 1️⃣ Create DTS Root Directory (PowerShell)

```powershell
mkdir DTS
cd DTS
```

---

### 2️⃣ Create Terraform Directory (PowerShell)

```powershell
mkdir terraform
cd terraform
```

---

### 1️⃣ Create DTS Root Directory (Unix / Linux)

```bash
mkdir -p DTS
cd DTS

```
---

### 2️⃣ Create Terraform Directory (Unix / Linux)

```bash
mkdir -p terraform
cd terraform

```

---

##  Terraform Files Placement

- Copy **Decube-provided Terraform files** into the `terraform` directory  
- Files **must be used exactly as provided**  
- No modifications unless explicitly instructed by the Decube team  

### Expected Directory Structure

```
DTS/
└── terraform/
    ├── main.tf
    ├── variables.tf
    └── templates/
        ├── load-balancer-controller-policy.json.tpl
        ├── teleport-rds-policy.json.tpl
        └── user-data-bottlerocket.sh.tpl
```

---

##  Architecture Overview

```
Local System (Windows PowerShell/Unix/Linux)
        ↓
Terraform (Infrastructure as Code)
        ↓
Cloud Provider (AWS)
        ↓
Infrastructure Ready for DTS
        ↓
Terraform Workspace Ready
        ↓
terraform init / plan / apply
```

---

## Outcome

- Terraform configuration files are used **exactly as shared by the Decube team**  
- No changes, additions, or deletions made  
- Ensures compliance with **Decube-recommended architecture**  

---

##  IAM Configuration

### IAM Setup for DTS Terraform Execution

1. Create IAM Policy using JSON provided by the Decube team  
2. Create IAM User for Terraform access  
3. Create IAM Role for DTS deployment  
4. Attach IAM User ARN to Role trust relationship  
5. Attach Decube policy to the Role  
6. Update Role ARN in Terraform AWS provider  

---

### Update Role ARN in Terraform (`main.tf`)

```hcl
provider "aws" {
  region = var.region

  assume_role {
    role_arn = "arn:aws:iam::XYZ:role/DTS_POC"
  }

  default_tags {
    tags = {
      Project   = "Decube"
      CreatedBy = "Decube"
    }
  }
}
```

---

##  `variables.tf` – Overview

- Defines all configurable inputs for DTS infrastructure  
- Used **exactly as provided** by the Decube team  

### Controls

- AWS configuration  
- Networking  
- EKS  
- Observability  
- Data plane settings  

---

##  Configuration Steps

### Step 1 – Basic AWS Configuration
- Define AWS region for deployment  

---

### Step 2 – AWS Access Key Authentication

#### Step 2.1 – Configure AWS Credentials (PowerShell)

```powershell
$env:AWS_ACCESS_KEY_ID="<AWS_ACCESS_KEY>"
$env:AWS_SECRET_ACCESS_KEY="<AWS_SECRET_ACCESS_KEY>"
```

Terraform and AWS CLI automatically read these values.

---

### Step 3 – Organization Identifier

- Uniquely identifies the organization within the Decube platform  
- Used for tenant mapping and resource association  

---

### Step 4 – Networking Configuration (VPC & Kubernetes)

- Defines IP ranges for VPC and Kubernetes services  
- Ensures network isolation and scalability  

---

### Step 5 – Control Plane IPs

- Enables secure communication between Decube control plane and DTS data plane  
- Used in security groups and firewall rules  

---

### Step 6 – EKS Cluster Configuration

- Ensures compatibility and stability of EKS components  
- Versions aligned with Decube-certified setup  

---

### Step 7 – Container Registry Configuration

- Pull Decube container images  
- Ensure secure access to Decube private registry  

---

### Step 8 – Observability (Grafana Integration)

**Components**
- Prometheus → Metrics  
- Tempo → Distributed Traces  
- Loki → Logs  

---

### Step 9 – RDS Configuration

- Controls RDS backup scheduling  
- Defines maintenance window with minimal business impact  

---

### Step 10 – Data Plane Configuration

- Defines public domain for DTS data plane API  
- Used for external integrations and access  

---

### Step 11 – Elasticsearch & Azure Function

- AMI used for Elasticsearch Bottlerocket nodes  
- Azure Function key used for Decube service integrations  

---

##  Terraform Execution Readiness

```bash
terraform init
terraform plan
terraform apply
```

---

##  Step 12 – EKS Cluster Access Setup

```bash
aws eks update-kubeconfig --name decube --region ap-south-1
```

```bash
kubectl get ns
```

---

##  Step 13 – Verify System Deployments

```bash
kubectl get deployment -n kube-system
```

---

##  Step 14 – Restart CoreDNS & EBS CSI Controller (If Required)

```bash
kubectl rollout restart deployment coredns -n kube-system
kubectl rollout restart deployment ebs-csi-controller -n kube-system
```

---

##  Step 15 – Validate Pod Status

```bash
kubectl get pods -n kube-system
kubectl get pods -n kube-system -w
```

---

##  Mandatory Validation Criteria

- CoreDNS pods are **Running**  
- EBS CSI Controller pods are **Running**  
- No `CrashLoopBackOff` or `Pending` pods  

---

##  Customer Deployment Recommendation

**Dedicated AWS Account (Mandatory)**

- Avoids IAM conflicts  
- Prevents resource overlap  
- Improves security isolation  

---

##  Issues Encountered

**Terraform Execution Error**

- Missing EKS permissions in IAM policy  

**Resolution**
- Update IAM policy with required EKS permissions  

---

##  Final Status

- Infrastructure validated  
- Environment ready for DTS deployment  
- EKS system components verified  
