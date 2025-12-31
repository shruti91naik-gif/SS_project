## Decube Hosted Data Plane – AWS Architecture

## Architecture Overview

This project follows the **Decube Hosted Data Plane architecture on AWS**, designed to support secure, scalable metadata ingestion, data quality checks, data profiling, and analytics.

The architecture is split into two logical layers:

- **Control Plane** – Managed by Decube, responsible for user access, orchestration, deployments, and platform management.
- **Hosted Data Plane** – Deployed within the customer’s AWS account, where metadata ingestion, profiling, lineage harvesting, and data quality checks are executed.

This separation enables customers to meet compliance, security, and data residency requirements while retaining full control over their data.

---

## 🔹 Component Description

The following diagram provides a high-level overview of the core components that make up the Decube Hosted Data Plane.

![Component Description](component-description.png)

---

## 🔹 Component Diagram

The component diagram below illustrates interactions between the core Decube Data Plane services, including APIs, databases, storage layers, job orchestration components, and connected data sources.

![Component Diagram](component-diagram.png)

### Key Components

- **Reverse Proxy (Traefik)**  
  Routes incoming requests from the Decube Control Plane to the Data Plane API.

- **Data Plane API**  
  Exposes endpoints for metadata ingestion, profiling, and data quality operations.

- **Metadata Database (PostgreSQL)**  
  Stores metadata, credentials, and monitoring configurations.

- **Object Storage (AWS S3)**  
  Stores data profiling artefacts.

- **Job Server & Scheduler**  
  Manages and schedules profiling and data quality jobs.

- **Queue (Redis)**  
  Holds scheduled jobs.

- **Worker**  
  Executes profiling and data quality jobs.

- **Search Engine (Elasticsearch)**  
  Supports full-text search on metadata.

- **Connected Data Sources**  
  Customer-managed data systems integrated with Decube.

---

## 🔹 Technology Mapping

The table below maps Decube Data Plane components to the underlying technologies used.

![Technology Mapping](technology-mapping.png)

---

## 🔹 Software Requirements

The Hosted Data Plane requires the following software components.

![Software Requirements](software-requirements.png)

### Notes
- All software components are provided and maintained by **Decube**.
- Security patches and application updates are managed by the **Decube team**.

---

## 🔹 Hosted Data Plane Architecture (AWS)

The Hosted Data Plane is deployed within a **dedicated AWS account** and follows AWS security, networking, and availability best practices.

![Hosted Data Plane Architecture – AWS](hosted-data-plane-architecture-aws.png)

### Architecture Highlights

- AWS VPC with public and private subnets across multiple Availability Zones.
- AWS EKS used as the core compute platform:
  - Fargate pods for Data Plane services.
  - Managed Node Group for Elasticsearch.
- AWS Network Load Balancer with IP whitelisting and TLS 1.2 enforcement.

### Security

- IAM-based access control.
- AES-256 encryption at rest.
- Optional enablement of GuardDuty, CloudTrail, and Security Hub.

### Data Stores

- AWS RDS for metadata and job databases.
- AWS S3 for profiling artefacts.

### Networking

- NAT Gateway for outbound traffic.
- Gateway VPC Endpoint for secure S3 access.

---

## 🔹 Cloud Resources (Minimum)

The minimum AWS cloud resources required to deploy the Hosted Data Plane are shown below.

![Cloud Resources – Minimum](cloud-resources-minimum.png)

---

## 🔹 Infrastructure Requirement

The Hosted Data Plane deployment is performed on AWS Cloud in the region requested by the customer.

### Requirements

- A **dedicated AWS account** for Data Plane deployment.
- **Temporary access** for Decube engineers during installation, configuration, and validation.

---

## 🔹 Networking Requirement

Customers must provide non-overlapping CIDR ranges for the Hosted Data Plane.

![Networking Requirements](networking-requirements.png)

### Key Points

- VPC CIDR must not overlap with existing VPCs or on-prem networks.
- AWS EKS Service CIDR must be reserved exclusively for Kubernetes services.

---

## 🔹 Collected Metadata in Hosted Data Plane

The Hosted Data Plane collects and stores metadata required for platform functionality.

![Collected Metadata](collected-metadata-hosted-data-plane.png)

### Security & Retention

- Indefinite retention until the underlying data source is removed.
- Dual-layer encryption (value-level + at-rest).
- AES-256 encryption standard used across all data.

---

## 🔹 Deployment Model

### Cloud Resources

- AWS infrastructure provisioned using **Decube Terraform manifests**.
- Terraform executed from the customer’s AWS account.

### Data Plane Applications

- Deployed by Decube engineers using **GitOps Continuous Delivery**.
- Secure connectivity established between the Control Plane and AWS EKS cluster.

---

## 🔹 Periodic Updates and Patches

Decube actively monitors security advisories and applies patches as required.

### Security Feeds

- AWS Security Bulletin RSS.
- Kubernetes Official CVE Feed.
- PostgreSQL Security Mailing List.

Customers are notified prior to applying critical security patches.

---

## 🔹 Application Observability

- Grafana Agents deployed within the AWS EKS cluster.
- Metrics and logs forwarded to Decube Grafana Cloud.
- PII redaction rules applied before log transmission.

---

## 🔹 Application Support

- Teleport Agent deployed in the Hosted Data Plane.
- Provides zero-trust access to AWS EKS and RDS.
- Improves response time for customer-reported issues.

---

## ✅ Summary

This repository documents the AWS-based Decube Hosted Data Plane architecture, covering infrastructure, security, networking, deployment, observability, and operational best practices required for enterprise-grade data management.
