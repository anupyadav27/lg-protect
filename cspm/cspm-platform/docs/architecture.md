# CSPM Platform Architecture Document

## Overview
The CSPM (Cloud Security Posture Management) platform is a SaaS-based solution designed to provide multi-cloud security visibility, configuration assessment, compliance checks, and automated remediation. It is built with a scalable, multi-tenant architecture and leverages AI-driven insights for enhanced functionality.

## Objectives
- Continuous visibility into cloud resource inventory
- Real-time misconfiguration and drift detection
- Compliance mapping (CIS, NIST, HIPAA, PCI-DSS)
- Threat and vulnerability intelligence integration
- Scalable, multi-tenant SaaS delivery model
- Role-based access control (RBAC) and MFA
- Graph-based relationship modeling and visualization

## High-Level Architecture
```
+-------------+      +-------------------+      +------------------+
|   Frontend  | <--> |  API Gateway      | <--> |  Microservices   |
|   (React)   |      |  (Auth, RBAC)     |      |  Layer (Node.js) |
+-------------+      +-------------------+      +------------------+
                                                    |
                                                    v
                          +------------------------+------------------+
                          | Cloud Connectors / Inventory / Threat DBs |
                          +------------------------+------------------+
                                                    |
                                                    v
                     +--------------------+    +--------------------+
                     |   Graph DB (Neo4j) |    |  NoSQL + RDS       |
                     +--------------------+    +--------------------+
```

## Components

### 1. Frontend (React)
- Dashboards, compliance summaries, posture scores
- Inventory browser with relationships (graph view)
- Alert management, remediation suggestions
- Auth with MFA and RBAC controls

### 2. API Gateway
- Handles authentication, rate limiting, tenant routing
- Exposes REST and GraphQL endpoints

### 3. Microservices Layer
| Service                    | Description                                             |
| -------------------------- | ------------------------------------------------------- |
| User Management            | Signup, login, SSO (OIDC/SAML), org and user roles      |
| Tenant Manager             | Tenant isolation, resource scoping                      |
| Cloud Connector Service    | Integration with AWS, Azure, GCP using SDKs            |
| Inventory Collector        | Periodic and event-based collection of cloud assets     |
| Compliance Engine          | Mapping assets to CIS, HIPAA, PCI-DSS, ISO 27001        |
| Misconfiguration Checker   | Policy engine (rule-based + AI) for detection           |
| Drift Detection Engine     | Compare snapshots over time for changes                 |
| Threat Intelligence Engine | Maps CVEs, MITRE ATT&CK, MISP indicators               |
| Data Security Engine       | Sensitive data detection, encryption, access validation |
| Notification Service       | Email, webhook, in-app, and SIEM alerting integration   |
| Recommendation Engine      | AI-driven fix suggestions, context-aware remediation    |

### 4. Databases
| Purpose        | Technology                                         |
| -------------- | -------------------------------------------------- |
| Graph Store    | Neo4j (for node-relationship modeling)             |
| NoSQL          | DynamoDB / MongoDB (resource snapshots, findings)  |
| Relational     | PostgreSQL (user data, audits, billing)            |
| Time-series DB | Timestream / InfluxDB (metrics, posture evolution) |

### 5. Storage
- Amazon S3: Inventory JSON, reports, artifacts
- Cloud-native encryption via KMS/CMKs

## Multi-Tenancy Design
- Logical tenant isolation with tenant_id in all resources
- Dedicated service roles per tenant for cloud access
- Row-level or schema-level isolation for databases

## Security Features
| Feature           | Description                                 |
| ----------------- | ------------------------------------------- |
| Authentication    | OAuth2 / OIDC + MFA support                 |
| Authorization     | Fine-grained RBAC with permission scopes    |
| Data Encryption   | At-rest (KMS), in-transit (TLS)             |
| Secret Management | AWS Secrets Manager / Vault                 |
| Audit Logging     | Full audit trail of user and system actions |
| Network Controls  | VPC Flow Logs, Security Groups, NACL review |

## DevOps and Observability
| Tool                 | Purpose                     |
| -------------------- | --------------------------- |
| Terraform / CDK      | Infrastructure provisioning |
| Helm / Kustomize     | Kubernetes deployment       |
| GitHub Actions       | CI/CD pipeline              |
| Prometheus + Grafana | Metrics monitoring          |
| ELK / OpenSearch     | Centralized log collection  |

## Compliance & Rule Management
- Rules stored in YAML with metadata
- Mapped to cloud resource types, severity, remediation
- Framework tags (e.g., CIS_1_1_1)
- Supports custom rules per tenant

## Integration Points
| System           | Integration                                     |
| ---------------- | ----------------------------------------------- |
| Cloud Accounts   | IAM Role Assumption / OAuth Token               |
| SIEM             | Syslog/Webhook/REST push (QRadar, Splunk)       |
| Ticketing Tools  | Jira/ServiceNow connector for alert remediation |
| DevOps Pipelines | GitHub Actions / Jenkins / GitLab integration   |

## Future Enhancements
- Auto-remediation workflows with approval gates
- GenAI assistant for security question answering
- Custom compliance framework editor
- Custom dashboard builder for tenants

## Deployment Strategy
- Containerized microservices (Docker + Kubernetes)
- Deployed via GitOps and IaC pipelines
- Blue/Green and Canary deployments for critical updates

## Execution Phases
1. **Planning & Team Setup**
   - Define engineering roles and responsibilities
   - Assign owners for each service/module
   - Set up DevSecOps best practices

2. **API and Interface Definition**
   - Define OpenAPI specs and GraphQL schemas
   - Create JSON schema for API requests/responses

3. **Infrastructure & Dev Environment**
   - Provision isolated dev/staging/prod environments
   - Create reusable Terraform/CDK modules

4. **Core Service Development**
   - Implement Auth, Tenant, Inventory, Compliance Engine microservices
   - Integrate AWS Cloud Connector with SDKs

5. **Testing and Feedback Loop**
   - Develop unit and integration tests
   - Configure UI regression testing

6. **Expansion and AI/ML Integration**
   - Extend support to GCP and Azure connectors
   - Train and deploy recommendation model using BERT/GPT

7. **Production Launch and Operations**
   - Finalize incident management playbooks
   - Run security assessments and pentesting

---

This document serves as a reference for understanding the overall functionality and individual modules of the CSPM platform.

## Updated Architecture

#### Frontend
- The new `ui` folder is now the primary frontend for the platform.
- Built using React and React Admin for managing resources.
- Features modular components for inventory, billing, dashboards, and more.

#### Backend
- Microservices architecture with services like `inventory-collector`, `user-management`, and others.
- Each service communicates via REST APIs.

#### Inventory Feature
- The `inventory-collector` service collects AWS inventories and provides a JSON response.
- The `ui` frontend consumes this data and displays it in a table using React Admin.