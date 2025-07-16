# Services Documentation

Comprehensive documentation for all LG-Protect microservices.

## 🏗️ Service Architecture Overview

LG-Protect is built on a microservices architecture with each service handling specific responsibilities:

- **[Inventory Service](#inventory-service)** - AWS resource discovery and management
- **[Compliance Service](#compliance-service)** - Security framework validation
- **[Data Security Service](#data-security-service)** - Data classification and protection
- **[Alert Engine](#alert-engine)** - Real-time alerting and notifications
- **[Report Generator](#report-generator)** - Report generation and analytics
- **[API Gateway](#api-gateway)** - Service orchestration and routing

## 📦 Inventory Service

**Location**: `backend/services/inventory-service/`
**Purpose**: AWS resource discovery, inventory management, and multi-account scanning

### Key Features
- **Multi-Account Scanning**: Enterprise-grade account management with 4 authentication methods
- **60+ AWS Services**: Complete coverage including EC2, S3, RDS, Lambda, IAM, VPC
- **Real-time Discovery**: Event-driven resource detection and updates
- **Advanced Error Handling**: Comprehensive error categorization and analysis
- **Resource Extraction**: Detailed metadata collection with fallback detection

### Architecture
```
┌─────────────────────────────────────┐
│         Inventory Service           │
├─────────────────────────────────────┤
│  Enterprise Account Manager        │
│  ├─> CLI Profiles                  │
│  ├─> Access Key Pairs              │
│  ├─> Cross-Account IAM Roles       │
│  └─> Mixed Authentication          │
├─────────────────────────────────────┤
│  Discovery Engines                 │
│  ├─> Compute Discovery             │
│  ├─> Storage Discovery             │
│  ├─> Network Discovery             │
│  ├─> Security Discovery            │
│  └─> Analytics Discovery           │
├─────────────────────────────────────┤
│  Service Enablement Checker        │
│  ├─> Service Mapping Engine        │
│  ├─> Resource Extraction           │
│  ├─> Global vs Regional Handling   │
│  └─> Advanced Error Analytics      │
└─────────────────────────────────────┘
```

### Discovery Engines

#### Compute Discovery (`engines/compute_discovery.py`)
**Covers**: EC2, Lambda, ECS, EKS, Auto Scaling, Batch
```python
# Discovers compute resources
discovered = await compute_discovery.discover_compute_resources(
    session=aws_session,
    region="us-east-1"
)
```

#### Storage Discovery (`engines/storage_discovery.py`)
**Covers**: S3, EBS, EFS, FSx, Storage Gateway
```python
# Discovers storage resources
storage_assets = await storage_discovery.discover_storage_resources(
    session=aws_session,
    region="us-east-1"
)
```

#### Network Discovery (`engines/network_discovery.py`)
**Covers**: VPC, Subnets, Security Groups, Load Balancers, API Gateway
```python
# Discovers network infrastructure
network_config = await network_discovery.discover_network_resources(
    session=aws_session,
    region="us-east-1"
)
```

### Multi-Account Configuration

#### Enterprise Account Manager
```python
from inventory_service_main import EnterpriseAccountManager

# Initialize account manager
account_manager = EnterpriseAccountManager()

# Add accounts via different authentication methods
account_manager.add_account("prod-account", profile="production")
account_manager.add_account("dev-account", 
    access_key="AKIA...", secret_key="...")
account_manager.add_account("audit-account",
    role_arn="arn:aws:iam::123456789:role/AuditRole",
    external_id="unique-external-id")
```

### Service Mapping

#### Service Configuration (`service_enablement_mapping.json`)
```json
{
  "s3": {
    "client_type": "s3",
    "check_function": "list_buckets",
    "scope": "global",
    "resource_identifier": "Name",
    "count_field": "Buckets[*]"
  },
  "ec2": {
    "client_type": "ec2",
    "check_function": "describe_instances",
    "scope": "regional", 
    "resource_identifier": "InstanceId",
    "count_field": "Reservations[*].Instances[*]"
  }
}
```

### API Endpoints
```http
POST /api/v1/inventory/scan          # Start inventory scan
GET  /api/v1/inventory/accounts      # List configured accounts
POST /api/v1/inventory/accounts      # Add new account
GET  /api/v1/inventory/services      # List discovered services
GET  /api/v1/inventory/resources     # Get resource inventory
```

### Output Formats

#### Account Service Inventory CSV
```csv
Account_ID,Account_Name,Region_Type,Region_Name,Service_Name,Service_Enabled,Resource_Count,Resource_Identifiers
123456789,production,Global,global,s3,True,15,bucket1; bucket2; bucket3
123456789,production,Regional,us-east-1,ec2,True,8,i-1234; i-5678; i-9abc
```

#### Enhanced Summary JSON
```json
{
  "scan_metadata": {
    "scan_session_id": "enterprise_scan_20250712_143022_abc123",
    "accounts_scanned": 3,
    "regions_scanned": 17,
    "success_rate": 94.2
  },
  "account_service_inventory": {
    "123456789": {
      "account_name": "production",
      "global_services": {
        "s3": {
          "enabled": true,
          "resource_count": 15,
          "resource_identifiers": ["bucket1", "bucket2"]
        }
      },
      "regions": {
        "us-east-1": {
          "services": {
            "ec2": {
              "enabled": true,
              "resource_count": 8,
              "resource_identifiers": ["i-1234", "i-5678"]
            }
          }
        }
      }
    }
  }
}
```

## 📋 Compliance Service

**Location**: `backend/services/compliance-service/`
**Purpose**: Security framework validation and compliance reporting

### Supported Frameworks
- **SOC 2 Type II**: Service Organization Control 2
- **PCI-DSS v3.2.1**: Payment Card Industry Data Security Standard
- **HIPAA**: Health Insurance Portability and Accountability Act
- **CIS Benchmarks**: Center for Internet Security
- **NIST CSF**: NIST Cybersecurity Framework
- **ISO 27001**: Information Security Management

### Architecture
```
┌─────────────────────────────────────┐
│        Compliance Service          │
├─────────────────────────────────────┤
│  Framework Engines                 │
│  ├─> SOC2 Engine                   │
│  ├─> PCI-DSS Engine                │
│  ├─> HIPAA Engine                  │
│  └─> CIS Benchmarks Engine         │
├─────────────────────────────────────┤
│  Policy Evaluation                 │
│  ├─> OPA Integration               │
│  ├─> Rule Engine                   │
│  ├─> Risk Scoring                  │
│  └─> Remediation Suggestions       │
├─────────────────────────────────────┤
│  Compliance Reporting              │
│  ├─> Executive Dashboards          │
│  ├─> Technical Reports             │
│  ├─> Audit Trail                   │
│  └─> Trending Analysis             │
└─────────────────────────────────────┘
```

### API Endpoints
```http
POST /api/v1/compliance/validate     # Start compliance validation
GET  /api/v1/compliance/frameworks   # List available frameworks
GET  /api/v1/compliance/status       # Get compliance status
GET  /api/v1/compliance/reports      # Generate compliance reports
```

## 🔒 Data Security Service

**Location**: `backend/services/data-security-service/`
**Purpose**: Data classification, encryption validation, and data loss prevention

### Key Features
- **Sensitive Data Detection**: PII, PHI, financial data identification
- **Encryption Validation**: At-rest and in-transit encryption checks
- **Access Pattern Analysis**: Unusual access pattern detection
- **Data Loss Prevention**: DLP policy enforcement
- **Data Classification**: Automated data sensitivity classification

### API Endpoints
```http
POST /api/v1/data-security/scan      # Start data security scan
GET  /api/v1/data-security/findings  # Get security findings
GET  /api/v1/data-security/policies  # List DLP policies
POST /api/v1/data-security/classify  # Classify data sensitivity
```

## 🚨 Alert Engine

**Location**: `backend/services/alert-engine/`
**Purpose**: Real-time security alerting and notification management

### Features
- **Real-time Alert Generation**: Immediate security finding notifications
- **Multi-channel Delivery**: Email, Slack, Teams, webhooks
- **Alert Correlation**: Pattern detection and grouping
- **Escalation Workflows**: Automated escalation based on severity
- **Alert Suppression**: Intelligent duplicate alert handling

### API Endpoints
```http
POST /api/v1/alerts/create           # Create new alert
GET  /api/v1/alerts                  # List alerts
PUT  /api/v1/alerts/{id}/resolve     # Resolve alert
POST /api/v1/alerts/channels         # Configure notification channels
```

## 📊 Report Generator

**Location**: `backend/services/report-generator/`
**Purpose**: Executive reporting and analytics generation

### Report Types
- **Executive Dashboards**: High-level security posture overview
- **Technical Reports**: Detailed findings for security teams
- **Compliance Reports**: Framework-specific compliance status
- **Trend Analysis**: Historical data and pattern analysis
- **Custom Reports**: User-defined report templates

### API Endpoints
```http
POST /api/v1/reports/generate        # Generate custom report
GET  /api/v1/reports/templates       # List report templates
GET  /api/v1/reports/{id}            # Get generated report
POST /api/v1/reports/schedule        # Schedule recurring reports
```

## 🌐 API Gateway

**Location**: `backend/api-gateway/`
**Purpose**: Service orchestration, routing, and client communication

### Features
- **Service Routing**: Intelligent request routing to microservices
- **Authentication**: JWT-based authentication and authorization
- **Rate Limiting**: API usage control and throttling
- **WebSocket Support**: Real-time event streaming
- **Request/Response Transformation**: Data format standardization

### Key Components
```python
# FastAPI application with WebSocket support
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="LG-Protect API Gateway")

# Real-time WebSocket endpoint
@app.websocket("/ws/{tenant_id}")
async def websocket_endpoint(websocket: WebSocket, tenant_id: str):
    await websocket.accept()
    # Handle real-time events
```

## 🔧 Service Communication

### Event-Driven Architecture
All services communicate through the Redis event bus:

```python
# Event publishing
await event_bus.publish(Event(
    event_type=EventTypes.SCAN_COMPLETED,
    tenant_id="tenant_123",
    data={"scan_id": "scan_123", "results": results}
))

# Event subscription
@event_bus.subscribe(EventTypes.INVENTORY_DISCOVERED)
async def handle_inventory_discovered(event):
    # Trigger compliance validation
    await compliance_service.validate(event.data)
```

### Service Health Monitoring
Each service exposes health endpoints:

```http
GET /health                          # Basic health check
GET /health/detailed                 # Detailed health with dependencies
GET /metrics                         # Prometheus metrics
```

## 🧪 Testing Services

### Unit Testing
```bash
# Test individual service
cd backend/services/inventory-service
python -m pytest tests/

# Test with coverage
python -m pytest --cov=src tests/
```

### Integration Testing
```bash
# End-to-end service testing
python tests/integration/test_service_workflows.py

# Load testing
locust -f tests/performance/locustfile.py --host=http://localhost:8000
```

### Service Mocking
```python
# Mock external AWS calls for testing
@mock_ec2
def test_ec2_discovery():
    # Test EC2 discovery without real AWS calls
    pass
```

## 📈 Performance Optimization

### Service Scaling
```yaml
# Kubernetes horizontal pod autoscaling
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: inventory-service-hpa
spec:
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70
```

### Caching Strategies
```python
# Redis caching for expensive operations
@cache(ttl=300)  # 5-minute cache
async def get_aws_resources(account_id, region):
    return await discover_resources(account_id, region)
```

## 🔒 Security Best Practices

### Service Authentication
- JWT tokens for inter-service communication
- API keys for external integrations
- Mutual TLS for service-to-service communication

### Data Protection
- Encryption at rest and in transit
- PII data masking in logs
- Secure credential management

### Network Security
- Service mesh for encrypted communication
- Network policies for traffic isolation
- WAF for external API protection

---

*For service-specific deployment instructions, see [Deployment Guide](../deployment/README.md)*