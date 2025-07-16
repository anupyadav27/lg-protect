# Architecture Overview

LG-Protect is built on a modern, scalable event-driven microservices architecture designed for enterprise-grade cloud security posture management.

## 🏗️ System Architecture

### High-Level Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend UI   │    │   Mobile Apps   │    │  External APIs  │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────▼─────────────┐
                    │      API Gateway         │
                    │   (FastAPI + WebSocket)  │
                    └─────────────┬─────────────┘
                                 │
                    ┌─────────────▼─────────────┐
                    │     Redis Event Bus      │
                    │  (Pub/Sub + Streaming)   │
                    └─────────────┬─────────────┘
                                 │
        ┌────────────┬────────────┼────────────┬────────────┐
        │            │            │            │            │
        ▼            ▼            ▼            ▼            ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│ Inventory   │ │ Compliance  │ │Data Security│ │Alert Engine │ │   Report    │
│  Service    │ │   Service   │ │   Service   │ │   Service   │ │ Generator   │
└─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘
        │            │            │            │            │
        └────────────┴────────────┼────────────┴────────────┘
                                 │
                    ┌─────────────▼─────────────┐
                    │     DynamoDB Cluster     │
                    │   (Multi-table + TTL)    │
                    └───────────────────────────┘
```

## 🎯 Core Principles

### Event-Driven Architecture
- **Loose Coupling**: Services communicate only through events
- **Scalability**: Independent scaling based on service load
- **Resilience**: Fault isolation prevents cascade failures
- **Auditability**: Complete event trail for compliance

### Microservices Design
- **Single Responsibility**: Each service has one clear purpose
- **Technology Agnostic**: Services can use different tech stacks
- **Independent Deployment**: Deploy and scale services independently
- **Data Ownership**: Each service owns its data

### Cloud-Native Patterns
- **Container-First**: Docker containers for all services
- **Infrastructure as Code**: Terraform and Kubernetes configs
- **Observability**: Comprehensive monitoring and logging
- **Security by Design**: Zero-trust security model

## 📦 Service Architecture

### API Gateway (`backend/api-gateway/`)
**Purpose**: Single entry point for all client interactions

**Key Features**:
- **FastAPI Framework**: High-performance async Python
- **WebSocket Support**: Real-time event streaming to clients
- **Authentication**: JWT-based security with tenant isolation
- **Rate Limiting**: Protection against abuse and DoS
- **Request Routing**: Intelligent routing to microservices

```python
# FastAPI application with real-time capabilities
from fastapi import FastAPI, WebSocket

app = FastAPI(title="LG-Protect API Gateway")

@app.websocket("/ws/{tenant_id}")
async def websocket_endpoint(websocket: WebSocket, tenant_id: str):
    await websocket.accept()
    # Stream real-time scan updates, alerts, etc.
```

**Technology Stack**:
- Python 3.9+ with FastAPI
- Redis for session management
- WebSocket for real-time updates

### Inventory Service (`backend/services/inventory-service/`)
**Purpose**: AWS resource discovery and inventory management

**Key Capabilities**:
- **Multi-Account Scanning**: Enterprise-scale account management
- **60+ AWS Services**: Complete AWS service coverage
- **Real-time Discovery**: Event-driven resource detection
- **Resource Extraction**: Detailed resource metadata collection

**Discovery Engines**:
- `compute_discovery.py` - EC2, Lambda, ECS, EKS
- `storage_discovery.py` - S3, EBS, EFS
- `network_discovery.py` - VPC, Load Balancers
- `security_discovery.py` - IAM, KMS, Security Groups
- `analytics_discovery.py` - Athena, Glue, EMR
- `monitoring_discovery.py` - CloudWatch, CloudTrail

```python
def main():
    # Load service mapping from JSON file
    load_service_mapping()
    # -> Reads service_enablement_mapping.json
    # -> Identifies global vs regional services (64+ AWS services)
    # -> Validates service configurations
    
    # Thread-safe statistics tracking
    scan_stats = {
        "total_api_calls": 0,
        "successful_calls": 0, 
        "failed_calls": 0,
        "concurrent_workers": 15,
        "timeout_seconds": 30
    }
```

**Technology Stack**:
- Python with boto3 AWS SDK
- Multi-threading for parallel scanning
- Event-driven processing with Redis

### Compliance Service (`backend/services/compliance-service/`)
**Purpose**: Security framework compliance validation

**Supported Frameworks**:
- SOC 2 Type II
- PCI-DSS v3.2.1
- HIPAA Security Rule
- CIS Benchmarks
- NIST Cybersecurity Framework

**Compliance Engine**:
- Rule-based policy evaluation
- Risk scoring algorithms
- Remediation recommendations
- Compliance reporting

```python
@event_bus.subscribe("inventory.resources_discovered")
async def validate_compliance(event):
    resources = event.data['resources']
    
    # Validate against multiple frameworks
    for framework in ['soc2', 'pci-dss', 'hipaa']:
        violations = await compliance_engine.validate(resources, framework)
        
        if violations:
            await event_bus.publish(Event(
                type="compliance.violation_detected",
                data={"framework": framework, "violations": violations}
            ))
```

### Data Security Service (`backend/services/data-security-service/`)
**Purpose**: Data classification and security analysis

**Key Features**:
- Sensitive data detection
- Encryption status validation
- Access pattern analysis
- Data loss prevention (DLP)

```python
@event_bus.subscribe("inventory.s3_bucket_discovered")
async def analyze_data_security(event):
    bucket = event.data['bucket']
    
    # Check encryption, public access, data classification
    security_findings = await data_classifier.analyze_bucket(bucket)
    
    await event_bus.publish(Event(
        type="data_security.findings_generated",
        data={"bucket": bucket, "findings": security_findings}
    ))
```

### Alert Engine (`backend/services/alert-engine/`)
**Purpose**: Real-time alerting and notification management

**Capabilities**:
- Real-time alert generation
- Multi-channel notifications (email, Slack, webhook)
- Alert correlation and grouping
- Escalation workflows

```python
@event_bus.subscribe("compliance.violation_detected")
async def generate_alert(event):
    violation = event.data['violation']
    
    if violation['severity'] in ['HIGH', 'CRITICAL']:
        alert = await alert_generator.create_alert(violation)
        
        # Multi-channel notification
        await notification_service.send_alert(alert, channels=['slack', 'email'])
        
        await event_bus.publish(Event(
            type="alert.triggered",
            data={"alert_id": alert.id, "channels": ['slack', 'email']}
        ))
```

## 🔄 Event Bus Architecture

### Event-Driven Communication
**Location**: `backend/events/`
**Technology**: Redis with pub/sub patterns

```python
class EventBus:
    def __init__(self):
        self.redis_client = redis.Redis(host='localhost', port=6379)
    
    async def publish(self, event: Event):
        await self.redis_client.publish(event.channel, event.to_json())
    
    async def subscribe(self, channels: List[str], handler: Callable):
        pubsub = self.redis_client.pubsub()
        await pubsub.subscribe(*channels)
        # Process incoming events
```

**Event Types**:
- `SCAN_INITIATED` - New security scan started
- `INVENTORY_DISCOVERED` - AWS resources found
- `COMPLIANCE_VIOLATION` - Policy violation detected
- `ALERT_TRIGGERED` - Security alert generated
- `SCAN_COMPLETED` - Scan finished with results

### Complete Scan Workflow
```
1. Client Request -> API Gateway
2. API Gateway -> Inventory Service
3. Inventory Service -> AWS APIs (parallel)
4. Resources Discovered -> Event Bus
5. Event Bus -> Compliance Service
6. Compliance Service -> Policy Validation
7. Violations Found -> Event Bus
8. Event Bus -> Alert Engine
9. Alert Engine -> Notifications
10. Results Stored -> DynamoDB
11. Real-time Updates -> WebSocket Clients
```

## 📊 Data Architecture

### DynamoDB Tables

| Table Name | Purpose | Key Schema | Indexes |
|------------|---------|------------|---------|
| `lg-protect-scans` | Scan management & status | scan_id, tenant_id | tenant-created, tenant-status |
| `lg-protect-inventory` | AWS resource inventory | tenant_id, resource_id | scan-service, tenant-created |
| `lg-protect-compliance` | Compliance check results | tenant_id, result_id | scan-framework, tenant-severity |
| `lg-protect-alerts` | Real-time alerts | tenant_id, alert_id | tenant-severity, tenant-type |
| `lg-protect-tenants` | Multi-tenant management | tenant_id | organization, subscription-tier |
| `lg-protect-events` | Event audit trail | tenant_id, event_id | tenant-type, tenant-created |

### Data Flow Architecture
```
AWS APIs -> Inventory Service -> Event Bus -> Multiple Consumers
    |            |                   |              |
    v            v                   v              v
Resources -> DynamoDB Tables -> Redis Events -> Real-time UI
```

## 🔧 Advanced Error Handling

### Intelligent Error Categorization
```python
class EnterpriseErrorLogger:
    def categorize_error(self, error):
        # Maps AWS error codes to categories:
        error_mapping = {
            'AccessDenied': 'access_denied',
            'SubscriptionRequiredException': 'service_not_enabled',  
            'ValidationException': 'parameter_validation',
            'ServiceUnavailable': 'service_unavailable',
            'ResourceNotFoundException': 'resource_not_found'
        }
        
        # Track errors by multiple dimensions:
        self.service_errors[service][error_type] += 1
        self.region_errors[region][error_type] += 1  
        self.account_errors[account][error_type] += 1
```

## 📈 Performance & Scalability

### Key Metrics Tracked
- **API Calls**: Total, successful, failed, calls/second
- **Coverage**: Accounts, regions, services scanned
- **Enablement**: Services enabled vs total checks
- **Resources**: Count and types of AWS resources discovered
- **Errors**: Categorized by type, service, region, account
- **Performance**: Scan duration, throughput, success rate

### Scalability Features
- **Horizontal scaling**: Kubernetes-ready microservices
- **Auto-scaling**: Based on CPU/memory usage
- **Load balancing**: Multiple service instances
- **Caching**: Redis for frequently accessed data
- **Async processing**: Event-driven non-blocking operations

## 🛡️ Security Architecture

### Multi-Tenant Isolation
- **Tenant-based data separation** in DynamoDB
- **JWT tokens** with tenant claims
- **Role-based access control** (RBAC)
- **API rate limiting** per tenant
- **Audit logging** for all operations

### AWS Security Integration
- **IAM roles** for service authentication
- **VPC endpoints** for private connectivity
- **CloudTrail integration** for audit trails
- **AWS Security Hub** integration
- **Encryption** at rest and in transit

## 🔄 Execution Flow Summary

```
1. STARTUP (5 seconds)
   ├── Load service_enablement_mapping.json (64 services)
   ├── Identify 9 global + 55 regional services
   └── Validate configurations

2. SETUP (30-60 seconds)
   ├── Choose authentication method (CLI profiles, keys, roles)
   ├── Validate credentials for each account
   ├── Discover enabled regions per account (~17 regions)
   └── Calculate total scan scope (~3,000+ API calls)

3. SCAN EXECUTION (2-10 minutes)
   ├── Create output directories
   ├── Initialize error tracking
   ├── Launch 15 concurrent worker threads
   ├── Execute ~3,000 AWS API calls in parallel
   ├── Real-time progress reporting
   └── Collect results and errors

4. REPORTING (30 seconds)
   ├── Process and aggregate all results
   ├── Generate 4-dimensional analysis
   ├── Create 5+ output files
   ├── Perform error analysis
   └── Display comprehensive summary
```

---

*For detailed service documentation, see [Services Documentation](../services/README.md)*