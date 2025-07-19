# Development Guide

Complete guide for developers working on the LG-Protect platform.

## 🚀 Quick Start for Developers

### Development Environment Setup
```bash
# Clone repository
git clone https://github.com/anupyadav27/lg-protect.git
cd lg-protect

# Set up Python virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Set up pre-commit hooks
pre-commit install

# Start development services
docker-compose -f infrastructure/docker-compose/docker-compose.dev.yml up -d
```

### Project Structure
```
lg-protect/
├── backend/
│   ├── api-gateway/           # FastAPI gateway service
│   ├── services/              # Microservices
│   │   ├── inventory-service/
│   │   ├── compliance-service/
│   │   ├── data-security-service/
│   │   ├── alert-engine/
│   │   └── report-generator/
│   └── shared/               # Shared utilities
│       ├── database/
│       ├── event-bus/
│       └── auth/
├── frontend/                 # Frontend applications
├── infrastructure/           # Deployment configurations
├── tests/                   # Test suites
└── docs/                    # Documentation
```

## 🏗️ Architecture Principles

### Event-Driven Design
All services communicate through events via Redis:

```python
# Event publishing pattern
from shared.event_bus import EventBus, Event, EventTypes

async def publish_scan_completed(scan_id, results):
    event = Event(
        event_type=EventTypes.SCAN_COMPLETED,
        tenant_id="tenant_123",
        data={
            "scan_id": scan_id,
            "results": results,
            "timestamp": datetime.utcnow().isoformat()
        }
    )
    await EventBus.publish(event)

# Event subscription pattern
@EventBus.subscribe(EventTypes.INVENTORY_DISCOVERED)
async def handle_inventory_discovered(event):
    # Process inventory discovery
    await compliance_service.validate(event.data)
```

### Microservices Best Practices
- **Single Responsibility**: Each service has one clear purpose
- **Database per Service**: No shared databases between services
- **API Contracts**: Well-defined interfaces between services
- **Independent Deployment**: Services can be deployed separately

### Code Organization
```python
# Standard service structure
backend/services/service-name/
├── src/
│   ├── api/              # REST API endpoints
│   ├── models/           # Data models
│   ├── services/         # Business logic
│   ├── utils/            # Utilities
│   └── main.py          # Service entry point
├── tests/
│   ├── unit/            # Unit tests
│   ├── integration/     # Integration tests
│   └── fixtures/        # Test fixtures
├── Dockerfile           # Container definition
├── requirements.txt     # Dependencies
└── README.md           # Service documentation
```

## 🛠️ Development Workflow

### Feature Development Process
1. **Create feature branch** from main
2. **Write tests first** (TDD approach)
3. **Implement functionality** with clean code
4. **Run full test suite** locally
5. **Update documentation** as needed
6. **Submit pull request** with detailed description

### Code Standards
```python
# Python code style
from typing import List, Optional, Dict, Any
import structlog

logger = structlog.get_logger(__name__)

class ServiceClass:
    """Service class following PEP 257 docstring conventions."""
    
    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        
    async def process_data(self, 
                          data: List[Dict[str, Any]], 
                          validate: bool = True) -> Optional[Dict[str, Any]]:
        """Process data with optional validation.
        
        Args:
            data: List of data dictionaries to process
            validate: Whether to validate input data
            
        Returns:
            Processed data dictionary or None if processing fails
            
        Raises:
            ValidationError: If data validation fails
        """
        try:
            if validate:
                self._validate_data(data)
            return await self._process_internal(data)
        except Exception as e:
            logger.error("Data processing failed", error=str(e))
            raise
```

### Git Workflow
```bash
# Feature development
git checkout -b feature/aws-ecr-discovery
git add .
git commit -m "feat: add ECR discovery engine

- Implement ECR repository discovery
- Add ECR image vulnerability scanning
- Update service mapping configuration
- Add comprehensive test coverage

Closes #123"

# Pull request
git push origin feature/aws-ecr-discovery
# Create PR via GitHub/GitLab interface
```

### Commit Message Format
```
type(scope): short description

Longer description if needed

- Bullet point changes
- Multiple lines allowed

Closes #issue-number
```

**Types**: `feat`, `fix`, `docs`, `test`, `refactor`, `style`, `chore`

## 🧪 Testing Framework

### Test Structure
```python
# tests/unit/test_inventory_service.py
import pytest
from unittest.mock import Mock, patch
from inventory_service.discovery_engines import EC2Discovery

@pytest.fixture
def mock_aws_session():
    """Mock AWS session for testing."""
    session = Mock()
    ec2_client = Mock()
    session.client.return_value = ec2_client
    return session, ec2_client

@pytest.mark.asyncio
async def test_ec2_discovery_success(mock_aws_session):
    """Test successful EC2 instance discovery."""
    session, ec2_client = mock_aws_session
    
    # Mock AWS response
    ec2_client.describe_instances.return_value = {
        'Reservations': [{
            'Instances': [{
                'InstanceId': 'i-1234567890abcdef0',
                'State': {'Name': 'running'},
                'InstanceType': 't3.micro'
            }]
        }]
    }
    
    # Test discovery
    discovery = EC2Discovery(session)
    instances = await discovery.discover_instances('us-east-1')
    
    # Assertions
    assert len(instances) == 1
    assert instances[0]['InstanceId'] == 'i-1234567890abcdef0'
    assert instances[0]['State'] == 'running'
```

### Running Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/unit/test_inventory_service.py

# Run integration tests
pytest tests/integration/ -v

# Run with specific markers
pytest -m "not slow"
```

### Test Categories
- **Unit Tests**: Individual function/class testing
- **Integration Tests**: Service interaction testing  
- **End-to-End Tests**: Full workflow testing
- **Performance Tests**: Load and stress testing

## 🔧 Service Development

### Creating a New Service
```bash
# Use service template
./scripts/create_service.sh new-service-name

# Manual creation
mkdir -p backend/services/new-service/{src,tests}
cd backend/services/new-service
```

### Service Template
```python
# backend/services/new-service/src/main.py
from fastapi import FastAPI
from shared.event_bus import EventBus
from shared.database import DynamoDBClient
import structlog

logger = structlog.get_logger(__name__)

app = FastAPI(title="New Service", version="1.0.0")

class NewService:
    def __init__(self):
        self.db = DynamoDBClient()
        self.event_bus = EventBus()
        
    async def startup(self):
        """Service startup initialization."""
        await self.event_bus.connect()
        logger.info("New service started")
        
    async def shutdown(self):
        """Service shutdown cleanup."""
        await self.event_bus.disconnect()
        logger.info("New service stopped")

service = NewService()

@app.on_event("startup")
async def startup_event():
    await service.startup()

@app.on_event("shutdown") 
async def shutdown_event():
    await service.shutdown()

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "new-service"}

@app.post("/api/v1/new-service/action")
async def perform_action(request: dict):
    """Main service endpoint."""
    try:
        # Process request
        result = await service.process_request(request)
        
        # Publish event
        await service.event_bus.publish({
            "type": "new_service.action_completed",
            "data": result
        })
        
        return {"success": True, "data": result}
    except Exception as e:
        logger.error("Action failed", error=str(e))
        raise
```

### Adding Discovery Engines
```python
# backend/services/inventory-service/src/engines/new_discovery.py
from typing import List, Dict, Any
import boto3
import structlog

logger = structlog.get_logger(__name__)

class NewServiceDiscovery:
    """Discovery engine for AWS New Service."""
    
    def __init__(self, session: boto3.Session):
        self.session = session
        
    async def discover_resources(self, region: str) -> List[Dict[str, Any]]:
        """Discover resources in specified region."""
        try:
            client = self.session.client('new-service', region_name=region)
            
            response = client.list_resources()
            resources = []
            
            for item in response.get('Resources', []):
                resource = {
                    'service': 'new-service',
                    'region': region,
                    'resource_type': 'Resource',
                    'resource_id': item['Id'],
                    'name': item.get('Name', ''),
                    'status': item.get('Status', 'unknown'),
                    'created_time': item.get('CreatedTime'),
                    'tags': item.get('Tags', [])
                }
                resources.append(resource)
                
            logger.info("Discovered resources", 
                       service="new-service", 
                       region=region, 
                       count=len(resources))
            
            return resources
            
        except Exception as e:
            logger.error("Discovery failed", 
                        service="new-service", 
                        region=region, 
                        error=str(e))
            return []
```

## 📚 API Development

### API Design Principles
- **RESTful design** with proper HTTP methods
- **Consistent response format** across all endpoints
- **Comprehensive error handling** with meaningful messages
- **Input validation** with clear error responses
- **Rate limiting** and authentication

### API Endpoint Template
```python
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import List, Optional

app = FastAPI()

class RequestModel(BaseModel):
    name: str = Field(..., description="Resource name")
    region: str = Field(..., description="AWS region")
    tags: Optional[List[str]] = Field(default=[], description="Resource tags")

class ResponseModel(BaseModel):
    success: bool
    data: dict
    message: Optional[str] = None

@app.post("/api/v1/resource", response_model=ResponseModel)
async def create_resource(request: RequestModel):
    """Create a new resource."""
    try:
        # Validate input
        if not request.name:
            raise HTTPException(status_code=400, detail="Name is required")
            
        # Process request
        result = await process_resource_creation(request)
        
        return ResponseModel(
            success=True,
            data=result,
            message="Resource created successfully"
        )
        
    except Exception as e:
        logger.error("Resource creation failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))
```

### Error Handling
```python
from fastapi import HTTPException
from shared.exceptions import ServiceError, ValidationError

@app.exception_handler(ValidationError)
async def validation_error_handler(request, exc):
    return JSONResponse(
        status_code=400,
        content={
            "success": False,
            "error": {
                "code": "VALIDATION_ERROR",
                "message": str(exc),
                "details": exc.details
            }
        }
    )

@app.exception_handler(ServiceError)
async def service_error_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": {
                "code": "SERVICE_ERROR", 
                "message": "Internal service error",
                "request_id": request.headers.get("X-Request-ID")
            }
        }
    )
```

## 🔌 Database Development

### Database Schema Design
```python
# shared/database/models.py
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class ScanRecord(BaseModel):
    """DynamoDB scan record model."""
    tenant_id: str
    scan_id: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    results: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    
    class Config:
        # DynamoDB table configuration
        table_name = "lg-protect-scans"
        partition_key = "tenant_id"
        sort_key = "scan_id"
        ttl_attribute = "expires_at"
        
        # Secondary indexes
        gsi_1_pk = "status"
        gsi_1_sk = "created_at"
```

### Database Operations
```python
# shared/database/repositories.py
from shared.database import DynamoDBClient
from shared.database.models import ScanRecord

class ScanRepository:
    """Repository for scan operations."""
    
    def __init__(self, db_client: DynamoDBClient):
        self.db = db_client
        
    async def create_scan(self, scan: ScanRecord) -> bool:
        """Create a new scan record."""
        try:
            await self.db.put_item(
                table_name="lg-protect-scans",
                item=scan.dict()
            )
            return True
        except Exception as e:
            logger.error("Failed to create scan", error=str(e))
            return False
            
    async def get_scan(self, tenant_id: str, scan_id: str) -> Optional[ScanRecord]:
        """Get scan by ID."""
        try:
            item = await self.db.get_item(
                table_name="lg-protect-scans",
                key={"tenant_id": tenant_id, "scan_id": scan_id}
            )
            return ScanRecord(**item) if item else None
        except Exception as e:
            logger.error("Failed to get scan", error=str(e))
            return None
```

## 🚀 Deployment Development

### Docker Development
```dockerfile
# Dockerfile.dev - Development container
FROM python:3.9-slim

WORKDIR /app

# Install development dependencies
COPY requirements-dev.txt .
RUN pip install -r requirements-dev.txt

# Copy source code
COPY src/ ./src/
COPY tests/ ./tests/

# Development server with hot reload
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
```

### Environment Configuration
```python
# shared/config.py
from pydantic import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    # Service configuration
    service_name: str = "lg-protect"
    service_version: str = "1.0.0"
    log_level: str = "INFO"
    
    # Database configuration
    dynamodb_endpoint: Optional[str] = None
    dynamodb_region: str = "us-east-1"
    
    # Event bus configuration
    redis_url: str = "redis://localhost:6379"
    
    # AWS configuration
    aws_region: str = "us-east-1"
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# Global settings instance
settings = Settings()
```

## 🔍 Debugging and Monitoring

### Logging Configuration
```python
# shared/logging.py
import structlog
import logging
from datetime import datetime

def configure_logging(service_name: str, log_level: str = "INFO"):
    """Configure structured logging."""
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="ISO"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Configure standard logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper())
    )
    
    # Add service context
    logger = structlog.get_logger()
    logger = logger.bind(service=service_name)
    
    return logger
```

### Performance Monitoring
```python
# shared/monitoring.py
import time
from functools import wraps
import structlog

logger = structlog.get_logger(__name__)

def monitor_performance(operation_name: str):
    """Decorator to monitor function performance."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                logger.info("Operation completed",
                           operation=operation_name,
                           duration=duration,
                           success=True)
                return result
            except Exception as e:
                duration = time.time() - start_time
                logger.error("Operation failed",
                           operation=operation_name,
                           duration=duration,
                           error=str(e),
                           success=False)
                raise
        return wrapper
    return decorator

# Usage
@monitor_performance("ec2_discovery")
async def discover_ec2_instances(region: str):
    # Discovery logic here
    pass
```

## 📋 Contributing Guidelines

### Pull Request Process
1. **Fork the repository** and create feature branch
2. **Write comprehensive tests** for new functionality
3. **Update documentation** for API changes
4. **Follow code standards** and pass linting
5. **Submit PR** with detailed description

### Code Review Checklist
- [ ] **Functionality**: Code works as intended
- [ ] **Tests**: Comprehensive test coverage
- [ ] **Documentation**: Updated and accurate
- [ ] **Performance**: No performance regressions
- [ ] **Security**: No security vulnerabilities
- [ ] **Style**: Follows project conventions

### Release Process
```bash
# Version bump
./scripts/bump_version.sh 1.2.0

# Create release branch
git checkout -b release/1.2.0

# Update changelog
./scripts/update_changelog.sh

# Tag release
git tag -a v1.2.0 -m "Release version 1.2.0"

# Deploy to staging
./scripts/deploy.sh staging

# Deploy to production (after testing)
./scripts/deploy.sh production
```

## 🛡️ Security Development

### Security Best Practices
- **Input validation** for all external inputs
- **SQL injection prevention** with parameterized queries
- **Authentication** and authorization on all endpoints
- **Secrets management** with proper rotation
- **Audit logging** for all sensitive operations

### Security Testing
```python
# tests/security/test_api_security.py
import pytest
from fastapi.testclient import TestClient

def test_api_requires_authentication():
    """Test that API endpoints require authentication."""
    client = TestClient(app)
    
    # Test without auth token
    response = client.get("/api/v1/scans")
    assert response.status_code == 401
    
    # Test with invalid token
    response = client.get("/api/v1/scans", 
                         headers={"Authorization": "Bearer invalid"})
    assert response.status_code == 401

def test_input_validation():
    """Test input validation prevents injection attacks."""
    client = TestClient(app)
    
    # Test SQL injection attempt
    malicious_input = "'; DROP TABLE users; --"
    response = client.post("/api/v1/search", 
                          json={"query": malicious_input})
    assert response.status_code == 400
```

---

*For specific development tasks, see the individual service README files and the examples in the codebase.*