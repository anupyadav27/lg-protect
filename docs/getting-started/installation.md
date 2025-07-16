# Installation Guide

Complete installation and setup guide for the LG-Protect platform.

## 🚀 Quick Installation Options

### Option 1: One-Command Setup (Recommended)
```bash
# Basic installation with AWS DynamoDB
./setup.sh

# Development setup with local DynamoDB
./setup.sh --local-dynamodb

# Custom region installation
./setup.sh --region eu-west-1

# Full development setup with sample data
./setup.sh --local-dynamodb --sample-data
```

### Option 2: Docker Deployment
```bash
# Complete system deployment
cd infrastructure/docker-compose/
./deploy-microservices.sh

# Development environment
docker-compose up -d
```

### Option 3: Manual Installation
```bash
# Run the Python installer directly
python3 install.py --region us-east-1

# Or with specific options
python3 install.py --region us-east-1 --local-dynamodb --sample-data
```

## 📋 Prerequisites

### System Requirements
- **Python 3.8+** with pip
- **AWS CLI** configured with credentials
- **Docker & Docker Compose** (for containerized deployment)
- **Git** for repository access
- **4GB RAM minimum** (8GB recommended for enterprise)
- **10GB disk space** for installation and data

### AWS Requirements
- **AWS Account** with appropriate permissions
- **AWS CLI configured** with credentials
- **Read permissions** for services you want to scan
- **DynamoDB permissions** for table creation (production)

## 🔧 Installation Methods

### Method 1: Automated Setup Script

The setup script handles all dependencies and configuration:

```bash
# Clone repository
git clone https://github.com/anupyadav27/lg-protect.git
cd lg-protect

# Run automated setup
./setup.sh

# Verify installation
curl http://localhost:8000/health
```

**What the setup script does:**
- Creates Python virtual environment
- Installs all dependencies from requirements files
- Sets up DynamoDB tables (AWS or local)
- Configures environment variables
- Starts core services
- Validates installation

### Method 2: Docker Deployment

For production and containerized environments:

```bash
# Navigate to Docker configuration
cd infrastructure/docker-compose/

# Deploy complete microservices stack
./deploy-microservices.sh

# Check deployment status
docker-compose ps

# View service logs
docker-compose logs -f api-gateway
```

**Services deployed:**
- API Gateway (Port 8000)
- Inventory Service (Port 3000)
- Compliance Service (Port 3001)
- Data Security Service (Port 3002)
- Alert Engine (Port 3010)
- Redis Event Bus (Port 6379)
- Local DynamoDB (Port 8000)
- Monitoring Stack (Prometheus, Grafana)

## 📦 Dependency Management

### Available Dependency Files
- **`requirements.txt`** - Core platform dependencies
- **`requirements-dev.txt`** - Development tools (testing, debugging, docs)
- **`requirements-prod.txt`** - Production-only dependencies (pinned versions)

### Dependency Manager Commands
```bash
# Setup development environment
python3 manage_dependencies.py --setup dev

# Setup production environment  
python3 manage_dependencies.py --setup prod

# Install specific package
python3 manage_dependencies.py --install "package-name"

# Validate current installation
python3 manage_dependencies.py --validate

# Create fresh virtual environment
python3 manage_dependencies.py --recreate

# List all installed packages
python3 manage_dependencies.py --list

# Freeze current environment
python3 manage_dependencies.py --freeze requirements-current.txt
```

## 🗄️ Database Setup

### Production Setup (AWS DynamoDB)

```bash
# Automatic table creation during installation
./setup.sh --region us-east-1

# Manual table management
python3 backend/shared/database/dynamodb_setup.py

# Create tables in specific region
python3 backend/shared/database/dynamodb_setup.py --region eu-west-1
```

**Created Tables:**
- `lg-protect-scans` - Scan management & status
- `lg-protect-inventory` - AWS resource inventory
- `lg-protect-compliance` - Compliance check results
- `lg-protect-alerts` - Real-time alerts
- `lg-protect-tenants` - Multi-tenant management
- `lg-protect-events` - Event audit trail

### Development Setup (Local DynamoDB)

```bash
# Start local DynamoDB container
docker run -p 8000:8000 amazon/dynamodb-local

# Install with local DynamoDB
./setup.sh --local-dynamodb

# Or create tables manually
python3 backend/shared/database/dynamodb_setup.py --local http://localhost:8000
```

### DynamoDB Management Commands

```bash
# Create all tables (production)
python3 backend/shared/database/dynamodb_setup.py

# Show all table information
python3 backend/shared/database/dynamodb_setup.py --info

# Validate AWS connection
python3 backend/shared/database/dynamodb_setup.py --validate

# Create tables in local DynamoDB
python3 backend/shared/database/dynamodb_setup.py --local http://localhost:8000

# Delete all tables (development only - requires confirmation)
python3 backend/shared/database/dynamodb_setup.py --delete
```

## 🔧 Configuration

### Environment Variables
```bash
# Copy template and customize
cp .env.template .env

# Key configuration options:
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_DEFAULT_REGION=us-east-1
REDIS_URL=redis://localhost:6379
DATABASE_URL=dynamodb://localhost:8000
LOG_LEVEL=INFO
```

### Service Configuration
```bash
# API Gateway configuration
backend/api-gateway/config.json

# Service-specific configurations
backend/services/*/config/
```

## ✅ Installation Validation

### Health Checks
```bash
# Check API Gateway
curl http://localhost:8000/health

# Check individual services
curl http://localhost:3000/health  # Inventory Service
curl http://localhost:3001/health  # Compliance Service
curl http://localhost:3002/health  # Data Security Service

# Check database connectivity
python3 backend/shared/database/dynamodb_setup.py --validate
```

### Integration Tests
```bash
# Run complete integration test suite
cd infrastructure/docker-compose/
./test-integration.sh

# Test individual workflows
curl -X POST http://localhost:8000/api/v1/inventory/scan
```

### Access Points After Installation
| Service | URL | Purpose |
|---------|-----|---------|
| **API Gateway** | http://localhost:8000 | Main API access |
| **API Documentation** | http://localhost:8000/docs | Interactive API docs |
| **Inventory Service** | http://localhost:3000 | Resource discovery |
| **Compliance Service** | http://localhost:3001 | Framework validation |
| **Grafana Dashboard** | http://localhost:3030 | Monitoring |
| **Prometheus** | http://localhost:9090 | Metrics |
| **Redis Commander** | http://localhost:8081 | Event bus management |

## 🚨 Troubleshooting

### Common Issues

#### 1. AWS Credentials Not Configured
```bash
# Error: NoCredentialsError
# Solution: Configure AWS credentials
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"

# Verify credentials
aws sts get-caller-identity
```

#### 2. Permission Denied for DynamoDB
```bash
# Error: AccessDeniedException
# Solution: Ensure IAM user/role has required permissions
# Required permissions:
# - dynamodb:CreateTable
# - dynamodb:DescribeTable
# - dynamodb:ListTables
# - dynamodb:UpdateTimeToLive
```

#### 3. Port Conflicts
```bash
# Error: Port already in use
# Solution: Check what's using the port
lsof -i :8000
sudo kill -9 <PID>

# Or change port in configuration
```

#### 4. Docker Issues
```bash
# Container startup failures
docker-compose logs <service-name>

# Restart specific service
docker-compose restart <service-name>

# Clean restart
docker-compose down
docker-compose up -d
```

#### 5. Local DynamoDB Connection Issues
```bash
# Error: EndpointConnectionError
# Solution: Ensure local DynamoDB is running
docker ps | grep dynamodb-local

# Start if not running
docker run -p 8000:8000 amazon/dynamodb-local
```

## 🔄 Post-Installation

### 1. Verify Complete Installation
```bash
# Run comprehensive validation
./setup.sh --validate

# Check all service health
curl -s http://localhost:8000/health | jq '.'

# Test API endpoints
curl -s http://localhost:8000/api/v1/status | jq '.'
```

### 2. Run Your First Scan
```bash
# Navigate to inventory service
cd backend/services/inventory-service/src

# Run AWS scan
python simplified_service_enablement_checker.py

# Or via API
curl -X POST http://localhost:8000/api/v1/inventory/scan
```

### 3. Access Monitoring
```bash
# Open Grafana dashboard
open http://localhost:3030
# Default credentials: admin/admin

# View Prometheus metrics
open http://localhost:9090

# Check Redis event bus
open http://localhost:8081
```

## 🎯 Next Steps

After successful installation:

1. **Configure your first scan** - See [Getting Started Guide](../getting-started/README.md)
2. **Set up multi-account scanning** - See [User Guide](../user-guide/multi-account-setup.md)
3. **Explore the API** - Visit http://localhost:8000/docs
4. **Configure compliance frameworks** - See [Compliance Guide](../compliance/README.md)
5. **Set up monitoring dashboards** - Access Grafana at http://localhost:3030

---

**Your LG-Protect platform is now ready for enterprise-grade cloud security posture management! 🚀**

For detailed usage instructions, continue to the [Getting Started Guide](../getting-started/README.md).