# Getting Started with LG-Protect

Welcome to LG-Protect! This guide will help you set up and run your first security scan in under 10 minutes.

## Prerequisites

### System Requirements
- **Python**: 3.9 or higher
- **Operating System**: macOS, Linux, or Windows
- **Memory**: Minimum 4GB RAM (8GB recommended for enterprise scanning)
- **Disk Space**: 2GB free space for installation and scan results
- **Redis**: For event bus functionality (Docker recommended)

### AWS Requirements
- **AWS Account**: Active AWS account with resources to scan
- **AWS CLI**: Installed and configured
- **Permissions**: Read access to AWS services you want to scan

### Required AWS Permissions
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "iam:ListUsers",
                "iam:ListRoles",
                "dynamodb:ListTables",
                "lambda:ListFunctions",
                "rds:DescribeDBInstances",
                "cloudtrail:DescribeTrails",
                "cloudwatch:DescribeAlarms",
                "vpc:DescribeVpcs"
            ],
            "Resource": "*"
        }
    ]
}
```

## Quick Installation

### 1. Clone the Repository
```bash
git clone https://github.com/anupyadav27/lg-protect.git
cd lg-protect
```

### 2. Set Up Python Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Start Redis (Event Bus)
```bash
# Using Docker (recommended)
docker run -d --name redis -p 6379:6379 redis:latest

# Or using Docker Compose
cd infrastructure/docker-compose
docker-compose up -d redis
```

### 5. Configure AWS Credentials
```bash
aws configure
# Enter your AWS Access Key ID, Secret Access Key, and default region
```

### 6. Verify Installation
```bash
cd backend/services/inventory-service/src
python simplified_service_enablement_checker.py --help
```

## Your First Scan

### Option 1: Quick Single-Account Scan
```bash
cd backend/services/inventory-service/src
python simplified_service_enablement_checker.py
```

This will:
- Scan 60+ AWS services in your default account
- Discover actual resources across all regions
- Generate timestamped CSV reports with enhanced analytics
- Save results to `service_enablement_results/scan_YYYYMMDD_HHMMSS/`

### Option 2: Interactive Multi-Account Setup
```bash
cd backend/services/inventory-service/src
python simplified_service_enablement_checker.py --enterprise
```

Follow the interactive prompts to:
- Add multiple AWS accounts with 4 authentication methods
- Configure cross-account roles
- Set up AWS CLI profiles
- Customize scan parameters

### Option 3: Run with Docker Compose
```bash
cd infrastructure/docker-compose
docker-compose up -d
```

This will start:
- **Inventory Service** on port 3000
- **Compliance Service** on port 3001
- **Redis Event Bus** on port 6379
- **API Gateway** on port 8000 (if configured)

## Understanding Your Results

After the scan completes, you'll find these files in the results directory:

### 📊 Main Reports
- **`account_service_inventory_YYYYMMDD_HHMMSS.csv`** - Complete service inventory
- **`service_enablement_summary_YYYYMMDD_HHMMSS.json`** - Executive summary with statistics
- **`detailed_enablement_results_YYYYMMDD_HHMMSS.json`** - Full technical details
- **`error_analysis_YYYYMMDD_HHMMSS.json`** - Comprehensive error categorization

### 📈 Enhanced Quick Stats Example
```json
{
  "executive_summary": {
    "total_service_instances": 1024,
    "enabled_service_instances": 287,
    "overall_enablement_rate": 28.0,
    "total_resources_discovered": 1456,
    "unique_services": 42,
    "unique_regions": 17,
    "scan_performance": {
      "total_execution_time": "4.2 minutes",
      "api_calls_made": 3421,
      "success_rate": 94.2,
      "errors_by_category": {
        "access_denied": 12,
        "service_not_enabled": 8,
        "rate_limiting": 3
      }
    }
  }
}
```

### 📋 Enhanced CSV Output Sample
```csv
Account_ID,Account_Name,Region_Type,Region_Name,Service_Name,Service_Enabled,Resource_Count,Resource_Identifiers
123456789,production,Global,global,s3,True,15,my-bucket-1; my-bucket-2; logs-bucket
123456789,production,Regional,us-east-1,ec2,True,5,i-1234567890abcdef0; i-0987654321fedcba
123456789,production,Regional,us-east-1,dynamodb,True,3,users; products; sessions
123456789,production,Regional,us-east-1,lambda,True,12,user-processor; data-handler
```

## Event-Driven Real-Time Monitoring

### Start the Full Platform
```bash
# Start all services with event bus
cd infrastructure/docker-compose
docker-compose up -d

# Verify services are running
curl http://localhost:3000/health  # Inventory Service
curl http://localhost:3001/health  # Compliance Service
```

### Monitor Events in Real-Time
```bash
# Connect to Redis to see events
redis-cli monitor

# Or use the WebSocket endpoint (if API Gateway is running)
# Connect to ws://localhost:8000/ws/your-tenant-id
```

### Event Types You'll See
- **INVENTORY_DISCOVERED**: When AWS resources are found
- **COMPLIANCE_VIOLATION**: When compliance checks fail
- **ALERT_TRIGGERED**: When security alerts are generated
- **SCAN_COMPLETED**: When scans finish

## Next Steps

### 🔍 Explore Your Results
1. **Open the CSV file** in Excel or Google Sheets for analysis
2. **Review the summary JSON** for high-level insights
3. **Check error logs** if any services failed to scan
4. **Monitor Redis events** for real-time updates

### 🚀 Set Up Regular Scanning
- [Configure Multi-Account Scanning](../user-guide/multi-account-setup.md)
- [Set Up Automated Scans](../user-guide/automation.md)
- [Enable Real-time Monitoring](../user-guide/real-time-monitoring.md)

### 📋 Add Compliance Checking
```bash
# Start compliance service
cd backend/services/compliance-service
python -m pytest tests/ -v  # Verify all tests pass
python src/compliance_engine/check_aws/main.py
```

- [Enable SOC2 Compliance](../compliance/soc2.md)
- [Configure PCI-DSS Checks](../compliance/pci-dss.md)
- [Set Up HIPAA Validation](../compliance/hipaa.md)

### 🏢 Enterprise Setup
- [Deploy with Docker](../deployment/docker.md)
- [Kubernetes Deployment](../deployment/kubernetes.md)
- [Production Configuration](../deployment/production.md)

## Platform Architecture Overview

### Service Ports
- **Inventory Service**: 3000
- **Compliance Service**: 3001
- **Data Security Service**: 3002
- **Alert Engine**: 3003
- **Report Generator**: 3004
- **Redis Event Bus**: 6379
- **API Gateway**: 8000

### Event Flow
```
1. Start Inventory Scan → Publishes INVENTORY_DISCOVERED
2. Compliance Service Receives Event → Validates Resources
3. Violations Found → Publishes COMPLIANCE_VIOLATION
4. Alert Engine Receives Event → Generates Alerts
5. Real-time Updates → WebSocket to UI
```

## Troubleshooting

### Common Issues

#### Redis Connection Errors
```bash
# Check Redis is running
docker ps | grep redis

# Start Redis if not running
docker run -d --name redis -p 6379:6379 redis:latest
```

#### Permission Denied Errors
```bash
# Check your AWS credentials
aws sts get-caller-identity

# Verify permissions
aws iam get-user

# Test with specific service
aws ec2 describe-instances --region us-east-1
```

#### No Resources Found
- Ensure you're scanning the correct regions
- Verify your account has actual AWS resources
- Check that services are enabled in your account

#### Scan Takes Too Long
- Use `--max-workers 5` to reduce concurrent API calls
- Scan specific services with `--services ec2,s3,iam`
- Limit regions with `--regions us-east-1,us-west-2`

#### Event Bus Not Working
```bash
# Check Redis connection
redis-cli ping

# Verify event publishing
redis-cli monitor
# Then run a scan in another terminal
```

### Service Health Checks
```bash
# Check all services
curl http://localhost:3000/health  # Inventory
curl http://localhost:3001/health  # Compliance
curl http://localhost:3002/health  # Data Security
curl http://localhost:3003/health  # Alert Engine
```

### Getting Help
- [FAQ](../faq/) - Common questions and solutions
- [Troubleshooting Guide](../user-guide/troubleshooting.md) - Detailed problem resolution
- [Support](../user-guide/support.md) - How to get help

## What's Next?

Now that you've completed your first scan, you're ready to:

1. **[Learn the User Guide](../user-guide/README.md)** - Master all features
2. **[Understand the Architecture](../architecture/README.md)** - Learn the event-driven design
3. **[Explore APIs](../api/README.md)** - Integrate with other tools
4. **[Deploy at Scale](../deployment/README.md)** - Production deployment
5. **[Set Up Compliance](../compliance/README.md)** - Configure compliance frameworks

## Platform Features

### ✅ Current Capabilities
- **60+ AWS Services**: Comprehensive coverage across all regions
- **Multi-Account Support**: 4 authentication methods
- **Event-Driven Architecture**: Real-time processing with Redis
- **Compliance Frameworks**: SOC2, PCI-DSS, HIPAA, CIS, NIST
- **Advanced Error Handling**: Intelligent error categorization
- **Real-time Monitoring**: WebSocket-based live updates

### 🔥 Recent Updates (July 2025)
- **Restructured Compliance Service**: Clean folder organization
- **Event Bus Integration**: Redis-based real-time events
- **Enhanced Multi-Account**: Enterprise-grade account management
- **BaseCheck Framework**: Standardized compliance checking
- **Advanced Analytics**: Comprehensive error analysis

Welcome to the LG-Protect community! 🚀

*Platform Version: 2.1.0*
*Event Bus: Fully Operational*
*All Services: Production Ready*