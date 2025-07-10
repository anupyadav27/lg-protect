# AWS Service Enablement Checker

A comprehensive AWS infrastructure discovery tool that scans all services across all regions to provide detailed resource inventory and service enablement status.

## 🎯 Overview

This tool goes beyond simple service enablement checks - it discovers **actual resources** and their identifiers, providing a complete picture of your AWS infrastructure usage.

### Key Features
- ✅ **Real Resource Detection**: Finds actual resources, not just enabled services
- 🌍 **Multi-Region Coverage**: Scans 17 AWS regions automatically
- 📊 **Structured Output**: Hierarchical CSV format for easy analysis
- 🔍 **60+ AWS Services**: Comprehensive coverage of major AWS services
- ⚡ **Fast Execution**: Complete scan in ~60 seconds
- 🛡️ **Error Handling**: Robust error handling with detailed logging

## 🚀 Quick Start

### Prerequisites
```bash
pip install boto3
aws configure  # Ensure AWS credentials are configured
```

### Basic Usage
```bash
cd inventory
python simplified_service_enablement_checker.py
```

### Output Files
Results are saved to `service_enablement_results/latest_scan/`:
- `account_service_inventory_YYYYMMDD_HHMMSS.csv` - Main inventory report
- `scan_session_reference_YYYYMMDD_HHMMSS.json` - Scan metadata and statistics

## 📊 Understanding the Output

### CSV Structure
The output follows a hierarchical structure:
```
Account → Region Type → Region → Service → Resources
```

### Sample Output
```csv
Account_ID,Account_Name,Region_Type,Region_Name,Service_Name,Service_Enabled,Resource_Count,Resource_Identifier_Type,Resource_Identifiers,Service_Scope
588989875114,primary,Global,global,s3,True,15,Name,lgtech-website; www.lgtech.in; aws-codestar-bucket,global
588989875114,primary,Regional,us-east-1,dynamodb,True,15,TableName,users; products; orders; audit_logs,regional
588989875114,primary,Regional,us-east-1,lambda,True,2,FunctionName,chatbot; data-processor,regional
```

### Column Definitions
- **Account_ID**: AWS Account ID
- **Account_Name**: Friendly account name (default: "primary")
- **Region_Type**: "Global" or "Regional"
- **Region_Name**: AWS region name (e.g., "us-east-1") or "global"
- **Service_Name**: AWS service name (e.g., "s3", "dynamodb")
- **Service_Enabled**: Boolean indicating if service has resources
- **Resource_Count**: Number of resources found
- **Resource_Identifier_Type**: Type of identifier used (e.g., "Name", "TableName")
- **Resource_Identifiers**: Semicolon-separated list of resource identifiers
- **Service_Scope**: "global" or "regional"

## 🔧 Supported AWS Services

### Global Services
- **IAM**: Users, roles, policies
- **S3**: Buckets
- **CloudFront**: Distributions
- **Route53**: Hosted zones
- **Organizations**: Account organization
- **WAF**: Web ACLs
- **Shield**: DDoS protection

### Regional Services (per region)

#### Compute
- **EC2**: Instances
- **Lambda**: Functions
- **ECS**: Clusters
- **EKS**: Kubernetes clusters
- **Auto Scaling**: Auto scaling groups

#### Storage
- **EBS**: Volumes
- **EFS**: File systems
- **FSx**: File systems
- **S3 Glacier**: Vaults
- **Storage Gateway**: Gateways

#### Database
- **RDS**: Database instances
- **DynamoDB**: Tables
- **ElastiCache**: Cache clusters
- **Redshift**: Data warehouse clusters

#### Networking
- **API Gateway**: REST APIs
- **ELB/ALB**: Load balancers
- **VPC Lattice**: Service networks

#### Security
- **KMS**: Encryption keys
- **Secrets Manager**: Secrets
- **Security Hub**: Security standards
- **GuardDuty**: Threat detection

#### Analytics & ML
- **Athena**: Query workgroups
- **Glue**: Data catalogs
- **Kinesis**: Data streams
- **EMR**: Big data clusters
- **SageMaker**: ML notebooks
- **Comprehend**: NLP resources
- **Rekognition**: Image analysis
- **Polly**: Text-to-speech voices
- **Transcribe**: Speech-to-text jobs
- **Translate**: Translation jobs
- **Textract**: Document analysis

#### Management & Monitoring
- **CloudFormation**: Stacks
- **CloudTrail**: Audit trails
- **CloudWatch**: Metrics and logs
- **Config**: Configuration recorders
- **SSM**: Systems Manager
- **Backup**: Backup vaults

#### Developer Tools
- **CodeBuild**: Build projects
- **CodePipeline**: CI/CD pipelines

#### Application Services
- **SNS**: Topics
- **SQS**: Queues
- **Step Functions**: State machines
- **EventBridge**: Event rules

## 🧪 Testing Framework

### Quick Validation
Fast verification that resource detection is working:
```bash
cd testing/quick_validation
python quick_validation_test.py
```

### Comprehensive Testing
Full system validation:
```bash
cd testing/comprehensive
python comprehensive_testing.py
```

### Utility Testing
Maintenance and service mapping updates:
```bash
cd testing/utility
python utility_testing.py
```

All tests save timestamped results for tracking improvements over time.

## ⚙️ Configuration

### Service Mapping
Edit `service_enablement_mapping.json` to:
- Add new AWS services
- Modify API endpoints
- Update resource extraction logic
- Add region-specific configurations

### Custom Regions
Modify the `regions` list in the main script to scan specific regions:
```python
regions = ['us-east-1', 'us-west-2', 'eu-west-1']  # Custom region list
```

## 🔍 Error Analysis

### Error Analyzer Tool
```bash
python error_analyzer.py
```

Analyzes common error patterns and provides solutions for:
- Permission issues
- API throttling
- Service availability
- Region-specific limitations

### Common Issues & Solutions

#### Permission Errors
Ensure your AWS credentials have read permissions for all services:
```bash
aws iam list-attached-user-policies --user-name your-username
```

#### Rate Limiting
The tool includes automatic retry logic, but for high-usage accounts:
- Run during off-peak hours
- Use IAM roles with appropriate rate limits

#### Region Availability
Some services aren't available in all regions (handled automatically):
- Check AWS service availability by region
- Tool skips unavailable services gracefully

## 📈 Performance Metrics

### Typical Scan Results
- **API Calls**: ~944 calls across all services and regions
- **Success Rate**: 93-95% (varies by account configuration)
- **Execution Time**: 60-90 seconds
- **Services Covered**: 60+ AWS services
- **Regions Scanned**: 17 AWS regions

### Resource Detection Examples
Based on real scan results:
- **S3**: 15 buckets detected with actual names
- **DynamoDB**: 15 tables in us-east-1 with table names
- **Lambda**: Multiple functions across regions with function names
- **KMS**: Encryption keys with key IDs
- **IAM**: 5 users with usernames

## 🛠️ Advanced Usage

### Programmatic Access
```python
from simplified_service_enablement_checker import ServiceEnablementChecker

checker = ServiceEnablementChecker()
results = checker.scan_all_services()
checker.save_results(results)
```

### Custom Output Formats
Modify the CSV writer section to add custom columns or change formatting.

### Integration with Other Tools
The CSV output can be easily imported into:
- Excel/Google Sheets for analysis
- Business intelligence tools
- Compliance reporting systems
- Cost optimization tools

## 📝 Changelog

### Latest Improvements
- ✅ Enhanced resource detection for all services
- ✅ Improved error handling and retry logic
- ✅ Professional testing framework
- ✅ Timestamped result tracking
- ✅ Better CSV structure with hierarchical data

### Previous Versions
- Basic service enablement checking
- Limited resource detection
- Simple error logging

## 🤝 Contributing

1. Test changes using the testing framework
2. Update service mapping for new services
3. Document any new features
4. Ensure all tests pass

## 📚 Additional Resources

- **AWS Service Documentation**: [AWS Docs](https://docs.aws.amazon.com/)
- **Boto3 Documentation**: [Boto3 Docs](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- **Testing Framework**: See `testing/README.md`