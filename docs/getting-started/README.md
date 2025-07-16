# Getting Started with LG-Protect

Welcome to LG-Protect! This guide will help you set up and run your first security scan in under 10 minutes.

## Prerequisites

### System Requirements
- **Python**: 3.7 or higher
- **Operating System**: macOS, Linux, or Windows
- **Memory**: Minimum 4GB RAM (8GB recommended for enterprise scanning)
- **Disk Space**: 2GB free space for installation and scan results

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
                "rds:DescribeDBInstances"
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

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure AWS Credentials
```bash
aws configure
# Enter your AWS Access Key ID, Secret Access Key, and default region
```

### 4. Verify Installation
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
- Scan all AWS services in your default account
- Discover actual resources across all regions
- Generate timestamped CSV reports
- Save results to `service_enablement_results/scan_YYYYMMDD_HHMMSS/`

### Option 2: Interactive Multi-Account Setup
```bash
cd backend/services/inventory-service/src
python simplified_service_enablement_checker.py --enterprise
```

Follow the interactive prompts to:
- Add multiple AWS accounts
- Configure cross-account roles
- Set up AWS CLI profiles
- Customize scan parameters

## Understanding Your Results

After the scan completes, you'll find these files in the results directory:

### 📊 Main Reports
- **`account_service_inventory_YYYYMMDD_HHMMSS.csv`** - Complete service inventory
- **`service_enablement_summary_YYYYMMDD_HHMMSS.json`** - Executive summary with statistics
- **`detailed_enablement_results_YYYYMMDD_HHMMSS.json`** - Full technical details

### 📈 Quick Stats Example
```json
{
  "executive_summary": {
    "total_service_instances": 156,
    "enabled_service_instances": 42,
    "overall_enablement_rate": 26.9,
    "total_resources_discovered": 287,
    "unique_services": 15,
    "unique_regions": 4
  }
}
```

### 📋 CSV Output Sample
```csv
Account_ID,Service_Name,Region_Name,Enabled,Resource_Count,Resource_Identifiers
123456789,s3,global,True,15,my-bucket-1; my-bucket-2; logs-bucket
123456789,ec2,us-east-1,True,5,i-1234567890abcdef0; i-0987654321fedcba
123456789,dynamodb,us-east-1,True,3,users; products; sessions
```

## Next Steps

### 🔍 Explore Your Results
1. **Open the CSV file** in Excel or Google Sheets for analysis
2. **Review the summary JSON** for high-level insights
3. **Check error logs** if any services failed to scan

### 🚀 Set Up Regular Scanning
- [Configure Multi-Account Scanning](../user-guide/multi-account-setup.md)
- [Set Up Automated Scans](../user-guide/automation.md)
- [Enable Real-time Monitoring](../user-guide/real-time-monitoring.md)

### 📋 Add Compliance Checking
- [Enable SOC2 Compliance](../compliance/soc2.md)
- [Configure PCI-DSS Checks](../compliance/pci-dss.md)
- [Set Up HIPAA Validation](../compliance/hipaa.md)

### 🏢 Enterprise Setup
- [Deploy with Docker](../deployment/docker.md)
- [Kubernetes Deployment](../deployment/kubernetes.md)
- [Production Configuration](../deployment/production.md)

## Troubleshooting

### Common Issues

#### Permission Denied Errors
```bash
# Check your AWS credentials
aws sts get-caller-identity

# Verify permissions
aws iam get-user
```

#### No Resources Found
- Ensure you're scanning the correct regions
- Verify your account has actual AWS resources
- Check that services are enabled in your account

#### Scan Takes Too Long
- Use `--max-workers 5` to reduce concurrent API calls
- Scan specific services with `--services ec2,s3,iam`
- Limit regions with `--regions us-east-1,us-west-2`

### Getting Help
- [FAQ](../faq/) - Common questions and solutions
- [Troubleshooting Guide](../user-guide/troubleshooting.md) - Detailed problem resolution
- [Support](../user-guide/support.md) - How to get help

## What's Next?

Now that you've completed your first scan, you're ready to:

1. **[Learn the User Guide](../user-guide/README.md)** - Master all features
2. **[Understand the Architecture](../architecture/README.md)** - Learn how it works
3. **[Explore APIs](../api/README.md)** - Integrate with other tools
4. **[Deploy at Scale](../deployment/README.md)** - Production deployment

Welcome to the LG-Protect community! 🚀