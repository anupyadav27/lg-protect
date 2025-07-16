# Tutorials and Guides

Step-by-step tutorials for common LG-Protect use cases and workflows.

## 🎯 Quick Navigation

### 🚀 Getting Started Tutorials
- [**Your First AWS Scan**](#tutorial-1-your-first-aws-scan) - 5 minutes
- [**Understanding Scan Results**](#tutorial-2-understanding-scan-results) - 10 minutes
- [**Setting Up Multi-Account Scanning**](#tutorial-3-multi-account-scanning) - 20 minutes

### 🏢 Enterprise Tutorials
- [**Enterprise Multi-Account Setup**](#tutorial-4-enterprise-multi-account-setup) - 30 minutes
- [**Cross-Account IAM Role Configuration**](#tutorial-5-cross-account-iam-roles) - 15 minutes
- [**Automated Compliance Reporting**](#tutorial-6-automated-compliance-reporting) - 25 minutes

### 🔧 Advanced Tutorials
- [**Custom Service Discovery**](#tutorial-7-custom-service-discovery) - 45 minutes
- [**Real-time Event Monitoring**](#tutorial-8-real-time-event-monitoring) - 20 minutes
- [**Performance Optimization**](#tutorial-9-performance-optimization) - 30 minutes

### 🚀 Deployment Tutorials
- [**Docker Production Deployment**](#tutorial-10-docker-production-deployment) - 40 minutes
- [**Kubernetes Cluster Deployment**](#tutorial-11-kubernetes-deployment) - 60 minutes
- [**AWS EKS Enterprise Setup**](#tutorial-12-aws-eks-enterprise-setup) - 90 minutes

---

## Tutorial 1: Your First AWS Scan

**Goal**: Run your first comprehensive AWS security scan in 5 minutes.

### Prerequisites
- AWS account with resources
- AWS CLI configured
- Python 3.7+ installed

### Step 1: Quick Installation
```bash
# Clone and enter the repository
git clone https://github.com/anupyadav27/lg-protect.git
cd lg-protect

# Install dependencies
pip install boto3 structlog
```

### Step 2: Verify AWS Access
```bash
# Check your AWS credentials
aws sts get-caller-identity

# Expected output:
{
    "UserId": "AIDACKCEVSQ6C2EXAMPLE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/your-username"
}
```

### Step 3: Run Your First Scan
```bash
# Navigate to the inventory service
cd backend/services/inventory-service/src

# Run the simplified service enablement checker
python simplified_service_enablement_checker.py
```

### Step 4: Monitor Scan Progress
You'll see real-time progress output:
```
🚀 LG-Protect AWS Service Enablement Checker
📊 Scanning Account: 123456789012
🌍 Regions: us-east-1, us-west-2, eu-west-1...

✅ EC2 (us-east-1): 8 instances discovered
✅ S3 (global): 15 buckets discovered  
✅ RDS (us-east-1): 3 databases discovered
⚠️  Lambda (us-west-2): Permission denied
✅ IAM (global): 25 users, 12 roles discovered

📋 Scan Complete! Results saved to: service_enablement_results/scan_20250712_143022/
```

### Step 5: Review Your Results
```bash
# Check the results directory
ls service_enablement_results/latest_scan/

# Files created:
account_service_inventory_20250712_143022.csv
service_enablement_summary_20250712_143022.json
error_analysis_20250712_143022.json

# Quick summary view
cat service_enablement_results/latest_scan/service_enablement_summary_*.json | jq '.executive_summary'
```

### Step 6: Open Results in Excel
```bash
# Copy the CSV file to your desktop for analysis
cp service_enablement_results/latest_scan/account_service_inventory_*.csv ~/Desktop/
```

Open the CSV file in Excel or Google Sheets to see your complete AWS inventory with:
- Account and service breakdown
- Resource counts per service
- Actual resource identifiers
- Global vs regional service distribution

**🎉 Congratulations!** You've completed your first AWS security scan.

**Next Steps**: Try [Tutorial 2: Understanding Scan Results](#tutorial-2-understanding-scan-results)

---

## Tutorial 2: Understanding Scan Results

**Goal**: Learn to interpret and analyze your AWS scan results effectively.

### Result File Types

#### 1. Account Service Inventory CSV
**Purpose**: Comprehensive spreadsheet-ready data
**Best for**: Analysis, reporting, sharing with teams

```csv
Account_ID,Account_Name,Region_Type,Region_Name,Service_Name,Service_Enabled,Resource_Count,Resource_Identifiers
123456789,primary,Global,global,s3,True,15,my-bucket-1; my-bucket-2; logs-bucket
123456789,primary,Regional,us-east-1,ec2,True,8,i-1234567890abcdef0; i-0987654321fedcba
123456789,primary,Regional,us-east-1,dynamodb,True,3,users; products; sessions
```

**Key Columns**:
- **Region_Type**: Global (IAM, S3) vs Regional (EC2, RDS) services
- **Service_Enabled**: Whether the service has discoverable resources
- **Resource_Count**: Number of actual resources found
- **Resource_Identifiers**: Actual resource names/IDs (semicolon-separated)

#### 2. Executive Summary JSON
**Purpose**: High-level insights and statistics
**Best for**: Dashboards, executive reporting

```json
{
  "executive_summary": {
    "total_service_instances": 156,
    "enabled_service_instances": 42,
    "overall_enablement_rate": 26.9,
    "total_resources_discovered": 287,
    "unique_services": 15,
    "unique_regions": 4,
    "scan_duration": "4.2 minutes"
  },
  "service_breakdown": {
    "compute": {"services": 5, "resources": 45},
    "storage": {"services": 4, "resources": 89},
    "database": {"services": 3, "resources": 12},
    "security": {"services": 6, "resources": 67}
  }
}
```

### Analyzing Your Results

#### Step 1: Quick Health Check
```bash
# Get overall statistics
jq '.executive_summary' service_enablement_results/latest_scan/service_enablement_summary_*.json

# Check for any critical errors
jq '.error_summary' service_enablement_results/latest_scan/error_analysis_*.json
```

#### Step 2: Identify Your Largest Services
```bash
# Sort CSV by resource count (requires csvkit)
csvstat --max "Resource_Count" account_service_inventory_*.csv

# Or manually check in Excel:
# - Sort by Resource_Count column (descending)
# - Look for services with highest resource counts
```

### Common Patterns and What They Mean

#### Pattern 1: High S3 Bucket Count
```csv
123456789,primary,Global,global,s3,True,45,bucket1; bucket2; logs-bucket...
```
**Meaning**: Lots of data storage, check for:
- Public buckets (security risk)
- Unencrypted buckets
- Lifecycle policies for cost optimization

#### Pattern 2: Many EC2 Instances in One Region
```csv
123456789,primary,Regional,us-east-1,ec2,True,67,i-1234; i-5678...
```
**Meaning**: Compute concentration, consider:
- Multi-region disaster recovery
- Right-sizing for cost optimization
- Security group configurations

### Creating Executive Reports

#### Step 1: Calculate Key Metrics
```python
import pandas as pd
import json

# Load your scan data
df = pd.read_csv('account_service_inventory_*.csv')

# Calculate metrics
total_resources = df['Resource_Count'].sum()
enabled_services = len(df[df['Service_Enabled'] == True])
total_services = len(df)

print(f"Total Resources: {total_resources}")
print(f"Service Utilization: {enabled_services}/{total_services} ({enabled_services/total_services*100:.1f}%)")
```

### Troubleshooting Common Issues

#### Issue 1: Many "Access Denied" Errors
**Solution**: Update your IAM permissions
```bash
# Check what permissions you have
aws iam get-user-policy --user-name your-username --policy-name your-policy

# Add missing permissions for services showing access denied
```

#### Issue 2: No Resources Found for Known Services
**Possible Causes**:
- Service not available in scanned region
- Resources exist but with different names than expected
- Service requires special permissions

**🎉 Tutorial Complete!** You can now effectively analyze your AWS scan results.

**Next Steps**: Try [Tutorial 3: Multi-Account Scanning](#tutorial-3-multi-account-scanning)

---

## Tutorial 3: Multi-Account Scanning

**Goal**: Set up scanning across multiple AWS accounts for enterprise visibility.

### Prerequisites
- Multiple AWS accounts to scan
- Appropriate permissions in each account
- Understanding of AWS IAM roles (recommended)

### Authentication Methods Overview

LG-Protect supports 4 authentication methods:

1. **AWS CLI Profiles** - Easiest for existing setups
2. **Access Key Pairs** - Direct credential access
3. **Cross-Account IAM Roles** - Most secure for enterprise
4. **Mixed Authentication** - Combination approach

### Method 1: AWS CLI Profiles (Recommended for Small Teams)

#### Step 1: Configure AWS Profiles
```bash
# Configure profiles for each account
aws configure --profile production
# Enter production account credentials

aws configure --profile development  
# Enter development account credentials

aws configure --profile staging
# Enter staging account credentials

# Test each profile
aws sts get-caller-identity --profile production
aws sts get-caller-identity --profile development
aws sts get-caller-identity --profile staging
```

#### Step 2: Run Multi-Account Scan
```bash
cd backend/services/inventory-service/src
python simplified_service_enablement_checker.py --enterprise --profiles production,development,staging
```

### Method 2: Cross-Account IAM Roles (Recommended for Enterprise)

#### Step 1: Create Cross-Account Role in Each Target Account

**In Production Account (123456789012):**
```bash
# Create trust policy for your audit account
cat > trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::AUDIT-ACCOUNT-ID:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "unique-external-id-prod-123"
        }
      }
    }
  ]
}
EOF

# Create the role
aws iam create-role \
  --role-name LGProtectAuditRole \
  --assume-role-policy-document file://trust-policy.json

# Attach read-only permissions
aws iam attach-role-policy \
  --role-name LGProtectAuditRole \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# Get the role ARN for configuration
aws iam get-role --role-name LGProtectAuditRole --query 'Role.Arn'
```

#### Step 2: Run Enterprise Scan
```bash
cd backend/services/inventory-service/src
python simplified_service_enablement_checker.py --enterprise --use-roles
```

### Understanding Multi-Account Results

#### Result Structure
```
service_enablement_results/enterprise_scan_20250712_143022/
├── enterprise_summary_20250712_143022.json          # Overall summary
├── account_123456789_production_20250712_143022.csv # Production account
├── account_234567890_development_20250712_143022.csv # Development account  
├── account_345678901_staging_20250712_143022.csv    # Staging account
├── enterprise_consolidated_20250712_143022.csv      # All accounts combined
└── cross_account_analysis_20250712_143022.json      # Cross-account insights
```

### Cross-Account Analysis

#### Resource Distribution
```bash
# Analyze resource distribution across accounts
python -c "
import pandas as pd
df = pd.read_csv('enterprise_consolidated_*.csv')
print(df.groupby('Account_Name')['Resource_Count'].sum().sort_values(ascending=False))
"

# Output:
# Account_Name
# Production     892
# Development    234  
# Staging        121
```

### Best Practices for Multi-Account Scanning

#### 1. Security Best Practices
```bash
# Use unique external IDs for each account
EXTERNAL_ID="lg-protect-$(openssl rand -hex 16)"
echo "External ID for this account: $EXTERNAL_ID"

# Rotate external IDs regularly
# Document all cross-account roles
# Use least-privilege permissions
```

### Troubleshooting Multi-Account Issues

#### Issue 1: "AssumeRole Failed"
```bash
# Check role ARN and external ID
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT:role/LGProtectAuditRole \
  --role-session-name test \
  --external-id your-external-id

# Common fixes:
# 1. Verify external ID matches exactly
# 2. Check trust policy allows your account
# 3. Ensure role has necessary permissions
```

**🎉 Tutorial Complete!** You can now scan multiple AWS accounts efficiently.

**Next Steps**: Try [Tutorial 4: Enterprise Multi-Account Setup](#tutorial-4-enterprise-multi-account-setup) for advanced configurations.

---

*Additional tutorials for Docker deployment, Kubernetes setup, compliance reporting, and advanced configurations are available in the respective documentation sections.*