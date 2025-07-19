# Project Overview

## lg-protect

This repository contains tools and scripts for compliance checks, inventory management, and cloud security posture management (CSPM). The project is structured to provide a comprehensive solution for evaluating and maintaining security and compliance in cloud environments.

---

## 🚀 Quick Start - AWS Service Enablement Checker

### Prerequisites
- Python 3.7+
- AWS CLI configured with appropriate permissions
- boto3 library installed

### Installation
```bash
git clone https://github.com/anupyadav27/lg-protect.git
cd lg-protect
pip install boto3
```

### Basic Usage

#### 1. Run AWS Service Inventory Scan
```bash
cd inventory
python simplified_service_enablement_checker.py
```

This will:
- Scan all AWS services across all regions
- Detect actual resources and their identifiers
- Generate CSV reports with service enablement status
- Save results to `service_enablement_results/latest_scan/`

#### 2. Quick Validation Test
```bash
cd inventory/testing/quick_validation
python quick_validation_test.py
```

#### 3. Comprehensive Testing
```bash
cd inventory/testing/comprehensive
python comprehensive_testing.py
```

### Output Files
The scanner generates several files:
- **`account_service_inventory_YYYYMMDD_HHMMSS.csv`** - Main service inventory
- **`scan_session_reference_YYYYMMDD_HHMMSS.json`** - Scan metadata and statistics
- **`error_log_YYYYMMDD_HHMMSS.json`** - Any errors encountered during scanning

### Sample CSV Output
```csv
Account_ID,Account_Name,Region_Type,Region_Name,Service_Name,Service_Enabled,Resource_Count,Resource_Identifier_Type,Resource_Identifiers,Service_Scope
588989875114,primary,Global,global,s3,True,15,Name,my-bucket-1; my-bucket-2; lgtech-website,global
588989875114,primary,Regional,us-east-1,dynamodb,True,5,TableName,users; products; orders,regional
```

---

## 📁 Folder Structure

### inventory/ - AWS Service Enablement Checker
**Main Tool**: `simplified_service_enablement_checker.py` - Comprehensive AWS service discovery and inventory

**Key Features**:
- ✅ Real resource detection across 60+ AWS services
- 🌍 Multi-region scanning (17 regions)
- 📊 CSV export with hierarchical data structure
- 🔍 Detailed resource identification and counting
- ⚡ Optimized API calls with error handling

**Testing Framework**: `testing/`
- **`quick_validation/`** - Fast resource detection validation
- **`comprehensive/`** - Full system testing
- **`utility/`** - Service mapping maintenance tools

**Configuration**: 
- `service_enablement_mapping.json` - Service definitions and API mappings
- `error_analyzer.py` - Error analysis and reporting tools

### core-engine/
This folder contains the core logic for compliance checks and simulations.
- **compliance_checks.csv**: CSV file containing compliance check data.
- **compliance_checks.json**: JSON file containing compliance check data.
- **converter_csv-json.py**: Script to convert compliance data between CSV and JSON formats.
- **simulation_results.ipynb**: Jupyter notebook for simulating compliance scenarios.
- **compliance_rules/**: Contains JSON files defining various compliance rules.

### cspm/
This folder contains tools for Cloud Security Posture Management.
- **package.json**: Configuration file for CSPM platform.
- **README.md**: Documentation for CSPM platform.
- **cspm-platform/**: Contains CSPM platform-specific scripts and configurations.

### opa_evaluation_engine/
This folder contains the Open Policy Agent (OPA) evaluation engine.
- **config/**: Configuration files for OPA.
- **data/**: Data files used by OPA.
- **evaluations/**: Scripts for evaluating policies.
- **input_builder/**: Scripts for building input data for OPA.
- **opa/**: Core OPA engine files.

---

## 🎯 AWS Service Enablement Checker - Detailed Usage

### Understanding the Output

The AWS Service Enablement Checker provides a hierarchical view of your AWS infrastructure:

**Account Level**: Your AWS account information
**Region Level**: Global vs Regional services  
**Service Level**: Each AWS service's enablement status
**Resource Level**: Actual resources found with identifiers

### Supported AWS Services (60+)

**Global Services**:
- IAM, S3, CloudFront, Route53, Organizations, WAF, Shield

**Regional Services** (per region):
- Compute: EC2, Lambda, ECS, EKS, Auto Scaling
- Storage: EBS, EFS, FSx, S3 Glacier, Storage Gateway  
- Database: RDS, DynamoDB, ElastiCache, Redshift
- Networking: VPC, ELB, API Gateway, CloudFront
- Security: KMS, Secrets Manager, Security Hub, GuardDuty
- Analytics: Athena, Glue, Kinesis, EMR
- And many more...

### Testing Framework Usage

#### Quick Validation (Recommended for daily checks)
```bash
cd inventory/testing/quick_validation
python quick_validation_test.py
```
**Purpose**: Fast verification that resource detection is working
**Tests**: S3, DynamoDB, SQS, IAM, Lambda
**Output**: Timestamped results in `results/quick_validation_YYYYMMDD_HHMMSS/`

#### Comprehensive Testing (For thorough validation)  
```bash
cd inventory/testing/comprehensive
python comprehensive_testing.py
```
**Purpose**: Full system validation of all features
**Tests**: Multiple services, resource extraction, CSV generation
**Output**: Detailed results in `results/comprehensive_test_YYYYMMDD_HHMMSS/`

#### Utility Testing (For maintenance)
```bash
cd inventory/testing/utility  
python utility_testing.py
```
**Purpose**: Update service mappings with new regions
**Function**: Maintenance utility for service configuration
**Output**: Updated mapping files in `results/utility_test_YYYYMMDD_HHMMSS/`

### Advanced Configuration

**Custom Region Selection**: Edit the `regions` list in `simplified_service_enablement_checker.py`
**Service Selection**: Modify `service_enablement_mapping.json` to add/remove services
**Output Format**: Customize CSV headers and data structure in the main script

### Troubleshooting

**Common Issues**:
1. **Permission Errors**: Ensure your AWS credentials have read permissions for all services
2. **Rate Limiting**: The tool includes automatic retry logic for API throttling
3. **Region Availability**: Some services aren't available in all regions (handled automatically)

**Error Analysis**:
```bash
cd inventory
python error_analyzer.py
```

---

## Purpose

The purpose of this repository is to:
1. **AWS Infrastructure Discovery**: Comprehensive scanning and inventory of AWS resources
2. **Service Enablement Analysis**: Identify which AWS services are actively used vs just enabled
3. **Compliance Automation**: Automate compliance checks for cloud environments
4. **Security Posture Management**: Tools for evaluating and improving cloud security
5. **Policy Evaluation**: Enable policy evaluation using Open Policy Agent (OPA)

---

## 🏆 Key Benefits

### AWS Service Enablement Checker
- **Complete Visibility**: See all your AWS resources across all regions in one scan
- **Resource Identification**: Get actual resource names, not just service enablement status  
- **Time Efficient**: Scan 1000+ service/region combinations in ~60 seconds
- **Audit Ready**: Generate compliance-ready CSV reports
- **Cost Optimization**: Identify unused services that may incur costs

### Testing Framework
- **Quality Assurance**: Validate functionality before production scans
- **Historical Tracking**: Timestamped results show improvements over time
- **Multiple Test Types**: Quick validation, comprehensive testing, utility maintenance
- **Professional Structure**: Organized testing approach with clear documentation

---

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/anupyadav27/lg-protect.git
   cd lg-protect
   ```

2. Install dependencies:
   ```bash
   pip install boto3
   ```

3. Configure AWS credentials:
   ```bash
   aws configure
   ```

4. Run your first scan:
   ```bash
   cd inventory
   python simplified_service_enablement_checker.py
   ```

5. View results:
   ```bash
   ls service_enablement_results/latest_scan/
   ```

---

## 📚 Documentation

- **AWS Service Enablement Checker**: See `inventory/README.md`
- **Testing Framework**: See `inventory/testing/README.md`  
- **Core Engine**: See `core-engine/README.md`
- **CSPM Platform**: See `cspm/README.md`

---

## Contributions

Contributions are welcome! Please fork the repository and submit a pull request for any improvements or new features.

### Development Workflow
1. Test your changes using the testing framework
2. Update documentation if adding new features
3. Ensure all tests pass before submitting PR