# Inventory-Compliance Integration Bridge

This bridge integrates AWS service inventory discovery with compliance validation using your existing ComplianceEngine architecture.

## 🏗️ Architecture Overview

```
inventory_compliance_bridge/
├── __init__.py                          # Package initialization
├── compliance_function_registry.py      # Registry of all compliance functions
├── inventory_compliance_integration.py  # Main orchestrator
├── main_runner.py                      # CLI interface and entry points
├── results/                            # Output directory for results
└── README.md                          # This file
```

## 🔄 Integration Flow

1. **Inventory Discovery** → Reads service inventory from discovery module
2. **Service Mapping** → Maps enabled services to compliance functions
3. **Resource Identification** → Extracts resource identifiers per service
4. **Compliance Execution** → Runs functions using existing ComplianceEngine
5. **Results Aggregation** → Combines findings with scoring and analytics

## 🚀 Quick Start

### Basic Usage

```python
# Run with defaults (auto-detect inventory)
from inventory_compliance_bridge import run_with_defaults
results = run_with_defaults()
```

### Command Line Usage

```bash
# Run with default settings
python main_runner.py

# Run with specific inventory file
python main_runner.py --file /path/to/inventory.json

# Run interactively
python main_runner.py --interactive

# Filter by services
python main_runner.py --services s3,ec2 --profile my-profile

# List available compliance functions
python main_runner.py --list-functions

# Run tests
python main_runner.py --test --quick
```

## 📋 Available Compliance Functions

### S3 Functions
- `check_s3_bucket_encryption` - Verifies S3 bucket encryption
- `check_s3_bucket_public_access` - Checks public access configuration
- `check_s3_bucket_versioning` - Validates versioning settings
- `check_s3_bucket_ssl_requests_only` - Ensures SSL-only requests

### EC2 Functions
- `check_ec2_security_groups` - Validates security group rules
- `check_ec2_ebs_encryption` - Checks EBS volume encryption
- `check_ec2_instances_in_vpc` - Ensures instances are in VPC

### RDS Functions
- `check_rds_encryption` - Validates encryption at rest
- `check_rds_backup_enabled` - Checks backup configuration
- `check_rds_public_access` - Validates public accessibility

### IAM Functions
- `check_iam_password_policy` - Validates password policy
- `check_iam_mfa_enabled` - Checks MFA enablement

### Lambda Functions
- `check_lambda_function_public_access` - Checks public access
- `check_lambda_runtime_supported` - Validates runtime versions

## 🎯 Execution Modes

### 1. Default Mode
Automatically detects inventory file in standard locations:
- `/Users/apple/Desktop/lg-protect/inventory/service_enablement_results/account_service_inventory.json`
- `/Users/apple/Desktop/lg-protect/account_service_inventory.json`

### 2. File Mode
Run with specific inventory file:
```python
from inventory_compliance_bridge import run_from_inventory_file
results = run_from_inventory_file('/path/to/inventory.json')
```

### 3. Data Mode
Run with pre-loaded inventory data:
```python
from inventory_compliance_bridge import run_from_inventory_data
results = run_from_inventory_data(my_inventory_dict)
```

### 4. Interactive Mode
Guided CLI experience with prompts for all options.

## 🔧 Configuration Options

### Service Filtering
Run compliance only for specific services:
```python
integration = InventoryComplianceIntegration()
results = integration.run_inventory_compliance_validation(
    services_filter=['s3', 'ec2']
)
```

### Function Filtering
Run only specific compliance functions:
```python
results = integration.run_inventory_compliance_validation(
    functions_filter=['check_s3_bucket_encryption', 'check_ec2_security_groups']
)
```

### AWS Profile Selection
Use specific AWS profile:
```python
integration = InventoryComplianceIntegration(profile_name='my-profile')
```

## 📊 Output Structure

```json
{
  "metadata": {
    "account_id": "123456789012",
    "account_name": "production-account",
    "compliance_timestamp": "2025-07-05T10:30:00Z",
    "profile_used": "default"
  },
  "execution_summary": {
    "total_services_found": 5,
    "services_with_compliance": 4,
    "total_functions_executed": 12,
    "total_resources_checked": 25,
    "overall_compliance_score": 85.5
  },
  "service_results": {
    "s3": {
      "resource_count": 4,
      "total_findings": 8,
      "compliance_score": 75.0,
      "function_executions": [...]
    }
  },
  "all_findings": [...],
  "execution_errors": [...]
}
```

## 🧪 Testing

### Quick Test
```bash
python main_runner.py --test --quick
```

### Comprehensive Test
```bash
python main_runner.py --test
```

### Programmatic Testing
```python
from inventory_compliance_bridge import quick_test_integration
success = quick_test_integration()
```

## 🔗 Integration with Existing Engine

This bridge leverages your existing `ComplianceEngine` architecture:

1. **Reuses** existing session management
2. **Integrates** with existing error handling
3. **Extends** existing account management
4. **Maintains** existing result structures

## 📁 Expected Inventory Format

```json
{
  "account_id": "123456789012",
  "account_name": "my-account",
  "discovery_timestamp": "2025-07-05T10:30:00Z",
  "services": {
    "s3": {
      "enabled": true,
      "regions": ["us-east-1", "us-west-2"],
      "identifiers": ["bucket1", "bucket2", "bucket3"]
    },
    "ec2": {
      "enabled": true,
      "regions": ["us-east-1"],
      "identifiers": ["i-1234567890abcdef0"]
    }
  }
}
```

## 🚨 Error Handling

The integration provides comprehensive error handling:

- **Service Level**: Errors for entire services
- **Function Level**: Errors for specific compliance functions
- **Resource Level**: Errors for individual resources
- **Graceful Degradation**: Continues execution despite errors

## 📈 Compliance Scoring

- **Resource Level**: Each resource gets a compliance status
- **Function Level**: Aggregated from resource results
- **Service Level**: Percentage of compliant findings
- **Overall Score**: Weighted average across all services

## 🔄 Workflow Example

```python
# 1. Initialize integration
from inventory_compliance_bridge import InventoryComplianceIntegration

integration = InventoryComplianceIntegration(
    inventory_path='/path/to/inventory.json',
    profile_name='production'
)

# 2. Run compliance validation
results = integration.run_inventory_compliance_validation(
    services_filter=['s3', 'rds'],
    functions_filter=['check_s3_bucket_encryption']
)

# 3. Save results
integration.save_results(results, 'my_compliance_results.json')

# 4. Analyze results
print(f"Compliance Score: {results['execution_summary']['overall_compliance_score']:.1f}%")
print(f"Total Findings: {len(results['all_findings'])}")
```

## 🤝 Benefits

✅ **Seamless Integration** - Works with existing ComplianceEngine  
✅ **Flexible Input** - Multiple inventory sources supported  
✅ **Comprehensive Testing** - Built-in test suite  
✅ **Rich Output** - Detailed findings and analytics  
✅ **Error Resilience** - Graceful error handling  
✅ **CLI Support** - Easy command-line usage  
✅ **Extensible** - Easy to add new compliance functions  

## 🎛️ Advanced Usage

### Custom Compliance Functions
Add new compliance functions to the registry:

```python
registry = ComplianceFunctionRegistry()

# Add custom function
def my_custom_check(resource_identifiers):
    def compliance_check(client, region, account_name, logger):
        # Your compliance logic here
        return findings
    return compliance_check

registry.functions['my_custom_check'] = {
    'service': 'myservice',
    'category': 'security',
    'severity': 'HIGH',
    'function': my_custom_check
}
```

### Batch Processing
Process multiple accounts:

```python
accounts = ['account1.json', 'account2.json', 'account3.json']
for account_file in accounts:
    results = run_from_inventory_file(account_file)
    # Process results...
```

This integration bridge provides a robust, flexible way to connect your inventory discovery with compliance validation while maintaining compatibility with your existing architecture!