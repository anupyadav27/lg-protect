# Compliance Engine - Service Onboarding Guide

This guide is the **single source of truth** for onboarding new AWS services into the compliance engine. 

## 🚀 Quick Start (For New Services)

**If you've already added a new service folder under `checks/`, just tell me:**
> "I have added a new services folder for XYZ under checks folder. Please make the enhancement in code as per other services without losing functionality and make sure it perfectly integrated with our current architecture and reporting."

**I will automatically:**
1. ✅ Analyze your new service structure
2. ✅ Create the service client and functions
3. ✅ Add it to the scan runners
4. ✅ Integrate with hierarchical reporting
5. ✅ Test the integration
6. ✅ Update documentation

---

## 📋 Manual Onboarding Process (If Needed)

## 📋 Prerequisites

- AWS credentials configured
- Python virtual environment activated
- Understanding of the target AWS service
- Compliance requirements for the service

## 🔄 Automatic Integration Process

When you add a new service folder, the system will automatically:

### **1. Service Structure Analysis**
```
checks/{new_service}/
├── {new_service}_client.py           # ✅ Auto-generated
├── {new_service}_service.py          # ✅ Auto-generated (if needed)
└── {check_name}/                     # ✅ Your compliance checks
    ├── {check_name}.py
    └── {check_name}.metadata.json
```

### **2. Scan Runner Integration**
```python
# ✅ Auto-added to run_individual_service_scan.py
def run_{new_service}_scan(regions=None, account_id=None):
    from checks.{new_service}.{new_service}_client import initialize_{new_service}_client
    from checks.{new_service}.{check_name}.{check_name} import {check_name}
    
    runner = ComplianceScanRunner()
    return runner.run_service_scan(
        service_name="{new_service}",
        check_classes=[{check_name}],
        regions=regions,
        account_id=account_id,
        client_initializer=initialize_{new_service}_client
    )

# ✅ Auto-added to run_all_services_scan.py
try:
    logger.info("Running {new_service} scan...")
    {new_service}_report = run_{new_service}_scan(regions, account_id)
    service_reports.append(("{new_service}", {new_service}_report))
    logger.info(f"{new_service} scan completed with {len({new_service}_report.findings)} findings")
except Exception as e:
    logger.error(f"Error running {new_service} scan: {e}")
```

### **3. Package Export Integration**
```python
# ✅ Auto-updated in utils/scan_runners/__init__.py
from .run_individual_service_scan import (
    ComplianceScanRunner,
    run_acm_scan,
    run_account_scan,
    run_{new_service}_scan  # ✅ Auto-added
)

__all__ = [
    'ComplianceScanRunner',
    'run_acm_scan', 
    'run_account_scan',
    'run_{new_service}_scan',  # ✅ Auto-added
    'run_comprehensive_scan'
]
```

### **4. Hierarchical Reporting Integration**
```
output/scan_YYYY-MM-DD_HH-MM-SS/
├── overall/                    # ✅ Auto-includes new service
│   └── compliance_report.json  # All services including {new_service}
└── services/
    ├── acm/
    ├── account/
    └── {new_service}/          # ✅ Auto-created
        ├── {new_service}_report.json
        ├── {new_service}_report.csv
        ├── {new_service}_summary.txt
        └── checks/             # ✅ Auto-created
            ├── {check_name}_report.json
            ├── {check_name}_report.csv
            └── {check_name}_summary.txt
```

### **5. Usage Integration**
```bash
# ✅ Auto-available commands
python run_individual_scan.py                    # Can be modified for {new_service}
python run_all_services.py                       # ✅ Auto-includes {new_service}

# ✅ Auto-available imports
from utils.scan_runners import run_{new_service}_scan
from utils.scan_runners import run_comprehensive_scan  # ✅ Auto-includes {new_service}
```

## 🏗️ Architecture Overview

```
compliance_engine/
├── base.py                    # BaseService for AWS service abstractions
├── config.py                  # Centralized configuration management  
├── utils/
│   ├── reporting.py           # BaseCheck and comprehensive reporting
│   └── scan_runners/          # All scan runner implementations
│       ├── __init__.py        # Package exports
│       ├── run_individual_service_scan.py  # Individual service scans
│       └── run_all_services_scan.py        # Multi-service orchestration
├── run_individual_scan.py     # Entry point for individual scans
├── run_all_services.py        # Entry point for all services
└── checks/
    └── {service_name}/        # Service-specific checks
        ├── {service_name}_client.py      # ✅ Auto-generated
        ├── {service_name}_service.py     # ✅ Auto-generated (if needed)
        └── {check_name}/                 # ✅ Your compliance checks
            ├── {check_name}.py           # Check implementation
            └── {check_name}.metadata.json # Check metadata (optional)
```

## 📦 What You Provide vs What Gets Auto-Generated

### **✅ What You Need to Provide**
```
checks/{new_service}/
└── {check_name}/              # Your compliance check folders
    ├── {check_name}.py        # Your check implementation
    └── {check_name}.metadata.json  # Your check metadata
```

### **🤖 What Gets Auto-Generated**
```
checks/{new_service}/
├── {new_service}_client.py    # ✅ Auto-generated client
├── {new_service}_service.py   # ✅ Auto-generated service (if needed)
└── {check_name}/              # ✅ Your existing checks
```

### **🔧 What Gets Auto-Updated**
- ✅ `utils/scan_runners/run_individual_service_scan.py` - New service function
- ✅ `utils/scan_runners/run_all_services_scan.py` - Service integration
- ✅ `utils/scan_runners/__init__.py` - Package exports
- ✅ Hierarchical reporting structure
- ✅ All existing functionality preserved

## 🚀 Step-by-Step Onboarding Process

### **Option A: Automated Integration (Recommended)**

**Just tell me:**
> "I have added a new services folder for XYZ under checks folder. Please make the enhancement in code as per other services without losing functionality and make sure it perfectly integrated with our current architecture and reporting."

**I will automatically handle everything!**

---

### **Option B: Manual Process (If Needed)**

### Step 1: Create Service Directory Structure

```bash
# Create service directory
mkdir -p checks/{service_name}

# Create check directories (example for S3)
mkdir -p checks/s3/s3_bucket_encryption
mkdir -p checks/s3/s3_bucket_public_access
mkdir -p checks/s3/s3_bucket_versioning
```

### Step 2: Create Service Client

**File**: `checks/{service_name}/{service_name}_client.py`

```python
"""
{Service Name} Client

Provides client initialization and management for {service name} compliance checks.
"""

import boto3
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)

# Global client instance
_{service_name}_client = None

def initialize_{service_name}_client(session: boto3.Session, regions: Optional[List[str]] = None):
    """
    Initialize the {service name} client for compliance checks.
    
    Args:
        session: Boto3 session with appropriate credentials
        regions: List of AWS regions to scan
    """
    global _{service_name}_client
    
    try:
        # Initialize client for default region
        default_region = regions[0] if regions else 'us-east-1'
        _{service_name}_client = session.client('{service_name}', region_name=default_region)
        
        logger.info(f"Initialized {service_name} client for region: {default_region}")
        
        # If multiple regions, initialize clients for each
        if regions and len(regions) > 1:
            for region in regions[1:]:
                session.client('{service_name}', region_name=region)
                logger.info(f"Initialized {service_name} client for region: {region}")
                
    except Exception as e:
        logger.error(f"Error initializing {service_name} client: {e}")
        raise

def get_{service_name}_client():
    """
    Get the {service name} client instance.
    
    Returns:
        Boto3 client for {service name}
    """
    if _{service_name}_client is None:
        raise RuntimeError(f"{service_name} client not initialized. Call initialize_{service_name}_client() first.")
    return _{service_name}_client
```

### Step 3: Create Service Abstraction (if needed)

**File**: `checks/{service_name}/{service_name}_service.py`

*Only create this if you need complex service logic or data models.*

```python
"""
{Service Name} Service

Service abstraction for {service name} compliance checks.
"""

from datetime import datetime
from typing import Optional, Dict, List
from pydantic import BaseModel
import boto3
import logging

logger = logging.getLogger(__name__)


class {Resource}(BaseModel):
    """{Resource} model with essential data"""
    id: str
    name: str
    arn: str
    region: str
    # Add other relevant fields
    
    # Computed properties
    @property
    def is_compliant(self) -> bool:
        """Check if resource is compliant"""
        # Implement compliance logic
        return True


class {ServiceName}Service:
    """{Service name} service that collects resource data"""
    
    def __init__(self, boto3_session: boto3.Session, regions: Optional[List[str]] = None):
        self.session = boto3_session
        self.regions = regions or ['us-east-1']
        self.resources = {}
        self._load_resources()
    
    def _load_resources(self):
        """Load all resources from AWS"""
        for region in self.regions:
            try:
                client = self.session.client('{service_name}', region_name=region)
                self._list_resources(client, region)
            except Exception as error:
                logger.error(f"{service_name} - Error getting resources from {region}: {error}")
    
    def _list_resources(self, client, region: str):
        """Get list of resources from AWS"""
        logger.info(f"{service_name} - Getting resources from {region}")
        
        try:
            # Implement resource listing logic
            # Example for S3:
            # response = client.list_buckets()
            # for bucket_data in response.get('Buckets', []):
            #     self._create_resource(bucket_data, region)
            pass
                    
        except Exception as error:
            logger.error(f"{service_name} - Error getting resources from {region}: {error}")
    
    def _create_resource(self, resource_data, region: str):
        """Create resource object from AWS data"""
        # Implement resource creation logic
        pass
    
    def get_all_resources(self):
        """Get all resources"""
        return list(self.resources.values())
```

### Step 4: Create Individual Compliance Checks

**File**: `checks/{service_name}/{check_name}/{check_name}.py`

```python
"""
{Check Name} Compliance Check

Checks if {service name} resources meet {specific compliance requirement}.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'utils'))
from reporting import (
    BaseCheck, CheckReport, CheckMetadata, CheckStatus, 
    Severity, ComplianceStandard
)

from ..{service_name}_client import get_{service_name}_client


class {check_name}(BaseCheck):
    """Check if {service name} resources meet {specific compliance requirement}"""
    
    def _get_metadata(self) -> CheckMetadata:
        """Get check metadata"""
        return CheckMetadata(
            check_id="{check_id}",
            check_name="{Check Name}",
            description="{Detailed description of what this check does}",
            severity=Severity.{SEVERITY},  # CRITICAL, HIGH, MEDIUM, LOW, INFO
            compliance_standard=ComplianceStandard.{STANDARD},  # AWS_FOUNDATIONAL_SECURITY_BEST_PRACTICES, etc.
            category="{Category}",  # e.g., "Data Protection", "Access Control", "Logging and Monitoring"
            tags=["{service_name}", "{tag1}", "{tag2}"],
            remediation="{Step-by-step remediation instructions}",
            references=[
                "{AWS documentation URL}",
                "{Best practice guide URL}"
            ]
        )
    
    def execute(self) -> list[CheckReport]:
        """Execute the compliance check"""
        findings = []
        
        # Get service client
        client = get_{service_name}_client()
        
        # Get resources to check
        resources = self._get_resources_to_check(client)
        
        # Check each resource
        for resource in resources:
            if self._should_check_resource(resource):
                report = self._check_resource(resource)
                findings.append(report)
        
        return findings
    
    def _get_resources_to_check(self, client):
        """Get resources that need to be checked"""
        # Implement resource retrieval logic
        # Example:
        # response = client.list_{resources}()
        # return response.get('{Resources}', [])
        pass
    
    def _should_check_resource(self, resource) -> bool:
        """Determine if resource should be checked"""
        # Implement filtering logic
        # Example: Check if resource is active, in use, etc.
        return True
    
    def _check_resource(self, resource) -> CheckReport:
        """Check if a single resource is compliant"""
        
        # Implement compliance logic
        # Example:
        # is_compliant = self._evaluate_compliance(resource)
        
        # Determine status and message
        if is_compliant:
            status = CheckStatus.PASS
            status_extended = (
                f"{Resource type} {resource.get('id', 'unknown')} "
                f"meets compliance requirements."
            )
        else:
            status = CheckStatus.FAIL
            status_extended = (
                f"{Resource type} {resource.get('id', 'unknown')} "
                f"does not meet compliance requirements."
            )
        
        # Create report for this resource
        report = CheckReport(
            status=status,
            status_extended=status_extended,
            resource=resource,
            metadata=self.metadata,
            region=resource.get('region', 'unknown'),
            evidence={
                "resource_id": resource.get('id', 'unknown'),
                "resource_name": resource.get('name', 'unknown'),
                # Add other relevant evidence
            }
        )
        
        return report
```

### Step 5: Add Service to Unified Scan Runner

**File**: `run_compliance_scan.py`

Add the convenience function at the bottom of the file:

```python
def run_{service_name}_scan(regions: Optional[List[str]] = None, account_id: Optional[str] = None) -> ComplianceReport:
    """
    Run {service name} compliance scan using the unified runner.
    
    Args:
        regions: List of AWS regions to scan
        account_id: AWS account ID
        
    Returns:
        ComplianceReport with all findings
    """
    from checks.{service_name}.{service_name}_client import initialize_{service_name}_client
    from checks.{service_name}.{check_name1}.{check_name1} import {check_name1}
    from checks.{service_name}.{check_name2}.{check_name2} import {check_name2}
    # Import all check classes for this service
    
    runner = ComplianceScanRunner()
    return runner.run_service_scan(
        service_name="{service_name}",
        check_classes=[
            {check_name1},
            {check_name2},
            # Add all check classes
        ],
        regions=regions,
        account_id=account_id,
        client_initializer=initialize_{service_name}_client
    )
```

### Step 6: Create Tests (Optional but Recommended)

**File**: `tests/test_{service_name}_{check_name}.py`

```python
"""
Tests for {service name} {check name} compliance check
"""

import unittest
from unittest.mock import Mock, patch
from checks.{service_name}.{check_name}.{check_name} import {check_name}


class Test{CheckName}(unittest.TestCase):
    
    def setUp(self):
        self.check = {check_name}()
    
    @patch('checks.{service_name}.{service_name}_client.get_{service_name}_client')
    def test_compliant_resource(self, mock_client):
        """Test that compliant resources pass the check"""
        # Mock compliant resource
        mock_resource = {
            'id': 'test-resource',
            'name': 'test-resource',
            'region': 'us-east-1',
            # Add compliant properties
        }
        
        # Mock client response
        mock_client.return_value.list_{resources}.return_value = {
            '{Resources}': [mock_resource]
        }
        
        # Run check
        findings = self.check.execute()
        
        # Assertions
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status.value, 'PASS')
    
    @patch('checks.{service_name}.{service_name}_client.get_{service_name}_client')
    def test_non_compliant_resource(self, mock_client):
        """Test that non-compliant resources fail the check"""
        # Mock non-compliant resource
        mock_resource = {
            'id': 'test-resource',
            'name': 'test-resource',
            'region': 'us-east-1',
            # Add non-compliant properties
        }
        
        # Mock client response
        mock_client.return_value.list_{resources}.return_value = {
            '{Resources}': [mock_resource]
        }
        
        # Run check
        findings = self.check.execute()
        
        # Assertions
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status.value, 'FAIL')


if __name__ == '__main__':
    unittest.main()
```

## 🧪 Testing Your Implementation

### **Automated Testing (When I Handle Integration)**

When I automatically integrate your new service, I will test:

1. ✅ **Individual Check Testing**
2. ✅ **Service Scan Testing** 
3. ✅ **Comprehensive Scan Testing**
4. ✅ **Hierarchical Reporting Testing**
5. ✅ **Import/Export Testing**

---

### **Manual Testing (If You Do It Yourself)**

### 1. Test Individual Check

```bash
# Run individual check
python -c "
from checks.{service_name}.{check_name}.{check_name} import {check_name}
check = {check_name}()
findings = check.execute()
print(f'Found {len(findings)} findings')
for finding in findings:
    print(f'{finding.status.value}: {finding.status_extended}')
"
```

### 2. Test Service Scan

```bash
# Run service scan
python -c "
from utils.scan_runners import run_{service_name}_scan, ComplianceScanRunner
report = run_{service_name}_scan(regions=['us-east-1'])
runner = ComplianceScanRunner()
runner.save_reports(report)
print(f'Compliance Score: {report.get_summary()[\"compliance_score\"]}%')
"
```

### 3. Test Comprehensive Scan

```bash
# Run comprehensive scan with all services
python run_all_services.py
```

### 4. Test Full Integration

```bash
# Run individual service scan with reporting
python -c "
from utils.scan_runners import run_{service_name}_scan, ComplianceScanRunner
report = run_{service_name}_scan(regions=['us-east-1'])
runner = ComplianceScanRunner()
runner.save_reports(report)
"
```

## 📋 Checklist for New Service

### **Automated Integration (Recommended)**
- [ ] ✅ Service folder added under `checks/`
- [ ] ✅ Compliance check files created
- [ ] ✅ Tell me: "I have added a new services folder for XYZ under checks folder..."
- [ ] ✅ I handle all integration automatically

### **Manual Integration (If Needed)**
- [ ] Service directory created
- [ ] Service client implemented
- [ ] Service abstraction created (if needed)
- [ ] Individual checks implemented
- [ ] Checks added to scan runner
- [ ] Tests created and passing
- [ ] Documentation updated
- [ ] Code reviewed for consistency

## 🎯 Example: S3 Service Onboarding

Here's how the S3 service would be structured following this guide:

```
checks/s3/
├── s3_client.py
├── s3_service.py
├── s3_bucket_encryption/
│   └── s3_bucket_encryption.py
├── s3_bucket_public_access/
│   └── s3_bucket_public_access.py
└── s3_bucket_versioning/
    └── s3_bucket_versioning.py
```

## ⚠️ Important Notes

1. **Follow the exact naming conventions** shown in this guide
2. **Use the BaseCheck class** from `utils.reporting` for all checks
3. **Implement proper error handling** in all client interactions
4. **Use consistent logging** throughout the implementation
5. **Follow the metadata structure** exactly as shown
6. **Test thoroughly** before considering onboarding complete

## 📁 Hierarchical Output Structure

All reports are saved in a hierarchical structure that aligns with the check organization:

```
output/
└── scan_YYYY-MM-DD_HH-MM-SS/
    ├── scan_metadata.json          # Scan metadata and configuration
    ├── overall/                    # Level 1: Overall scan results
    │   ├── compliance_report.json  # Complete findings in JSON format
    │   ├── compliance_report.csv   # Findings in CSV format
    │   └── compliance_summary.txt  # Human-readable summary
    └── services/                   # Level 2: Service-specific reports
        ├── acm/                    # ACM service reports
        │   ├── acm_report.json
        │   ├── acm_report.csv
        │   ├── acm_summary.txt
        │   └── checks/             # Level 3: Individual check reports
        │       ├── acm_certificates_with_secure_key_algorithms_report.json
        │       ├── acm_certificates_with_secure_key_algorithms_report.csv
        │       ├── acm_certificates_with_secure_key_algorithms_summary.txt
        │       ├── acm_certificates_transparency_logs_enabled_report.json
        │       ├── acm_certificates_transparency_logs_enabled_report.csv
        │       ├── acm_certificates_transparency_logs_enabled_summary.txt
        │       ├── acm_certificates_expiration_check_report.json
        │       ├── acm_certificates_expiration_check_report.csv
        │       └── acm_certificates_expiration_check_summary.txt
        ├── account/                # Account service reports
        │   ├── account_report.json
        │   ├── account_report.csv
        │   ├── account_summary.txt
        │   └── checks/             # Level 3: Individual check reports
        │       ├── account_maintain_current_contact_details_report.json
        │       ├── account_maintain_current_contact_details_report.csv
        │       ├── account_maintain_current_contact_details_summary.txt
        │       └── [other_account_checks]/
        └── {service_name}/         # Other services as they're added
            ├── {service_name}_report.json
            ├── {service_name}_report.csv
            ├── {service_name}_summary.txt
            └── checks/             # Level 3: Individual check reports
                ├── {check_name}_report.json
                ├── {check_name}_report.csv
                └── {check_name}_summary.txt
```

### Report Hierarchy

The structure follows a three-level hierarchy that aligns with the check organization:

1. **Level 1 - Overall**: Complete compliance summary across all services
   - Cross-service findings and statistics
   - Overall compliance score
   - Executive summary

2. **Level 2 - Service**: Service-specific reports and findings
   - All findings for a specific AWS service
   - Service-level compliance score
   - Service-specific summary

3. **Level 3 - Check**: Individual check function reports
   - Detailed findings for each compliance check
   - Check-specific compliance status
   - Granular resource-level details

### Benefits of Hierarchical Structure:
- ✅ **Centralized reporting** - One place for all compliance findings
- ✅ **Service isolation** - Easy to focus on specific services
- ✅ **Check granularity** - Detailed reports for individual compliance checks
- ✅ **Consistent format** - JSON, CSV, and TXT formats at all levels
- ✅ **Timestamped scans** - No overwriting of previous results
- ✅ **Scalable** - Easy to add new services and checks without changing structure
- ✅ **Hierarchical alignment** - Structure matches the check organization

## 🔄 Maintenance

- Update this guide when architecture changes
- Keep examples current with latest patterns
- Review and update compliance standards as needed
- Maintain consistency across all services

## 🎯 Summary

### **For New Services - Just Do This:**

1. **Create your service folder:**
   ```bash
   mkdir -p checks/{new_service}/{check_name}
   ```

2. **Add your compliance checks:**
   ```
   checks/{new_service}/
   └── {check_name}/
       ├── {check_name}.py        # Your check implementation
       └── {check_name}.metadata.json  # Your check metadata
   ```

3. **Tell me:**
   > "I have added a new services folder for XYZ under checks folder. Please make the enhancement in code as per other services without losing functionality and make sure it perfectly integrated with our current architecture and reporting."

4. **I automatically handle:**
   - ✅ Service client generation
   - ✅ Scan runner integration
   - ✅ Hierarchical reporting setup
   - ✅ Package exports
   - ✅ Testing and validation
   - ✅ Documentation updates

### **What You Get:**
- ✅ **Individual service scan**: `python run_individual_scan.py`
- ✅ **All services scan**: `python run_all_services.py`
- ✅ **Direct imports**: `from utils.scan_runners import run_{service}_scan`
- ✅ **Hierarchical reports**: Service-specific and check-level reports
- ✅ **Full integration**: Works with existing architecture

---

**This guide is the single source of truth. For new services, just add your folder and tell me - I'll handle the rest!** 