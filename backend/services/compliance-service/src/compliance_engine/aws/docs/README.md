# Compliance Engine - Clean Structure

This directory contains a unified compliance engine with no code duplication, ready for onboarding new AWS services.

## Structure Overview

```
compliance_engine/
├── base.py                    # BaseService for AWS service abstractions
├── config.py                  # Centralized configuration management
├── engine.py                  # Legacy engine (deprecated)
├── run_compliance_scan.py     # UNIFIED scan runner for all services
├── utils/
│   └── reporting.py           # BaseCheck and comprehensive reporting system
└── checks/
    └── acm/                   # ACM service checks
        ├── acm_client.py      # ACM service client
        ├── acm_service.py     # ACM service abstraction

        └── [check_name]/      # Individual checks
            └── [check_name].py
```

## Key Principles

### 1. Single Base Class System
- **`BaseService`** (in `base.py`) - For AWS service abstractions
- **`BaseCheck`** (in `utils/reporting.py`) - For all compliance checks
- **No duplicate base classes**

### 2. Unified Scan Runner
- **`run_compliance_scan.py`** - Single runner for all services
- Eliminates code duplication across multiple scan runners
- Consistent interface and reporting

### 3. Simple and Clean
- **No unnecessary abstractions** - Keep it simple
- **Individual check methods** - Each check has its own logic
- **No utility files** - Unless there's significant shared logic

## Onboarding New Services

### Step 1: Create Service Directory
```bash
mkdir checks/{service_name}
```

### Step 2: Create Service Client
```python
# checks/{service_name}/{service_name}_client.py
def initialize_{service_name}_client(session, regions):
    # Initialize service client
    pass
```

### Step 3: Create Individual Checks
```python
# checks/{service_name}/{check_name}/{check_name}.py
from utils.reporting import BaseCheck, CheckMetadata, CheckStatus, Severity, ComplianceStandard

class {check_name}(BaseCheck):
    def _get_metadata(self) -> CheckMetadata:
        return CheckMetadata(...)
    
    def execute(self) -> List[CheckReport]:
        # Implementation with your own logic
        pass
```



### Step 4: Add to Scan Runner
```python
# In run_compliance_scan.py
def run_{service_name}_scan(regions: Optional[List[str]] = None, account_id: Optional[str] = None) -> ComplianceReport:
    from checks.{service_name}.{service_name}_client import initialize_{service_name}_client
    from checks.{service_name}.{check_name}.{check_name} import {check_name}
    
    runner = ComplianceScanRunner()
    return runner.run_service_scan(
        service_name="{service_name}",
        check_classes=[{check_name}],
        regions=regions,
        account_id=account_id,
        client_initializer=initialize_{service_name}_client
    )
```

## Benefits

✅ **No Code Duplication** - Single scan runner, unified base classes
✅ **Consistent Patterns** - All services follow the same structure  
✅ **Easy to Extend** - Minimal boilerplate for new services
✅ **Comprehensive Reporting** - Standardized JSON, CSV, TXT outputs
✅ **Error Handling** - Consistent error handling and logging
✅ **Configuration** - Centralized configuration management

## Example Usage

```python
# Run ACM scan
from run_compliance_scan import run_acm_scan
report = run_acm_scan(regions=['us-east-1'])

# Save reports
from run_compliance_scan import ComplianceScanRunner
runner = ComplianceScanRunner()
runner.save_reports(report)
```

## Migration Notes

- **Old scan runners removed**: `run_acm_scan.py`, `run_acm_scan_enhanced.py`, `run_acm_comprehensive_scan.py`
- **Deprecated base classes removed**: `BaseComplianceCheck` from `base.py`
- **Service-specific base classes removed**: `ACMBaseCheck` removed (unnecessary)
- **Unified approach**: All services now use the same patterns and interfaces 