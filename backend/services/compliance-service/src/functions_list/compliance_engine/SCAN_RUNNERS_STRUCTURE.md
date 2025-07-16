# Scan Runners Structure

## Overview

All scan runner files are now organized under `utils/scan_runners/` to eliminate ambiguity and create a clean, organized structure.

## Directory Structure

```
compliance_engine/
├── utils/
│   ├── reporting.py                    # Core reporting models and base classes
│   └── scan_runners/                   # All scan runner implementations
│       ├── __init__.py                 # Package initialization and exports
│       ├── run_individual_service_scan.py  # Individual service scan logic
│       └── run_all_services_scan.py    # Multi-service orchestration logic
├── run_individual_scan.py              # Entry point for individual scans
├── run_all_services.py                 # Entry point for all services scans
├── base.py                             # Base service classes
├── config.py                           # Configuration management
└── engine.py                           # Core engine functionality
```

## File Purposes

### **Core Implementation Files** (`utils/scan_runners/`)

#### `run_individual_service_scan.py`
- **Purpose**: Core logic for running individual service scans
- **Contains**: `ComplianceScanRunner` class and service-specific functions
- **Functions**: `run_acm_scan()`, `run_account_scan()`, etc.
- **Use**: Imported by other modules, not run directly

#### `run_all_services_scan.py`
- **Purpose**: Orchestrates multiple service scans
- **Contains**: `run_comprehensive_scan()` function
- **Logic**: Runs all individual service scans and combines results
- **Use**: Imported by other modules, not run directly

#### `__init__.py`
- **Purpose**: Makes `scan_runners` a proper Python package
- **Exports**: Main functions for easy importing
- **Usage**: `from utils.scan_runners import run_acm_scan`

### **Entry Point Scripts** (Root Directory)

#### `run_individual_scan.py`
- **Purpose**: Convenient script to run individual service scans
- **Usage**: `python run_individual_scan.py`
- **Default**: Runs ACM scan (can be modified for other services)

#### `run_all_services.py`
- **Purpose**: Convenient script to run comprehensive scans
- **Usage**: `python run_all_services.py`
- **Default**: Runs all available services

## Usage Examples

### **1. Using Entry Point Scripts**

```bash
# Run individual service scan (ACM)
python run_individual_scan.py

# Run all services scan
python run_all_services.py
```

### **2. Direct Import from Utils**

```python
# Import individual service functions
from utils.scan_runners import run_acm_scan, run_account_scan

# Run specific service
report = run_acm_scan(regions=['us-east-1'])

# Import comprehensive scan
from utils.scan_runners import run_comprehensive_scan

# Run all services
comprehensive_report = run_comprehensive_scan(regions=['us-east-1'])
```

### **3. Import ComplianceScanRunner**

```python
# Import the runner class
from utils.scan_runners import ComplianceScanRunner

# Create runner instance
runner = ComplianceScanRunner()

# Run custom service scan
report = runner.run_service_scan(
    service_name="s3",
    check_classes=[s3_bucket_encryption, s3_bucket_public_access],
    regions=['us-east-1'],
    client_initializer=initialize_s3_client
)
```

## Benefits of This Structure

### **✅ Eliminates Ambiguity**
- Clear separation between implementation and entry points
- No confusion about which file does what

### **✅ Organized Code**
- All scan runners in one logical location
- Easy to find and maintain

### **✅ Flexible Usage**
- Multiple ways to use the functionality
- Entry points for convenience, direct imports for flexibility

### **✅ Scalable**
- Easy to add new scan runners to `utils/scan_runners/`
- Entry points can be customized as needed

### **✅ Clean Imports**
```python
# Clean, clear imports
from utils.scan_runners import run_acm_scan
from utils.scan_runners import run_comprehensive_scan
from utils.scan_runners import ComplianceScanRunner
```

## Adding New Services

### **1. Add Service Function to `run_individual_service_scan.py`**
```python
def run_s3_scan(regions=None, account_id=None):
    from checks.s3.s3_client import initialize_s3_client
    from checks.s3.s3_bucket_encryption.s3_bucket_encryption import s3_bucket_encryption
    
    runner = ComplianceScanRunner()
    return runner.run_service_scan(
        service_name="s3",
        check_classes=[s3_bucket_encryption],
        regions=regions,
        account_id=account_id,
        client_initializer=initialize_s3_client
    )
```

### **2. Update `__init__.py`**
```python
from .run_individual_service_scan import (
    ComplianceScanRunner,
    run_acm_scan,
    run_account_scan,
    run_s3_scan  # Add new service
)
```

### **3. Add to `run_all_services_scan.py`**
```python
# Run S3 scan
try:
    logger.info("Running S3 scan...")
    s3_report = run_s3_scan(regions, account_id)
    service_reports.append(("s3", s3_report))
    logger.info(f"S3 scan completed with {len(s3_report.findings)} findings")
except Exception as e:
    logger.error(f"Error running S3 scan: {e}")
```

## Migration Notes

### **Old Usage** (Deprecated)
```python
# Old way - no longer works
from run_compliance_scan import run_acm_scan  # ❌ File moved
from run_comprehensive_scan import run_comprehensive_scan  # ❌ File moved
```

### **New Usage** (Current)
```python
# New way - clean and organized
from utils.scan_runners import run_acm_scan  # ✅
from utils.scan_runners import run_comprehensive_scan  # ✅
```

## Summary

This reorganization provides:
- **Clear organization** - All scan runners in `utils/scan_runners/`
- **No ambiguity** - Clear purpose for each file
- **Multiple access methods** - Entry points and direct imports
- **Easy maintenance** - Logical file structure
- **Scalable design** - Easy to add new services

The structure is now clean, organized, and eliminates any confusion about which file does what! 