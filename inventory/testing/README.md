# Testing Framework for AWS Service Enablement Checker

This directory contains a comprehensive testing framework for the AWS Service Enablement Checker with organized test types and timestamped results tracking.

## 📁 Directory Structure

```
testing/
├── README.md                          # This file
├── utility/
│   ├── utility_testing.py            # Service mapping region updater
│   └── results/                       # Timestamped utility test results
│       └── utility_test_YYYYMMDD_HHMMSS/
├── comprehensive/
│   ├── comprehensive_testing.py       # Full system validation
│   └── results/                       # Timestamped comprehensive test results
│       └── comprehensive_test_YYYYMMDD_HHMMSS/
└── quick_validation/
    ├── quick_validation_test.py       # Fast resource detection check
    └── results/                       # Timestamped validation results
        └── quick_validation_YYYYMMDD_HHMMSS/
```

## 🔧 Test Types

### 1. **Utility Testing** (`utility/utility_testing.py`)
- **Purpose**: Updates service_enablement_mapping.json with region information
- **Function**: Maintenance utility for service mapping
- **When to use**: When updating service mappings or adding new regions
- **Output**: 
  - `service_enablement_mapping_backup.json`
  - `service_enablement_mapping_updated.json`
  - `utility_test_log.txt`

### 2. **Comprehensive Testing** (`comprehensive/comprehensive_testing.py`)
- **Purpose**: Full system validation of resource detection and CSV generation
- **Function**: Tests multiple services, resource extraction, and output formatting
- **When to use**: After major changes or for thorough system validation
- **Output**:
  - `test_results_detailed.json`
  - `test_summary.txt`
  - `test_results_summary.csv`

### 3. **Quick Validation** (`quick_validation/quick_validation_test.py`)
- **Purpose**: Fast verification of basic resource detection
- **Function**: Tests S3, DynamoDB, SQS, IAM, Lambda for resource discovery
- **When to use**: Quick smoke testing and daily validation
- **Output**:
  - `validation_results.json`
  - `validation_summary.txt`
  - `validation_results.csv`

## 🚀 Usage Examples

### Run Quick Validation (Recommended for daily checks)
```bash
cd /Users/apple/Desktop/lg-protect/inventory/testing/quick_validation
python quick_validation_test.py
```

### Run Comprehensive Testing (For thorough validation)
```bash
cd /Users/apple/Desktop/lg-protect/inventory/testing/comprehensive
python comprehensive_testing.py
```

### Run Utility Testing (For maintenance tasks)
```bash
cd /Users/apple/Desktop/lg-protect/inventory/testing/utility
python utility_testing.py
```

## 📊 Results Management

Each test run creates a timestamped folder in the respective `results/` directory:

- **Format**: `test_type_YYYYMMDD_HHMMSS/`
- **Example**: `quick_validation_20250705_143022/`
- **Benefits**: 
  - Track test history over time
  - Compare results across runs
  - Maintain audit trail of testing

## 🎯 Test Workflow Recommendations

1. **Daily**: Run `quick_validation_test.py` for basic health checks
2. **After changes**: Run `comprehensive_testing.py` for full validation
3. **Maintenance**: Run `utility_testing.py` when updating service mappings
4. **Production**: Use the main `simplified_service_enablement_checker.py`

## 📈 Interpreting Results

### Success Indicators
- ✅ API calls successful
- 📦 Resources detected with counts > 0
- 📋 Real resource identifiers found (bucket names, table names, etc.)

### Warning Signs
- ❌ API call failures
- 📦 Zero resources detected across all services
- 🔴 Permission errors or access denied messages

## 🔄 Integration with Main Checker

These tests validate the core functionality used by:
- `simplified_service_enablement_checker.py` (Main production tool)
- Resource detection improvements
- CSV output generation
- Service mapping accuracy

## 📝 Notes

- All tests use the same service mapping (`service_enablement_mapping.json`)
- Tests validate the resource extraction logic used in production
- Timestamped results allow tracking improvements over time
- Each test type serves a specific purpose in the testing lifecycle