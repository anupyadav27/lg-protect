# Hierarchical Output Structure

## Overview

The compliance engine now uses a **three-level hierarchical structure** that perfectly aligns with the check organization:

1. **Level 1 - Overall**: Complete compliance summary across all services
2. **Level 2 - Service**: Service-specific reports and findings  
3. **Level 3 - Check**: Individual check function reports

## Structure Layout

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
        │       ├── account_security_contact_information_is_registered_report.json
        │       ├── account_security_contact_information_is_registered_report.csv
        │       ├── account_security_contact_information_is_registered_summary.txt
        │       ├── account_security_questions_are_registered_report.json
        │       ├── account_security_questions_are_registered_report.csv
        │       ├── account_security_questions_are_registered_summary.txt
        │       ├── account_maintain_different_contact_details_report.json
        │       ├── account_maintain_different_contact_details_report.csv
        │       └── account_maintain_different_contact_details_summary.txt
        └── {service_name}/         # Other services as they're added
            ├── {service_name}_report.json
            ├── {service_name}_report.csv
            ├── {service_name}_summary.txt
            └── checks/             # Level 3: Individual check reports
                ├── {check_name}_report.json
                ├── {check_name}_report.csv
                └── {check_name}_summary.txt
```

## Level Details

### Level 1 - Overall (Executive Summary)
**Location**: `output/scan_*/overall/`

**Purpose**: Complete compliance overview across all services
- Cross-service findings and statistics
- Overall compliance score
- Executive summary for stakeholders
- Complete audit trail

**Files**:
- `compliance_report.json` - Complete findings in JSON format
- `compliance_report.csv` - Findings in CSV format for analysis
- `compliance_summary.txt` - Human-readable executive summary

### Level 2 - Service (Service-Specific Analysis)
**Location**: `output/scan_*/services/{service_name}/`

**Purpose**: Service-specific reports and findings
- All findings for a specific AWS service
- Service-level compliance score
- Service-specific summary
- Resource-level analysis

**Files**:
- `{service_name}_report.json` - Service findings in JSON format
- `{service_name}_report.csv` - Service findings in CSV format
- `{service_name}_summary.txt` - Service-specific summary

### Level 3 - Check (Granular Analysis)
**Location**: `output/scan_*/services/{service_name}/checks/`

**Purpose**: Individual check function reports
- Detailed findings for each compliance check
- Check-specific compliance status
- Granular resource-level details
- Specific remediation guidance

**Files**:
- `{check_name}_report.json` - Check findings in JSON format
- `{check_name}_report.csv` - Check findings in CSV format
- `{check_name}_summary.txt` - Check-specific summary

## Benefits

### 🎯 **Centralized Reporting**
- One place for all compliance findings
- Easy to navigate and understand
- Consistent structure across all services

### 🔍 **Service Isolation**
- Easy to focus on specific services
- Service-specific compliance scores
- Isolated analysis and remediation

### 📊 **Check Granularity**
- Detailed reports for individual compliance checks
- Granular resource-level details
- Specific remediation guidance per check

### 📋 **Consistent Format**
- JSON, CSV, and TXT formats at all levels
- Standardized naming conventions
- Predictable file structure

### ⏰ **Timestamped Scans**
- Each scan gets its own directory
- No overwriting of previous results
- Historical compliance tracking

### 🚀 **Scalable**
- Easy to add new services and checks
- Structure automatically adapts
- No changes needed to existing reports

### 🏗️ **Hierarchical Alignment**
- Structure matches the check organization
- Logical progression from overall to specific
- Easy to drill down from executive to technical

## Usage Examples

### Executive Review
```bash
# View overall compliance summary
cat output/scan_*/overall/compliance_summary.txt
```

### Service Analysis
```bash
# View ACM service summary
cat output/scan_*/services/acm/acm_summary.txt

# View Account service summary  
cat output/scan_*/services/account/account_summary.txt
```

### Check-Specific Analysis
```bash
# View specific check details
cat output/scan_*/services/acm/checks/ACM\ Certificates\ Expiration\ Check_summary.txt

# View check CSV data for analysis
cat output/scan_*/services/account/checks/Account\ Maintain\ Current\ Contact\ Details_report.csv
```

### Programmatic Access
```bash
# Get overall compliance score
jq '.compliance_score' output/scan_*/overall/compliance_report.json

# Get service-specific findings
jq '.findings[] | select(.check_name | contains("ACM"))' output/scan_*/overall/compliance_report.json

# Get check-specific details
jq '.findings[] | select(.check_name == "ACM Certificates Expiration Check")' output/scan_*/services/acm/acm_report.json
```

## Metadata

The scan metadata includes information about the hierarchical structure:

```json
{
  "output_structure": {
    "overall": "Overall scan results and summary",
    "services": "Service-specific reports and findings", 
    "checks": "Individual check function reports within each service"
  },
  "hierarchy": {
    "level_1": "Overall compliance summary and cross-service findings",
    "level_2": "Service-specific reports (e.g., ACM, Account, S3)",
    "level_3": "Individual check function reports within each service"
  }
}
```

## Implementation

The hierarchical structure is automatically generated by the `ComplianceScanRunner.save_reports()` method:

1. **Overall reports**: Complete findings from all services
2. **Service reports**: Findings grouped by service
3. **Check reports**: Findings grouped by individual check function

Each level provides the same three formats (JSON, CSV, TXT) for maximum flexibility in consumption and analysis.

---

This hierarchical structure ensures that compliance reporting is both comprehensive and granular, providing the right level of detail for different stakeholders and use cases. 