# AWS Organization Discovery & Multi-Account Compliance

This document describes the organization discovery and multi-account compliance capabilities for the LG-Protect compliance service.

## Overview

The organization discovery module provides comprehensive AWS Organizations discovery and multi-account compliance checking capabilities. It automatically discovers all accounts in your AWS Organization and runs compliance checks across multiple accounts simultaneously.

## Architecture

The organization discovery system consists of three main components:

### 1. Organization Discovery (`organization_discovery.py`)
- Discovers all accounts in your AWS Organization
- Maps organizational units (OUs) and policies
- Identifies enabled regions per account
- Catalogs available services per account per region

### 2. Multi-Account Manager (`multi_account_manager.py`)
- Manages cross-account authentication and sessions
- Handles role assumption with secure external IDs
- Supports multiple authentication methods (CLI profiles, assume roles, access keys)
- Validates account access and permissions

### 3. Organization Orchestrator (`organization_orchestrator.py`)
- Main orchestration engine that coordinates discovery and compliance
- Integrates with existing compliance engine
- Provides parallel processing for faster execution
- Generates comprehensive reports and summaries

## Module Structure

```
utils/organization/
├── __init__.py                    # Module exports and configuration
├── organization_discovery.py      # Core discovery logic
├── multi_account_manager.py       # Multi-account session management
├── organization_orchestrator.py   # Main orchestration engine
├── organization_cli.py            # Command-line interface
└── organization_example.py        # Quick start examples
```

## Quick Start

### Basic Usage

```python
from compliance_engine.check_aws.utils.organization import OrganizationDiscoveryOrchestrator

# Initialize orchestrator
orchestrator = OrganizationDiscoveryOrchestrator()
orchestrator.initialize()

# Discover organization
organization = orchestrator.discover_full_organization()

# Run compliance checks
results = orchestrator.run_compliance_checks_organization_wide()

# Get summary
summary = orchestrator.get_organization_summary()
print(f"Total accounts: {summary['total_accounts']}")
print(f"Compliance score: {results['organization_summary']['overall_compliance_score']:.2f}%")
```

### Command Line Interface

```bash
# Navigate to the organization module
cd backend/services/compliance-service/src/compliance_engine/check_aws/utils/organization

# Discover organization structure
python organization_cli.py discover --verbose

# Run compliance checks
python organization_cli.py compliance --discover-first --frameworks SOC2 CIS

# Run full workflow (discovery + compliance)
python organization_cli.py full --max-parallel-discovery 5 --max-parallel-compliance 3

# Generate setup instructions
python organization_cli.py setup --output-file setup_instructions.md

# Check organization status
python organization_cli.py status
```

## Security & Setup

### Prerequisites

1. **AWS Organizations**: Must be enabled and you must run from the master account
2. **Permissions**: Organizations read permissions + cross-account assume role permissions
3. **Cross-Account Roles**: Deploy `LGProtectComplianceRole` in each member account

### Cross-Account Role Deployment

The system automatically generates CloudFormation templates for secure cross-account access:

```yaml
# Generated template includes:
- Role: LGProtectComplianceRole
- Policies: ReadOnlyAccess, SecurityAudit, + compliance-specific permissions
- Security: External ID for role assumption
- Trusted Account: Your Organizations master account
```

### Deployment Commands

```bash
# The system generates commands like this for each account:
aws cloudformation deploy \
  --template-file compliance-role-template.yaml \
  --stack-name lg-protect-compliance-role \
  --parameter-overrides \
    TrustedAccountId=123456789012 \
    ExternalId=lg-protect-compliance-987654321098 \
  --capabilities CAPABILITY_NAMED_IAM \
  --profile production-account
```

## Output & Results

### Discovery Results Structure

```
output/organization_discovery_YYYYMMDD_HHMMSS/
├── organization_structure.json      # Complete organization data
├── accounts_summary.json           # Account summaries
├── accounts_summary.csv            # CSV for analysis
└── compliance_accounts_config.json # Account configuration
```

### Compliance Results Structure

```
output/compliance_results_YYYYMMDD_HHMMSS/
├── organization_compliance_summary.json  # Overall compliance summary
├── detailed_compliance_results.json      # Per-account detailed results
└── compliance_summary.csv               # CSV summary
```

## Performance & Scalability

### Parallel Processing
- **Discovery**: Up to 10 accounts in parallel (configurable)
- **Compliance**: Up to 5 accounts in parallel (configurable)
- **Region Processing**: All regions per account processed in parallel

### Resource Management
- **API Throttling**: Built-in retry logic and rate limiting
- **Session Management**: Automatic session cleanup and reuse
- **Memory Usage**: Efficient streaming and pagination

## Integration with Existing Compliance Engine

The orchestrator integrates seamlessly with your existing compliance engine:

```python
# The orchestrator calls your compliance engine for each account/region
def _run_compliance_checks_for_region(self, session, account_id, region, services):
    # Configure your compliance engine with the account session
    for service in services:
        if hasattr(self.compliance_engine, f'check_{service}'):
            check_method = getattr(self.compliance_engine, f'check_{service}')
            service_results = check_method(session, region, account_id)
            # Process results...
```

## Troubleshooting

### Common Issues

1. **"No access to AWS Organizations"**
   - Ensure you're running from the Organizations master account
   - Check IAM permissions for Organizations APIs

2. **"Failed to assume role"**
   - Deploy the cross-account roles using generated CloudFormation templates
   - Verify external IDs match between role and configuration

3. **"Discovery failed for some accounts"**
   - Check account status (must be ACTIVE)
   - Verify cross-account role deployment
   - Review IAM permissions

### Debug Mode

```bash
# Enable verbose logging
python organization_cli.py discover --verbose

# Check organization status
python organization_cli.py status --verbose
```

## API Reference

### OrganizationDiscoveryOrchestrator

Main class for coordinating organization discovery and compliance checks.

#### Methods

- `initialize()` - Initialize the orchestrator and validate access
- `discover_full_organization()` - Perform full organization discovery
- `run_compliance_checks_organization_wide()` - Run compliance checks across all accounts
- `get_organization_summary()` - Get organization discovery summary
- `generate_setup_instructions()` - Generate setup instructions for cross-account roles

### OrganizationDiscovery

Core class for AWS Organizations discovery.

#### Methods

- `discover_organization_structure()` - Discover organization structure
- `discover_account_regions()` - Discover enabled regions for an account
- `discover_account_services()` - Discover available services for an account

### ComplianceMultiAccountManager

Manager for multi-account sessions and credentials.

#### Methods

- `get_account_session()` - Get or create a session for a specific account
- `validate_account_access()` - Validate access to an account
- `discover_all_accounts_parallel()` - Discover all accounts in parallel

## Next Steps

1. **Deploy Cross-Account Roles**: Use generated CloudFormation templates
2. **Test Discovery**: Run `organization_cli.py discover` to validate setup
3. **Run Compliance**: Execute `organization_cli.py full` for complete workflow
4. **Integrate Results**: Use JSON/CSV outputs for further analysis
5. **Automate**: Schedule regular organization-wide compliance checks