# Service Conversion Prompt - RDS

## 🎯 Copy this entire content and paste it to Cursor.ai

---

**I'm working on implementing Tier 3 for AWS compliance services.**

**Context:**
- Tier 1 is complete (all __init__.py and *_client.py files are generated)
- I need to convert service files from prowler to BaseService pattern
- I need to convert check files from prowler to BaseCheck pattern
- I'm working on the **rds** service

**Current Service Details:**
- **Service Name:** rds
- **Service File:** rds_service.py
- **Check Files:** 
  - rds_cluster_backtrack_enabled
  - rds_cluster_copy_tags_to_snapshots
  - rds_cluster_critical_event_subscription
  - rds_cluster_default_admin
  - rds_cluster_deletion_protection
  - rds_cluster_iam_authentication_enabled
  - rds_cluster_integration_cloudwatch_logs
  - rds_cluster_minor_version_upgrade_enabled
  - rds_cluster_multi_az
  - rds_cluster_non_default_port
  - rds_cluster_protected_by_backup_plan
  - rds_cluster_storage_encrypted
  - rds_instance_backup_enabled
  - rds_instance_certificate_expiration
  - rds_instance_copy_tags_to_snapshots
  - rds_instance_critical_event_subscription
  - rds_instance_default_admin
  - rds_instance_deletion_protection
  - rds_instance_deprecated_engine_version
  - rds_instance_enhanced_monitoring_enabled
  - rds_instance_event_subscription_parameter_groups
  - rds_instance_event_subscription_security_groups
  - rds_instance_iam_authentication_enabled
  - rds_instance_inside_vpc
  - rds_instance_integration_cloudwatch_logs
  - rds_instance_minor_version_upgrade_enabled
  - rds_instance_multi_az
  - rds_instance_no_public_access
  - rds_instance_non_default_port
  - rds_instance_protected_by_backup_plan
  - rds_instance_storage_encrypted
  - rds_instance_transport_encrypted
  - rds_snapshots_encrypted
  - rds_snapshots_public_access

**What I need you to do:**

### Step 1: Analyze Current Files
- Read and analyze the current rds_service.py file
- Read and analyze all check files in the rds directory
- Understand the current prowler structure and dependencies
- Identify the resource types and their properties
- List all AWS API calls used by the service

### Step 2: Convert Service File
- Convert rds_service.py from prowler to BaseService pattern
- Remove ALL prowler dependencies
- Import BaseService and ComplianceResult from base
- Implement _get_service_name() method
- Implement _load_resources_for_region() method
- Define service-specific data models (Pydantic classes)
- Add proper error handling and logging
- Include type hints for all methods

### Step 3: Convert Check Files
- Convert all check files from prowler to BaseCheck pattern
- Remove ALL prowler dependencies
- Import BaseCheck and ComplianceResult from base
- Import the corresponding service: from ..rds_service import RdsService
- Implement execute() method for each check with proper return type: List[ComplianceResult]
- Implement compliance logic for each check
- Add proper error handling with try/catch blocks
- Add logging with logger.error() for exceptions
- Include type hints for all methods

### Step 4: Quality Assurance
- Verify no prowler dependencies remain in any file
- Check that all imports work correctly
- Ensure error handling is implemented with try/catch
- Verify type hints are present, especially return types
- Confirm logging is configured with logger = logging.getLogger(__name__)
- Test that the service can be imported
- Test that check files can be imported

### Step 5: Testing
- Test service imports work correctly
- Test check imports work correctly
- Test service functionality
- Test check execution
- Ensure no errors occur

**Requirements:**
- Remove ALL prowler dependencies
- Use BaseService and BaseCheck patterns
- Add proper error handling and logging
- Include type hints, especially List[ComplianceResult] return type
- Follow the established patterns from completed services (bedrock, accessanalyzer, backup, etc.)

**Please start with Step 1 and proceed through each step systematically.**

---
