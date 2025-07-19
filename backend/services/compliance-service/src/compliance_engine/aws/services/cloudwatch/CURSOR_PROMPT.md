# Service Conversion Prompt - CLOUDWATCH

## 🎯 Copy this entire content and paste it to Cursor.ai

---

**I'm working on implementing Tier 3 for AWS compliance services.**

**Context:**
- Tier 1 is complete (all __init__.py and *_client.py files are generated)
- I need to convert service files from prowler to BaseService pattern
- I need to convert check files from prowler to BaseCheck pattern
- I'm working on the **cloudwatch** service

**Current Service Details:**
- **Service Name:** cloudwatch
- **Service File:** cloudwatch_service.py
- **Check Files:** 
  - cloudwatch_alarm_actions_alarm_state_configured
  - cloudwatch_alarm_actions_enabled
  - cloudwatch_changes_to_network_acls_alarm_configured
  - cloudwatch_changes_to_network_gateways_alarm_configured
  - cloudwatch_changes_to_network_route_tables_alarm_configured
  - cloudwatch_changes_to_vpcs_alarm_configured
  - cloudwatch_cross_account_sharing_disabled
  - cloudwatch_log_group_kms_encryption_enabled
  - cloudwatch_log_group_no_secrets_in_logs
  - cloudwatch_log_group_not_publicly_accessible
  - cloudwatch_log_group_retention_policy_specific_days_enabled
  - cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled
  - cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled
  - cloudwatch_log_metric_filter_authentication_failures
  - cloudwatch_log_metric_filter_aws_organizations_changes
  - cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk
  - cloudwatch_log_metric_filter_for_s3_bucket_policy_changes
  - cloudwatch_log_metric_filter_policy_changes
  - cloudwatch_log_metric_filter_root_usage
  - cloudwatch_log_metric_filter_security_group_changes
  - cloudwatch_log_metric_filter_sign_in_without_mfa
  - cloudwatch_log_metric_filter_unauthorized_api_calls

**What I need you to do:**

### Step 1: Analyze Current Files
- Read and analyze the current cloudwatch_service.py file
- Read and analyze all check files in the cloudwatch directory
- Understand the current prowler structure and dependencies
- Identify the resource types and their properties
- List all AWS API calls used by the service

### Step 2: Convert Service File
- Convert cloudwatch_service.py from prowler to BaseService pattern
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
- Import the corresponding service: from ..cloudwatch_service import CloudwatchService
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
