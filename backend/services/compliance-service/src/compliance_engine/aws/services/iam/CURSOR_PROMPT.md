# Service Conversion Prompt - IAM

## 🎯 Copy this entire content and paste it to Cursor.ai

---

**I'm working on implementing Tier 3 for AWS compliance services.**

**Context:**
- Tier 1 is complete (all __init__.py and *_client.py files are generated)
- I need to convert service files from prowler to BaseService pattern
- I need to convert check files from prowler to BaseCheck pattern
- I'm working on the **iam** service

**Current Service Details:**
- **Service Name:** iam
- **Service File:** iam_service.py
- **Check Files:** 
  - iam_administrator_access_with_mfa
  - iam_avoid_root_usage
  - iam_aws_attached_policy_no_administrative_privileges
  - iam_check_saml_providers_sts
  - iam_customer_attached_policy_no_administrative_privileges
  - iam_customer_unattached_policy_no_administrative_privileges
  - iam_group_administrator_access_policy
  - iam_inline_policy_allows_privilege_escalation
  - iam_inline_policy_no_administrative_privileges
  - iam_inline_policy_no_full_access_to_cloudtrail
  - iam_inline_policy_no_full_access_to_kms
  - iam_no_custom_policy_permissive_role_assumption
  - iam_no_expired_server_certificates_stored
  - iam_no_root_access_key
  - iam_password_policy_expires_passwords_within_90_days_or_less
  - iam_password_policy_lowercase
  - iam_password_policy_minimum_length_14
  - iam_password_policy_number
  - iam_password_policy_reuse_24
  - iam_password_policy_symbol
  - iam_password_policy_uppercase
  - iam_policy_allows_privilege_escalation
  - iam_policy_attached_only_to_group_or_roles
  - iam_policy_cloudshell_admin_not_attached
  - iam_policy_no_full_access_to_cloudtrail
  - iam_policy_no_full_access_to_kms
  - iam_role_administratoraccess_policy
  - iam_role_cross_account_readonlyaccess_policy
  - iam_role_cross_service_confused_deputy_prevention
  - iam_root_credentials_management_enabled
  - iam_root_hardware_mfa_enabled
  - iam_root_mfa_enabled
  - iam_rotate_access_key_90_days
  - iam_securityaudit_role_created
  - iam_support_role_created
  - iam_user_accesskey_unused
  - iam_user_administrator_access_policy
  - iam_user_console_access_unused
  - iam_user_hardware_mfa_enabled
  - iam_user_mfa_enabled_console_access
  - iam_user_no_setup_initial_access_key
  - iam_user_two_active_access_key
  - iam_user_with_temporary_credentials

**What I need you to do:**

### Step 1: Analyze Current Files
- Read and analyze the current iam_service.py file
- Read and analyze all check files in the iam directory
- Understand the current prowler structure and dependencies
- Identify the resource types and their properties
- List all AWS API calls used by the service

### Step 2: Convert Service File
- Convert iam_service.py from prowler to BaseService pattern
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
- Import the corresponding service: from ..iam_service import IamService
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
