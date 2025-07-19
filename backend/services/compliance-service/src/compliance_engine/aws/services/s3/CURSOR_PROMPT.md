# Service Conversion Prompt - S3

## 🎯 Copy this entire content and paste it to Cursor.ai

---

**I'm working on implementing Tier 3 for AWS compliance services.**

**Context:**
- Tier 1 is complete (all __init__.py and *_client.py files are generated)
- I need to convert service files from prowler to BaseService pattern
- I need to convert check files from prowler to BaseCheck pattern
- I'm working on the **s3** service

**Current Service Details:**
- **Service Name:** s3
- **Service File:** s3_service.py
- **Check Files:** 
  - s3_access_point_public_access_block
  - s3_account_level_public_access_blocks
  - s3_bucket_acl_prohibited
  - s3_bucket_cross_account_access
  - s3_bucket_cross_region_replication
  - s3_bucket_default_encryption
  - s3_bucket_event_notifications_enabled
  - s3_bucket_kms_encryption
  - s3_bucket_level_public_access_block
  - s3_bucket_lifecycle_enabled
  - s3_bucket_no_mfa_delete
  - s3_bucket_object_lock
  - s3_bucket_object_versioning
  - s3_bucket_policy_public_write_access
  - s3_bucket_public_access
  - s3_bucket_public_list_acl
  - s3_bucket_public_write_acl
  - s3_bucket_secure_transport_policy
  - s3_bucket_server_access_logging_enabled
  - s3_multi_region_access_point_public_access_block

**What I need you to do:**

### Step 1: Analyze Current Files
- Read and analyze the current s3_service.py file
- Read and analyze all check files in the s3 directory
- Understand the current prowler structure and dependencies
- Identify the resource types and their properties
- List all AWS API calls used by the service

### Step 2: Convert Service File
- Convert s3_service.py from prowler to BaseService pattern
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
- Import the corresponding service: from ..s3_service import S3Service
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
