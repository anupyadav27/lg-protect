# Service Conversion Prompt - CLOUDFRONT

## 🎯 Copy this entire content and paste it to Cursor.ai

---

**I'm working on implementing Tier 3 for AWS compliance services.**

**Context:**
- Tier 1 is complete (all __init__.py and *_client.py files are generated)
- I need to convert service files from prowler to BaseService pattern
- I need to convert check files from prowler to BaseCheck pattern
- I'm working on the **cloudfront** service

**Current Service Details:**
- **Service Name:** cloudfront
- **Service File:** cloudfront_service.py
- **Check Files:** 
  - cloudfront_distributions_custom_ssl_certificate
  - cloudfront_distributions_default_root_object
  - cloudfront_distributions_field_level_encryption_enabled
  - cloudfront_distributions_geo_restrictions_enabled
  - cloudfront_distributions_https_enabled
  - cloudfront_distributions_https_sni_enabled
  - cloudfront_distributions_logging_enabled
  - cloudfront_distributions_multiple_origin_failover_configured
  - cloudfront_distributions_origin_traffic_encrypted
  - cloudfront_distributions_s3_origin_access_control
  - cloudfront_distributions_s3_origin_non_existent_bucket
  - cloudfront_distributions_using_deprecated_ssl_protocols
  - cloudfront_distributions_using_waf

**What I need you to do:**

### Step 1: Analyze Current Files
- Read and analyze the current cloudfront_service.py file
- Read and analyze all check files in the cloudfront directory
- Understand the current prowler structure and dependencies
- Identify the resource types and their properties
- List all AWS API calls used by the service

### Step 2: Convert Service File
- Convert cloudfront_service.py from prowler to BaseService pattern
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
- Import the corresponding service: from ..cloudfront_service import CloudfrontService
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
