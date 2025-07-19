# Service Conversion Prompt - GLUE

## 🎯 Copy this entire content and paste it to Cursor.ai

---

**I'm working on implementing Tier 3 for AWS compliance services.**

**Context:**
- Tier 1 is complete (all __init__.py and *_client.py files are generated)
- I need to convert service files from prowler to BaseService pattern
- I need to convert check files from prowler to BaseCheck pattern
- I'm working on the **glue** service

**Current Service Details:**
- **Service Name:** glue
- **Service File:** glue_service.py
- **Check Files:** 
  - glue_data_catalogs_connection_passwords_encryption_enabled
  - glue_data_catalogs_metadata_encryption_enabled
  - glue_data_catalogs_not_publicly_accessible
  - glue_database_connections_ssl_enabled
  - glue_development_endpoints_cloudwatch_logs_encryption_enabled
  - glue_development_endpoints_job_bookmark_encryption_enabled
  - glue_development_endpoints_s3_encryption_enabled
  - glue_etl_jobs_amazon_s3_encryption_enabled
  - glue_etl_jobs_cloudwatch_logs_encryption_enabled
  - glue_etl_jobs_job_bookmark_encryption_enabled
  - glue_etl_jobs_logging_enabled
  - glue_ml_transform_encrypted_at_rest

**What I need you to do:**

### Step 1: Analyze Current Files
- Read and analyze the current glue_service.py file
- Read and analyze all check files in the glue directory
- Understand the current prowler structure and dependencies
- Identify the resource types and their properties
- List all AWS API calls used by the service

### Step 2: Convert Service File
- Convert glue_service.py from prowler to BaseService pattern
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
- Import the corresponding service: from ..glue_service import GlueService
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
