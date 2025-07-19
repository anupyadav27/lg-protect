# Service Conversion Prompt - AWSLAMBDA

## 🎯 Copy this entire content and paste it to Cursor.ai

---

**I'm working on implementing Tier 3 for AWS compliance services.**

**Context:**
- Tier 1 is complete (all __init__.py and *_client.py files are generated)
- The awslambda service file has already been converted to BaseService pattern
- I need to convert check files from prowler to BaseCheck pattern
- I'm working on the **awslambda** service

**Current Service Details:**
- **Service Name:** awslambda
- **Service File:** awslambda_service.py ✅ (Already converted to BaseService)
- **Check Files:** (Need conversion from prowler to BaseCheck)
  - awslambda_function_inside_vpc
  - awslambda_function_invoke_api_operations_cloudtrail_logging_enabled
  - awslambda_function_no_secrets_in_code
  - awslambda_function_no_secrets_in_variables
  - awslambda_function_not_publicly_accessible
  - awslambda_function_url_cors_policy
  - awslambda_function_url_public
  - awslambda_function_using_supported_runtimes
  - awslambda_function_vpc_multi_az

**What I need you to do:**

### Step 1: Analyze Current State
- The awslambda_service.py file is already converted to BaseService pattern
- Read and analyze all check files in the awslambda directory
- Understand the current prowler structure and dependencies in check files
- Identify what each check is validating
- List the AWS API calls and data used by each check

### Step 2: Convert Check Files
- Convert all check files from prowler to BaseCheck pattern
- Remove ALL prowler dependencies from check files
- Import BaseCheck and ComplianceResult from base
- Import the AwslambdaService from awslambda_service
- Implement execute() method for each check with proper return type: List[ComplianceResult]
- Implement compliance logic for each check
- Add proper error handling with try/catch blocks
- Add logging with logger.error() for exceptions
- Include type hints for all methods

### Step 3: Quality Assurance
- Verify no prowler dependencies remain in any check file
- Check that all imports work correctly
- Ensure error handling is implemented with try/catch
- Verify type hints are present, especially return types
- Confirm logging is configured with logger = logging.getLogger(__name__)
- Test that check files can be imported
- Test that check files can execute

### Step 4: Testing
- Test check imports work correctly
- Test check execution works
- Test service integration
- Ensure no errors occur

**Requirements:**
- Remove ALL prowler dependencies from check files
- Use BaseCheck pattern for all check files
- Import AwslambdaService from awslambda_service.py
- Add proper error handling and logging
- Include type hints, especially List[ComplianceResult] return type
- Follow the established patterns from completed services (bedrock, accessanalyzer, backup, etc.)

**Please start with Step 1 and proceed through each step systematically.**

---
