# Service Conversion Prompt - VPC

## 🎯 Copy this entire content and paste it to Cursor.ai

---

**I'm working on implementing Tier 3 for AWS compliance services.**

**Context:**
- Tier 1 is complete (all __init__.py and *_client.py files are generated)
- I need to convert service files from prowler to BaseService pattern
- I need to convert check files from prowler to BaseCheck pattern
- I'm working on the **vpc** service

**Current Service Details:**
- **Service Name:** vpc
- **Service File:** vpc_service.py
- **Check Files:** 
  - vpc_different_regions
  - vpc_endpoint_connections_trust_boundaries
  - vpc_endpoint_for_ec2_enabled
  - vpc_endpoint_multi_az_enabled
  - vpc_endpoint_services_allowed_principals_trust_boundaries
  - vpc_flow_logs_enabled
  - vpc_peering_routing_tables_with_least_privilege
  - vpc_subnet_different_az
  - vpc_subnet_no_public_ip_by_default
  - vpc_subnet_separate_private_public
  - vpc_vpn_connection_tunnels_up

**What I need you to do:**

### Step 1: Analyze Current Files
- Read and analyze the current vpc_service.py file
- Read and analyze all check files in the vpc directory
- Understand the current prowler structure and dependencies
- Identify the resource types and their properties
- List all AWS API calls used by the service

### Step 2: Convert Service File
- Convert vpc_service.py from prowler to BaseService pattern
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
- Import the corresponding service: from ..vpc_service import VpcService
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
