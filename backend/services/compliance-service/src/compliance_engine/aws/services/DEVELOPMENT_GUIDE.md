# AWS Compliance Services - Development Guide

## 🎯 Overview

This guide ensures **100% quality** during the manual implementation of AWS compliance services (Tier 3). All Tier 1 automation is complete - now we need to manually implement service-specific logic using **Cursor.ai**.

## 📋 Current Status

### ✅ Completed (Tier 1 - 100% Automated)
- `__init__.py` files with modular imports
- `*_client.py` files with singleton pattern
- **Total Services**: 82
- **Services Updated**: 72

### 🔄 Pending (Tier 3 - Manual Implementation)
- Service files (`*_service.py`) - Convert from prowler to BaseService
- Individual check files - Convert from prowler to BaseCheck
- **Total Services to Update**: 72

## 🚀 How to Work with Cursor.ai

### **Step 1: Find the Service Prompt**
Each service folder contains a `CURSOR_PROMPT.md` file with a complete, templated prompt.

### **Step 2: Copy and Paste**
1. **Navigate to the service folder** you want to work on (e.g., `cloudformation/`)
2. **Open the `CURSOR_PROMPT.md` file**
3. **Copy the entire content** (from the line above "---" to the line below "---")
4. **Paste it to Cursor.ai** in a new conversation

### **Step 3: Follow the Process**
Cursor.ai will guide you through the 5-step process:
1. **Analyze Current Files** - Understand the existing structure
2. **Convert Service File** - Convert to BaseService pattern
3. **Convert Check Files** - Convert all check files to BaseCheck pattern
4. **Quality Assurance** - Verify everything is correct
5. **Testing** - Ensure everything works

### **Step 4: Move to Next Service**
Once a service is complete, move to the next service folder and repeat the process.

## 🏗️ Architecture Pattern

### Service File Structure
```python
"""
AWS {ServiceName} Service

Service abstraction for AWS {ServiceName} compliance checks.
"""

import boto3
import logging
from typing import Optional, Dict, List, Any
from pydantic import BaseModel

# Import the base service class
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from base import BaseService, ComplianceResult

logger = logging.getLogger(__name__)


class Resource(BaseModel):
    """{ServiceName} resource model"""
    # MANUAL: Define service-specific fields
    pass


class {ServiceName}Service(BaseService):
    """AWS {ServiceName} service for compliance checks"""
    
    def __init__(self, session: boto3.Session = None, region: str = None):
        super().__init__(session, region)
        self.resources: Dict[str, Resource] = {}
    
    def _get_service_name(self) -> str:
        return "{service_name}"
    
    def _load_resources_for_region(self, region: str) -> None:
        """Load {ServiceName} resources for the specified region"""
        # MANUAL: Implement service-specific logic
        pass
    
    def get_all_resources(self, region: str = None) -> List[Resource]:
        """Get all {ServiceName} resources for the specified region"""
        if not region:
            region = self.region or 'us-east-1'
        
        if region not in self.resources:
            self._load_resources_for_region(region)
        
        return list(self.resources.values())
```

### Check File Structure
```python
"""
AWS {ServiceName} Compliance Check

Check: {check_description}
"""

import logging
from typing import List

# Import the base check class
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from base import BaseCheck, ComplianceResult
from ..{service_name}_service import {ServiceName}Service

logger = logging.getLogger(__name__)


class {check_name}(BaseCheck):
    """Check: {check_description}"""
    
    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = {ServiceName}Service(session, region)
    
    def execute(self, region=None) -> List[ComplianceResult]:
        """Execute the compliance check"""
        results = []
        
        # MANUAL: Implement check-specific logic
        resources = self.service.get_all_resources(region)
        
        for resource in resources:
            # MANUAL: Implement compliance logic
            if self._is_compliant(resource):
                status = "PASS"
                message = f"Resource {resource.name} is compliant"
            else:
                status = "FAIL"
                message = f"Resource {resource.name} is not compliant"
            
            results.append(ComplianceResult(
                resource_id=resource.arn,
                resource_name=resource.name,
                status=status,
                message=message,
                region=resource.region,
                service=self.service._get_service_name(),
                check_name=self.__class__.__name__
            ))
        
        return results
    
    def _is_compliant(self, resource) -> bool:
        """Check if resource is compliant"""
        # MANUAL: Implement compliance logic
        return True
```

## 🔄 Development Workflow

### Step 1: Service Analysis
1. **Examine existing service file** (e.g., `cloudformation_service.py`)
2. **Identify resource types** and their properties
3. **List AWS API calls** used by the service
4. **Document business logic** for each check

### Step 2: Service Implementation
1. **Create data models** (Pydantic classes)
2. **Implement `_load_resources_for_region`** method
3. **Add resource getter methods**
4. **Test service functionality**

### Step 3: Check Implementation
1. **Analyze existing check logic**
2. **Convert to BaseCheck pattern**
3. **Implement compliance logic**
4. **Test individual checks**

### Step 4: Quality Assurance
1. **Run linting** (flake8, mypy)
2. **Test imports** work correctly
3. **Verify AWS API calls**
4. **Check error handling**

## 📝 Quality Checklist

### Service File Checklist
- [ ] Imports BaseService and ComplianceResult
- [ ] Defines service-specific data models
- [ ] Implements `_get_service_name()` method
- [ ] Implements `_load_resources_for_region()` method
- [ ] Provides resource getter methods
- [ ] Handles AWS API errors gracefully
- [ ] Uses proper logging
- [ ] Follows typing annotations

### Check File Checklist
- [ ] Imports BaseCheck and ComplianceResult
- [ ] Imports corresponding service
- [ ] Implements `execute()` method
- [ ] Returns list of ComplianceResult objects
- [ ] Handles errors gracefully
- [ ] Uses proper logging
- [ ] Follows typing annotations

### General Checklist
- [ ] No prowler dependencies
- [ ] No hardcoded values
- [ ] Proper error handling
- [ ] Consistent naming conventions
- [ ] Documentation and comments
- [ ] Type hints for all functions

## 🚨 Common Issues & Solutions

### Issue 1: Import Errors
```python
# ❌ Wrong
from prowler.providers.aws.lib.service.service import AWSService

# ✅ Correct
from base import BaseService, ComplianceResult
```

### Issue 2: Missing Error Handling
```python
# ❌ Wrong
response = client.list_resources()

# ✅ Correct
try:
    response = client.list_resources()
except Exception as e:
    logger.error(f"Error listing resources: {e}")
    return
```

### Issue 3: Incorrect Return Types
```python
# ❌ Wrong
def execute(self) -> ComplianceResult:

# ✅ Correct
def execute(self, region=None) -> List[ComplianceResult]:
```

### Issue 4: Missing Resource Properties
```python
# ❌ Wrong
class Resource(BaseModel):
    name: str

# ✅ Correct
class Resource(BaseModel):
    name: str
    arn: str
    region: str
    # ... all required properties
```

## 🛠️ Development Tools

### 1. Quality Assurance Script
```bash
# Check quality of a specific service
python quality_assurance.py cloudformation

# Check quality of all services
python quality_assurance.py
```

### 2. Template Generator
```bash
# Generate service template
python template_generator.py service cloudformation cloudformation_service_template.py

# Generate check template
python template_generator.py check cloudformation cloudformation_stack_termination_protection_enabled "Check if stacks have termination protection" cloudformation_stack_termination_protection_enabled_template.py
```

## 📊 Progress Tracking

### Services Completed (11)
- ✅ accessanalyzer
- ✅ account
- ✅ acm
- ✅ apigatewayv2
- ✅ appstream
- ✅ appsync
- ✅ athena
- ✅ autoscaling
- ✅ awslambda
- ✅ backup
- ✅ bedrock

### Services Pending (71)
- 🔄 cloudformation
- 🔄 cloudfront
- 🔄 cloudtrail
- 🔄 cloudwatch
- 🔄 codeartifact
- 🔄 codebuild
- 🔄 cognito
- 🔄 config
- 🔄 datasync
- 🔄 directconnect
- 🔄 directoryservice
- 🔄 dlm
- 🔄 dms
- 🔄 documentdb
- 🔄 drs
- 🔄 dynamodb
- 🔄 ec2
- 🔄 ecr
- 🔄 ecs
- 🔄 efs
- 🔄 eks
- 🔄 elasticache
- 🔄 elasticbeanstalk
- 🔄 elb
- 🔄 elbv2
- 🔄 emr
- 🔄 eventbridge
- 🔄 firehose
- 🔄 fms
- 🔄 fsx
- 🔄 glacier
- 🔄 globalaccelerator
- 🔄 glue
- 🔄 guardduty
- 🔄 iam
- 🔄 inspector2
- 🔄 kafka
- 🔄 kinesis
- 🔄 kms
- 🔄 lightsail
- 🔄 macie
- 🔄 memorydb
- 🔄 mq
- 🔄 neptune
- 🔄 networkfirewall
- 🔄 opensearch
- 🔄 organizations
- 🔄 rds
- 🔄 redshift
- 🔄 resourceexplorer2
- 🔄 route53
- 🔄 s3
- 🔄 sagemaker
- 🔄 secretsmanager
- 🔄 securityhub
- 🔄 servicecatalog
- 🔄 ses
- 🔄 shield
- 🔄 sns
- 🔄 sqs
- 🔄 ssm
- 🔄 ssmincidents
- 🔄 stepfunctions
- 🔄 storagegateway
- 🔄 transfer
- 🔄 trustedadvisor
- 🔄 vpc
- 🔄 waf
- 🔄 wafv2
- 🔄 wellarchitected
- 🔄 workspaces

## 🧪 Testing Commands

### Test Service
```python
# Test service imports
python -c "from cloudformation import CloudFormationService; print('Import successful')"

# Test service functionality
python -c "
from cloudformation import CloudFormationService
service = CloudFormationService()
resources = service.get_all_resources('us-east-1')
print(f'Found {len(resources)} resources')
"
```

### Test Check
```python
# Test check imports
python -c "from cloudformation import cloudformation_stacks_termination_protection_enabled; print('Import successful')"

# Test check execution
python -c "
from cloudformation import cloudformation_stacks_termination_protection_enabled
check = cloudformation_stacks_termination_protection_enabled()
results = check.execute('us-east-1')
print(f'Found {len(results)} results')
"
```

## 📞 Support

For questions or issues during development:

1. **Check this guide first**
2. **Review existing implementations** (accessanalyzer, account, acm, etc.)
3. **Use the quality checklist**
4. **Run quality assurance script**
5. **Test thoroughly before committing**

## 🎯 Success Criteria

A service is considered **complete** when:
- [ ] Service file follows BaseService pattern
- [ ] All check files follow BaseCheck pattern
- [ ] No prowler dependencies remain
- [ ] All imports work correctly
- [ ] Error handling is implemented
- [ ] Linting passes without errors
- [ ] Tests pass successfully

## 🚀 Quick Start

```bash
# 1. Navigate to a service folder
cd cloudformation

# 2. Copy the prompt content
cat CURSOR_PROMPT.md

# 3. Paste to Cursor.ai and follow the 5-step process
# 4. Run quality check
python quality_assurance.py cloudformation

# 5. Test functionality
python -c "from cloudformation import CloudFormationService; print('Success!')"
```

**Happy coding with Cursor.ai! 🎉** 