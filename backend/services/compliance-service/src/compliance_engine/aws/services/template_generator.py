#!/usr/bin/env python3
"""
Template Generator for AWS Compliance Services

This script generates templates for service and check files to ensure
consistency and quality during development.
"""

import os
import sys
from typing import List, Dict


class TemplateGenerator:
    """Template generator for AWS compliance services"""
    
    def __init__(self):
        self.service_templates = {}
        self.check_templates = {}
    
    def generate_service_template(self, service_name: str, resource_fields: List[str] = None) -> str:
        """Generate a service file template"""
        
        service_class_name = self._get_service_class_name(service_name)
        
        # Default resource fields if not provided
        if not resource_fields:
            resource_fields = [
                "name: str",
                "arn: str", 
                "region: str",
                "tags: List[Dict[str, str]] = []"
            ]
        
        resource_fields_str = "\n    ".join([f"{field}," for field in resource_fields])
        
        template = f'''"""
AWS {service_name.title()} Service

Service abstraction for AWS {service_name.title()} compliance checks.
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


class {service_name.title()}Resource(BaseModel):
    """{service_name.title()} resource model"""
    {resource_fields_str}


class {service_class_name}(BaseService):
    """AWS {service_name.title()} service for compliance checks"""
    
    def __init__(self, session: boto3.Session = None, region: str = None):
        super().__init__(session, region)
        self.resources: Dict[str, {service_name.title()}Resource] = {{}}
    
    def _get_service_name(self) -> str:
        return "{service_name}"
    
    def _load_resources_for_region(self, region: str) -> None:
        """Load {service_name.title()} resources for the specified region"""
        try:
            client = self._get_client(region)
            
            # TODO: Implement service-specific logic
            # Example:
            # self._load_resources(client, region)
            # self._load_resource_details(client, region)
            # self._load_tags(client, region)
            
            logger.info(f"Loaded {{len(self.resources)}} {service_name} resources in {{region}}")
            
        except Exception as e:
            logger.error(f"Error loading {service_name} resources in {{region}}: {{e}}")
    
    def _load_resources(self, client, region: str) -> None:
        """Load basic {service_name} resources"""
        try:
            # TODO: Implement resource loading logic
            # Example:
            # response = client.list_resources()
            # for resource_data in response.get("Resources", []):
            #     resource = {service_name.title()}Resource(
            #         name=resource_data["Name"],
            #         arn=resource_data["Arn"],
            #         region=region
            #     )
            #     self.resources[resource.arn] = resource
            pass
            
        except Exception as e:
            logger.error(f"Error loading {service_name} resources in {{region}}: {{e}}")
    
    def _load_resource_details(self, client, region: str) -> None:
        """Load detailed information for {service_name} resources"""
        try:
            # TODO: Implement resource detail loading
            # Example:
            # for resource in self.resources.values():
            #     if resource.region == region:
            #         try:
            #             details = client.get_resource_details(ResourceId=resource.arn)
            #             # Update resource with details
            #         except Exception as e:
            #             logger.error(f"Error loading details for {{resource.name}}: {{e}}")
            pass
            
        except Exception as e:
            logger.error(f"Error loading {service_name} resource details in {{region}}: {{e}}")
    
    def _load_tags(self, client, region: str) -> None:
        """Load tags for {service_name} resources"""
        try:
            # TODO: Implement tag loading
            # Example:
            # for resource in self.resources.values():
            #     if resource.region == region:
            #         try:
            #             tags_response = client.list_tags_for_resource(ResourceArn=resource.arn)
            #             resource.tags = tags_response.get("Tags", [])
            #         except Exception as e:
            #             logger.error(f"Error loading tags for {{resource.name}}: {{e}}")
            pass
            
        except Exception as e:
            logger.error(f"Error loading {service_name} tags in {{region}}: {{e}}")
    
    def get_all_resources(self, region: str = None) -> List[{service_name.title()}Resource]:
        """
        Get all {service_name.title()} resources for the specified region
        
        Args:
            region: AWS region (optional)
            
        Returns:
            List of {service_name.title()}Resource objects
        """
        if not region:
            region = self.region or 'us-east-1'
        
        if region not in self.resources:
            self._load_resources_for_region(region)
        
        return list(self.resources.values())
    
    def get_resource_by_arn(self, arn: str) -> Optional[{service_name.title()}Resource]:
        """
        Get a specific {service_name} resource by ARN
        
        Args:
            arn: Resource ARN
            
        Returns:
            {service_name.title()}Resource object or None
        """
        return self.resources.get(arn)
    
    def get_resources_by_region(self, region: str) -> List[{service_name.title()}Resource]:
        """
        Get all {service_name} resources for a specific region
        
        Args:
            region: AWS region
            
        Returns:
            List of {service_name.title()}Resource objects
        """
        return [r for r in self.resources.values() if r.region == region]
'''
        
        return template
    
    def generate_check_template(self, service_name: str, check_name: str, check_description: str) -> str:
        """Generate a check file template"""
        
        service_class_name = self._get_service_class_name(service_name)
        
        template = f'''"""
AWS {service_name.title()} Compliance Check

Check: {check_description}
"""

import logging
from typing import List

# Import the base check class
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from base import BaseCheck, ComplianceResult
from ..{service_name}_service import {service_class_name}

logger = logging.getLogger(__name__)


class {check_name}(BaseCheck):
    """Check: {check_description}"""
    
    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = {service_class_name}(session, region)
    
    def execute(self, region=None) -> List[ComplianceResult]:
        """Execute the compliance check"""
        results = []
        
        try:
            resources = self.service.get_all_resources(region)
            
            for resource in resources:
                try:
                    # TODO: Implement compliance logic
                    is_compliant = self._is_compliant(resource)
                    
                    if is_compliant:
                        status = "PASS"
                        message = f"{{service_name.title()}} resource {{resource.name}} is compliant"
                    else:
                        status = "FAIL"
                        message = f"{{service_name.title()}} resource {{resource.name}} is not compliant"
                    
                    results.append(ComplianceResult(
                        resource_id=resource.arn,
                        resource_name=resource.name,
                        status=status,
                        message=message,
                        region=resource.region,
                        service=self.service._get_service_name(),
                        check_name=self.__class__.__name__
                    ))
                    
                except Exception as e:
                    logger.error(f"Error checking resource {{resource.name}}: {{e}}")
                    results.append(ComplianceResult(
                        resource_id=resource.arn,
                        resource_name=resource.name,
                        status="ERROR",
                        message=f"Error during check: {{e}}",
                        region=resource.region,
                        service=self.service._get_service_name(),
                        check_name=self.__class__.__name__
                    ))
            
        except Exception as e:
            logger.error(f"Error executing {check_name}: {{e}}")
            # Return error result
            results.append(ComplianceResult(
                resource_id="",
                resource_name="",
                status="ERROR",
                message=f"Service error: {{e}}",
                region=region or self.region or "unknown",
                service=service_name,
                check_name=self.__class__.__name__
            ))
        
        return results
    
    def _is_compliant(self, resource) -> bool:
        """
        Check if resource is compliant
        
        Args:
            resource: {service_name.title()}Resource object
            
        Returns:
            True if compliant, False otherwise
        """
        # TODO: Implement compliance logic
        # Example:
        # return resource.some_property == expected_value
        
        return True
'''
        
        return template
    
    def _get_service_class_name(self, service_name: str) -> str:
        """Convert service name to class name"""
        special_cases = {
            'awslambda': 'LambdaService',
            'apigatewayv2': 'ApiGatewayV2Service',
            'directoryservice': 'DirectoryService',
            'resourceexplorer2': 'ResourceExplorer2Service',
            'ssmincidents': 'SsmIncidentsService',
            'stepfunctions': 'StepFunctionsService',
            'trustedadvisor': 'TrustedAdvisorService',
            'wellarchitected': 'WellArchitectedService',
            'workspaces': 'WorkSpacesService',
            'secretsmanager': 'SecretsManagerService',
            'securityhub': 'SecurityHubService',
            'servicecatalog': 'ServiceCatalogService',
            'storagegateway': 'StorageGatewayService',
            'globalaccelerator': 'GlobalAcceleratorService',
            'datasync': 'DataSyncService',
            'documentdb': 'DocumentDBService',
            'memorydb': 'MemoryDBService',
            'opensearch': 'OpenSearchService',
            'elasticache': 'ElastiCacheService',
            'elasticbeanstalk': 'ElasticBeanstalkService',
            'eventbridge': 'EventBridgeService',
            'codeartifact': 'CodeArtifactService',
            'codebuild': 'CodeBuildService',
            'cloudformation': 'CloudFormationService',
            'cloudfront': 'CloudFrontService',
            'cloudtrail': 'CloudTrailService',
            'cloudwatch': 'CloudWatchService',
            'directconnect': 'DirectConnectService',
            'dynamodb': 'DynamoDBService',
            'firehose': 'FirehoseService',
            'lightsail': 'LightsailService',
            'sagemaker': 'SageMakerService',
            'sns': 'SNSService',
            'sqs': 'SQSService',
            'ssm': 'SSMService',
            'transfer': 'TransferService',
            'waf': 'WAFService',
            'wafv2': 'WAFV2Service',
            'ses': 'SESService',
            'shield': 'ShieldService',
            'kafka': 'KafkaService',
            'kinesis': 'KinesisService',
            'kms': 'KMSService',
            'macie': 'MacieService',
            'mq': 'MQService',
            'neptune': 'NeptuneService',
            'networkfirewall': 'NetworkFirewallService',
            'organizations': 'OrganizationsService',
            'guardduty': 'GuardDutyService',
            'iam': 'IAMService',
            'inspector2': 'Inspector2Service',
            'glacier': 'GlacierService',
            'glue': 'GlueService',
            'ec2': 'EC2Service',
            'ecr': 'ECRService',
            'ecs': 'ECSService',
            'efs': 'EFSService',
            'eks': 'EKSService',
            'elb': 'ELBService',
            'elbv2': 'ELBV2Service',
            'emr': 'EMRService',
            'fms': 'FMSService',
            'fsx': 'FSxService',
            'rds': 'RDSService',
            'redshift': 'RedshiftService',
            'route53': 'Route53Service',
            's3': 'S3Service',
            'dms': 'DMSService',
            'drs': 'DRSService',
            'dlm': 'DLMService',
            'vpc': 'VPCService',
            'cognito': 'CognitoService',
            'config': 'ConfigService',
            'athena': 'AthenaService',
            'autoscaling': 'AutoScalingService',
            'backup': 'BackupService',
            'bedrock': 'BedrockService',
            'accessanalyzer': 'AccessAnalyzerService',
            'account': 'AccountService',
            'acm': 'ACMService',
            'appstream': 'AppStreamService',
            'appsync': 'AppSyncService'
        }
        
        if service_name in special_cases:
            return special_cases[service_name]
        
        return service_name.title().replace('_', '') + 'Service'
    
    def save_service_template(self, service_name: str, output_path: str, resource_fields: List[str] = None):
        """Save a service template to a file"""
        template = self.generate_service_template(service_name, resource_fields)
        
        with open(output_path, 'w') as f:
            f.write(template)
        
        print(f"✅ Service template saved to: {output_path}")
    
    def save_check_template(self, service_name: str, check_name: str, check_description: str, output_path: str):
        """Save a check template to a file"""
        template = self.generate_check_template(service_name, check_name, check_description)
        
        with open(output_path, 'w') as f:
            f.write(template)
        
        print(f"✅ Check template saved to: {output_path}")


def main():
    """Main function"""
    generator = TemplateGenerator()
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python template_generator.py service <service_name> [output_path]")
        print("  python template_generator.py check <service_name> <check_name> <description> [output_path]")
        return
    
    command = sys.argv[1]
    
    if command == "service":
        if len(sys.argv) < 3:
            print("❌ Service name required")
            return
        
        service_name = sys.argv[2]
        output_path = sys.argv[3] if len(sys.argv) > 3 else f"{service_name}_service_template.py"
        
        generator.save_service_template(service_name, output_path)
        
    elif command == "check":
        if len(sys.argv) < 5:
            print("❌ Service name, check name, and description required")
            return
        
        service_name = sys.argv[2]
        check_name = sys.argv[3]
        description = sys.argv[4]
        output_path = sys.argv[5] if len(sys.argv) > 5 else f"{check_name}_template.py"
        
        generator.save_check_template(service_name, check_name, description, output_path)
        
    else:
        print(f"❌ Unknown command: {command}")


if __name__ == "__main__":
    main() 