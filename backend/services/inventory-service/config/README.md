# Configuration Directory

This directory contains the core configuration files for the LG-Protect Inventory Service.

## 📁 **File Structure**

```
config/
├── enhanced_service_mapping.json     # Enhanced service mapping with multi-resource support
├── service_enablement_mapping.json   # Legacy service mapping (fallback)
├── service_categories.json           # Service categorization definitions
├── risk_weights.json                # Risk calculation parameters
└── README.md                        # This file
```

## 🎯 **Configuration Files**

### **1. enhanced_service_mapping.json**
- **Purpose**: Enhanced service mapping with multi-resource type support
- **Contains**: 92 AWS services with comprehensive metadata
- **Features**: 
  - Multi-resource types per service (e.g., EC2 instances, volumes, launch templates)
  - ARN format templates for automatic ARN generation
  - Category and scope classification
  - Client types and check functions for boto3 integration
- **Usage**: Primary source for enhanced resource discovery

### **2. service_enablement_mapping.json**
- **Purpose**: Legacy service mapping (fallback)
- **Contains**: Basic service configuration for backward compatibility
- **Usage**: Fallback when enhanced mapping is not available

### **3. service_categories.json**
- **Purpose**: Service categorization definitions
- **Contains**: 10 categories (compute, storage, database, network, security, etc.)
- **Usage**: Reference for service organization and discovery engine configuration

### **4. risk_weights.json**
- **Purpose**: Risk calculation parameters
- **Contains**: Category weights, severity impact, service criticality scores
- **Usage**: Risk assessment and scoring algorithms

## ✅ **Benefits of Enhanced Configuration**

1. **Multi-Resource Support**: Each service can discover multiple resource types
2. **Automatic ARN Generation**: ARNs generated using format templates
3. **Category Classification**: Services organized by function and scope
4. **Enhanced Error Handling**: Robust error handling for access denied, service not available
5. **Configuration-Driven**: Easy to add new services and resource types

## 🔧 **Usage Examples**

### **Load Enhanced Service Mapping**
```python
from src.utils.enhanced_extraction import EnhancedResourceExtractor

extractor = EnhancedResourceExtractor()
services = extractor.service_mapping
```

### **Extract Resources with ARNs**
```python
from src.utils.enhanced_extraction import EnhancedResourceExtractor

extractor = EnhancedResourceExtractor()
results = extractor.extract_all_resources(region, services)
```

## 📊 **Service Categories**

| Category | Services | Count |
|----------|----------|-------|
| **compute** | ec2, lambda, ecs, eks, batch, sagemaker, workspaces, elasticbeanstalk, lightsail, autoscaling | 10 |
| **storage** | s3, ebs, efs, fsx, backup, storagegateway, glacier, datasync | 8 |
| **database** | rds, dynamodb, elasticache, redshift, neptune, documentdb, timestream | 7 |
| **network** | vpc, cloudfront, route53, apigateway, apigatewayv2, elbv2, directconnect, globalaccelerator, networkfirewall, vpc-lattice, vpn | 11 |
| **security** | iam, kms, guardduty, securityhub, inspector2, secretsmanager, waf, wafv2, shield, acm, macie | 11 |
| **monitoring** | cloudwatch, cloudtrail, config, logs, xray, systems-manager | 6 |
| **analytics** | athena, glue, emr, kinesis, firehose, quicksight, elasticsearch | 7 |
| **application** | sns, sqs, events, stepfunctions, connect, chime, ses, pinpoint, eventbridge | 9 |
| **management** | cloudformation, organizations, ssm, transfer, control-tower, service-catalog, resource-groups | 7 |
| **ml_ai** | comprehend, rekognition, translate, textract, transcribe, polly, sagemaker | 7 |

**Total Services**: 92 (Enhanced mapping)

## 🚀 **Enhanced Features**

### **Multi-Resource Type Support**
Each service can now discover multiple resource types:
```json
{
  "ec2": {
    "resource_types": {
      "instance": { "count_field": "Reservations[*].Instances[*].InstanceId" },
      "volume": { "count_field": "Volumes[*].VolumeId" },
      "launch_template": { "count_field": "LaunchTemplates[*].LaunchTemplateId" }
    }
  }
}
```

### **Automatic ARN Generation**
ARNs are automatically generated using format templates:
```json
{
  "arn_format": "arn:aws:ec2:{region}:{account_id}:instance/{resource_id}"
}
```

### **Category and Scope Classification**
Services are classified for better organization:
- **Categories**: compute, storage, database, security, monitoring, etc.
- **Scope**: global, regional

## 📝 **Maintenance**

### **Adding New Services**
1. Add service to `enhanced_service_mapping.json` with resource types
2. Define ARN format templates
3. Specify category and scope
4. Add client type and check function

### **Updating Resource Types**
1. Modify `resource_types` section in enhanced mapping
2. Update ARN format templates
3. Test with enhanced extraction engine

### **Environment-Specific Configs**
Create environment-specific directories:
```
config/
├── dev/
├── staging/
└── prod/
```

## 🎯 **Next Steps**

1. **Database Schema Updates**: Update to handle multiple resource types and ARNs
2. **API Endpoint Integration**: Update remaining endpoints to use enhanced system
3. **Storage and Reporting**: Update to handle enhanced resource information
4. **Discovery Engine Updates**: Update individual discovery engines
5. **Service Enablement Integration**: Update service enablement integration

The enhanced configuration system provides a scalable, maintainable, and comprehensive approach to AWS resource discovery! 