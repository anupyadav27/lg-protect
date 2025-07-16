# Configuration Externalization Plan

## 🎯 **Problem Analysis**

Your current architecture has **extensive hardcoded mappings** scattered across multiple files:

### **Current Issues:**
1. **Service Categorization** - Hardcoded in multiple files
2. **Risk Weights** - Embedded in risk calculator
3. **Asset Type Mapping** - Duplicated across files
4. **Priority Levels** - Hardcoded in discovery engines
5. **Security Analysis Types** - Hardcoded in analyzers
6. **Compliance Frameworks** - Hardcoded in multiple places

### **Files with Hardcoded Configurations:**
- `backend/services/inventory-service/src/config/enhanced_service_config.py`
- `backend/services/inventory-service/src/utils/service_mapping.py`
- `backend/services/inventory-service/src/config/service_discovery_config.py`
- `backend/services/inventory-service/src/analyzers/risk_calculator.py`
- `backend/services/inventory-service/src/services/aws_discovery_service.py`

## 🚀 **Solution: Externalized Configuration Architecture**

### **1. Configuration File Structure**

```
backend/services/inventory-service/config/
├── service_categories.json          # Service categorization
├── risk_weights.json               # Risk calculation weights
├── asset_types.json                # Asset type mappings
├── discovery_priorities.json       # Discovery priority levels
├── security_analysis.json          # Security analysis configurations
├── compliance_frameworks.json      # Compliance framework mappings
├── service_relationships.json      # Service relationship definitions
├── threat_vectors.json            # Threat vector definitions
└── engine_configs.json            # Discovery engine configurations
```

### **2. Configuration File Examples**

#### **service_categories.json**
```json
{
  "categories": {
    "compute": {
      "name": "Compute Services",
      "description": "AWS compute and processing services",
      "services": [
        "ec2", "lambda", "ecs", "eks", "batch", "sagemaker", 
        "workspaces", "elasticbeanstalk", "lightsail"
      ],
      "priority": 2,
      "criticality": "high"
    },
    "storage": {
      "name": "Storage Services", 
      "description": "AWS storage and backup services",
      "services": [
        "s3", "ebs", "efs", "fsx", "backup", "storagegateway",
        "glacier", "datasync"
      ],
      "priority": 3,
      "criticality": "high"
    },
    "database": {
      "name": "Database Services",
      "description": "AWS database and data services", 
      "services": [
        "rds", "dynamodb", "elasticache", "redshift", "neptune",
        "documentdb", "timestream"
      ],
      "priority": 3,
      "criticality": "high"
    },
    "network": {
      "name": "Network Services",
      "description": "AWS networking and connectivity services",
      "services": [
        "vpc", "cloudfront", "route53", "apigateway", "elbv2",
        "directconnect", "globalaccelerator", "networkfirewall", "vpc-lattice"
      ],
      "priority": 2,
      "criticality": "high"
    },
    "security": {
      "name": "Security Services",
      "description": "AWS security and identity services",
      "services": [
        "iam", "kms", "guardduty", "securityhub", "inspector2",
        "secretsmanager", "waf", "wafv2", "shield", "acm"
      ],
      "priority": 1,
      "criticality": "critical"
    },
    "monitoring": {
      "name": "Monitoring Services",
      "description": "AWS monitoring and logging services",
      "services": [
        "cloudwatch", "cloudtrail", "config", "logs"
      ],
      "priority": 4,
      "criticality": "medium"
    },
    "analytics": {
      "name": "Analytics Services",
      "description": "AWS analytics and data processing services",
      "services": [
        "athena", "glue", "emr", "kinesis", "firehose", "quicksight",
        "elasticsearch"
      ],
      "priority": 5,
      "criticality": "medium"
    },
    "application": {
      "name": "Application Services",
      "description": "AWS application integration services",
      "services": [
        "sns", "sqs", "events", "stepfunctions", "connect", "chime"
      ],
      "priority": 4,
      "criticality": "medium"
    },
    "management": {
      "name": "Management Services",
      "description": "AWS management and governance services",
      "services": [
        "cloudformation", "organizations", "ssm", "transfer"
      ],
      "priority": 5,
      "criticality": "low"
    },
    "ml_ai": {
      "name": "ML/AI Services",
      "description": "AWS machine learning and AI services",
      "services": [
        "comprehend", "rekognition", "translate", "textract",
        "transcribe", "polly"
      ],
      "priority": 5,
      "criticality": "medium"
    }
  },
  "metadata": {
    "version": "1.0",
    "last_updated": "2025-01-12",
    "total_categories": 10,
    "total_services": 64
  }
}
```

#### **risk_weights.json**
```json
{
  "category_weights": {
    "encryption": 0.20,
    "access_control": 0.18,
    "network_security": 0.16,
    "logging_monitoring": 0.12,
    "configuration": 0.12,
    "backup_recovery": 0.10,
    "compliance": 0.08,
    "data_protection": 0.04
  },
  "severity_impact": {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.6,
    "low": 0.4,
    "info": 0.2
  },
  "service_criticality": {
    "s3": 1.0,
    "rds": 1.0,
    "ec2": 0.9,
    "iam": 1.0,
    "lambda": 0.8,
    "kms": 1.0,
    "vpc": 0.9,
    "cloudtrail": 0.9,
    "elbv2": 0.8,
    "dynamodb": 0.9,
    "eks": 0.9,
    "ecs": 0.8,
    "secretsmanager": 1.0,
    "guardduty": 0.7,
    "config": 0.7,
    "cloudwatch": 0.6,
    "sns": 0.5,
    "sqs": 0.5
  },
  "default_criticality": 0.6,
  "metadata": {
    "version": "1.0",
    "last_updated": "2025-01-12"
  }
}
```

#### **asset_types.json**
```json
{
  "service_asset_mapping": {
    "ec2": "compute",
    "lambda": "serverless", 
    "ecs": "container",
    "eks": "container",
    "autoscaling": "compute",
    "emr": "analytics",
    "sagemaker": "analytics",
    "s3": "storage",
    "ebs": "storage",
    "efs": "storage",
    "fsx": "storage",
    "glacier": "storage",
    "backup": "storage",
    "storagegateway": "storage",
    "rds": "database",
    "dynamodb": "database",
    "redshift": "database",
    "elasticache": "database",
    "vpc": "network",
    "cloudfront": "network",
    "route53": "network",
    "elbv2": "network",
    "directconnect": "network",
    "globalaccelerator": "network",
    "apigateway": "network",
    "apigatewayv2": "network",
    "vpc-lattice": "network",
    "iam": "identity",
    "kms": "security",
    "guardduty": "security",
    "securityhub": "security",
    "inspector2": "security",
    "secretsmanager": "security",
    "waf": "security",
    "wafv2": "security",
    "shield": "security",
    "cloudwatch": "monitoring",
    "cloudtrail": "monitoring",
    "config": "monitoring",
    "logs": "monitoring",
    "sns": "application",
    "sqs": "application",
    "events": "application",
    "stepfunctions": "application",
    "kinesis": "analytics",
    "firehose": "analytics",
    "glue": "analytics",
    "athena": "analytics",
    "cloudformation": "management",
    "ssm": "management",
    "organizations": "management",
    "transfer": "management",
    "datasync": "management"
  },
  "resource_type_mapping": {
    "ec2": {
      "instance": "compute",
      "volume": "storage",
      "vpc": "network",
      "subnet": "network",
      "security-group": "security",
      "network-acl": "security"
    },
    "s3": {
      "bucket": "storage"
    },
    "rds": {
      "db-instance": "database",
      "db-cluster": "database"
    },
    "lambda": {
      "function": "serverless"
    },
    "iam": {
      "role": "identity",
      "user": "identity",
      "group": "identity",
      "policy": "security"
    },
    "kms": {
      "key": "security"
    },
    "cloudformation": {
      "stack": "configuration"
    }
  },
  "metadata": {
    "version": "1.0",
    "last_updated": "2025-01-12"
  }
}
```

#### **discovery_priorities.json**
```json
{
  "priority_levels": {
    "1": {
      "name": "Critical",
      "description": "Security and identity services",
      "services": ["iam", "kms", "guardduty", "securityhub", "inspector2"]
    },
    "2": {
      "name": "High", 
      "description": "Core infrastructure services",
      "services": ["ec2", "s3", "rds", "vpc", "lambda", "elbv2", "cloudfront", "route53"]
    },
    "3": {
      "name": "Medium",
      "description": "Supporting infrastructure services",
      "services": ["dynamodb", "elasticache", "redshift", "efs", "ebs", "cloudwatch", "cloudtrail"]
    },
    "4": {
      "name": "Low",
      "description": "Application and management services",
      "services": ["sns", "sqs", "events", "stepfunctions", "ssm", "cloudformation"]
    },
    "5": {
      "name": "Optional",
      "description": "Specialized and analytics services",
      "services": ["sagemaker", "comprehend", "rekognition", "translate", "textract"]
    }
  },
  "engine_priorities": {
    "security": 1,
    "compute": 2,
    "network": 2,
    "database": 3,
    "storage": 3,
    "monitoring": 4,
    "application": 4,
    "analytics": 5,
    "management": 5,
    "ml_ai": 5
  },
  "metadata": {
    "version": "1.0",
    "last_updated": "2025-01-12"
  }
}
```

#### **security_analysis.json**
```json
{
  "analysis_types": {
    "encryption_status": {
      "name": "Encryption Status",
      "description": "Check encryption configuration for resources",
      "weight": 0.25,
      "supported_services": ["s3", "rds", "dynamodb", "ebs", "efs", "kms"]
    },
    "access_control": {
      "name": "Access Control",
      "description": "Validate access control configurations",
      "weight": 0.20,
      "supported_services": ["iam", "s3", "rds", "dynamodb", "vpc"]
    },
    "network_security": {
      "name": "Network Security",
      "description": "Check network security configurations",
      "weight": 0.15,
      "supported_services": ["vpc", "ec2", "rds", "lambda", "elbv2"]
    },
    "logging_monitoring": {
      "name": "Logging and Monitoring",
      "description": "Validate logging and monitoring setup",
      "weight": 0.15,
      "supported_services": ["cloudtrail", "cloudwatch", "config", "vpc"]
    },
    "configuration": {
      "name": "Configuration Management",
      "description": "Check configuration best practices",
      "weight": 0.12,
      "supported_services": ["all"]
    },
    "backup_recovery": {
      "name": "Backup and Recovery",
      "description": "Validate backup and recovery configurations",
      "weight": 0.10,
      "supported_services": ["rds", "dynamodb", "ebs", "s3"]
    },
    "compliance": {
      "name": "Compliance",
      "description": "Check compliance framework requirements",
      "weight": 0.08,
      "supported_services": ["all"]
    },
    "data_protection": {
      "name": "Data Protection",
      "description": "Validate data protection measures",
      "weight": 0.04,
      "supported_services": ["s3", "rds", "dynamodb", "lambda"]
    }
  },
  "service_analysis_mapping": {
    "s3": ["encryption_status", "access_control", "logging_monitoring", "data_protection"],
    "rds": ["encryption_status", "access_control", "network_security", "backup_recovery"],
    "dynamodb": ["encryption_status", "access_control", "backup_recovery", "data_protection"],
    "ec2": ["network_security", "access_control", "configuration"],
    "iam": ["access_control", "configuration", "compliance"],
    "vpc": ["network_security", "logging_monitoring", "configuration"],
    "lambda": ["network_security", "data_protection", "configuration"],
    "kms": ["encryption_status", "access_control", "configuration"],
    "cloudtrail": ["logging_monitoring", "encryption_status", "compliance"],
    "cloudwatch": ["logging_monitoring", "configuration"],
    "config": ["configuration", "compliance"],
    "guardduty": ["configuration", "compliance"],
    "securityhub": ["configuration", "compliance"]
  },
  "metadata": {
    "version": "1.0",
    "last_updated": "2025-01-12"
  }
}
```

#### **compliance_frameworks.json**
```json
{
  "frameworks": {
    "cis": {
      "name": "CIS AWS Foundations Benchmark",
      "description": "Center for Internet Security AWS security best practices",
      "version": "1.5.0",
      "supported_services": ["all"]
    },
    "soc2": {
      "name": "SOC 2 Type II",
      "description": "Service Organization Control 2 compliance",
      "version": "2017",
      "supported_services": ["all"]
    },
    "nist": {
      "name": "NIST Cybersecurity Framework",
      "description": "National Institute of Standards and Technology framework",
      "version": "1.1",
      "supported_services": ["all"]
    },
    "aws_foundational": {
      "name": "AWS Foundational Security Best Practices",
      "description": "AWS recommended security practices",
      "version": "2023",
      "supported_services": ["all"]
    },
    "hipaa": {
      "name": "HIPAA",
      "description": "Health Insurance Portability and Accountability Act",
      "version": "1996",
      "supported_services": ["s3", "rds", "dynamodb", "lambda", "kms"]
    },
    "pci_dss": {
      "name": "PCI DSS",
      "description": "Payment Card Industry Data Security Standard",
      "version": "4.0",
      "supported_services": ["s3", "ec2", "rds", "kms", "cloudtrail"]
    },
    "gdpr": {
      "name": "GDPR",
      "description": "General Data Protection Regulation",
      "version": "2018",
      "supported_services": ["s3", "rds", "dynamodb", "lambda", "kms"]
    },
    "sox": {
      "name": "SOX",
      "description": "Sarbanes-Oxley Act",
      "version": "2002",
      "supported_services": ["all"]
    },
    "fedramp": {
      "name": "FedRAMP",
      "description": "Federal Risk and Authorization Management Program",
      "version": "2023",
      "supported_services": ["all"]
    }
  },
  "service_framework_mapping": {
    "s3": ["cis", "soc2", "nist", "aws_foundational", "hipaa", "pci_dss", "gdpr"],
    "rds": ["cis", "soc2", "nist", "aws_foundational", "hipaa", "pci_dss", "gdpr"],
    "dynamodb": ["cis", "soc2", "nist", "aws_foundational", "hipaa", "gdpr"],
    "ec2": ["cis", "soc2", "nist", "aws_foundational", "pci_dss"],
    "iam": ["cis", "soc2", "nist", "aws_foundational", "sox", "fedramp"],
    "vpc": ["cis", "soc2", "nist", "aws_foundational"],
    "lambda": ["cis", "soc2", "nist", "aws_foundational", "hipaa", "gdpr"],
    "kms": ["cis", "soc2", "nist", "aws_foundational", "hipaa", "pci_dss", "gdpr"],
    "cloudtrail": ["cis", "soc2", "nist", "aws_foundational", "pci_dss", "sox", "fedramp"],
    "cloudwatch": ["cis", "soc2", "nist", "aws_foundational"],
    "config": ["cis", "soc2", "nist", "aws_foundational", "sox", "fedramp"],
    "guardduty": ["cis", "soc2", "nist", "aws_foundational"],
    "securityhub": ["cis", "soc2", "nist", "aws_foundational"]
  },
  "metadata": {
    "version": "1.0",
    "last_updated": "2025-01-12"
  }
}
```

### **3. Configuration Loader Class**

```python
#!/usr/bin/env python3
"""
Configuration Loader for Externalized Settings
Loads all configuration from JSON files instead of hardcoded values
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import structlog

logger = structlog.get_logger(__name__)

@dataclass
class ConfigurationManager:
    """Manages all externalized configurations"""
    
    config_dir: Path
    service_categories: Dict[str, Any] = None
    risk_weights: Dict[str, Any] = None
    asset_types: Dict[str, Any] = None
    discovery_priorities: Dict[str, Any] = None
    security_analysis: Dict[str, Any] = None
    compliance_frameworks: Dict[str, Any] = None
    service_relationships: Dict[str, Any] = None
    threat_vectors: Dict[str, Any] = None
    engine_configs: Dict[str, Any] = None
    
    def __post_init__(self):
        self.load_all_configurations()
    
    def load_all_configurations(self):
        """Load all configuration files"""
        try:
            self.service_categories = self._load_config("service_categories.json")
            self.risk_weights = self._load_config("risk_weights.json")
            self.asset_types = self._load_config("asset_types.json")
            self.discovery_priorities = self._load_config("discovery_priorities.json")
            self.security_analysis = self._load_config("security_analysis.json")
            self.compliance_frameworks = self._load_config("compliance_frameworks.json")
            self.service_relationships = self._load_config("service_relationships.json")
            self.threat_vectors = self._load_config("threat_vectors.json")
            self.engine_configs = self._load_config("engine_configs.json")
            
            logger.info("all_configurations_loaded_successfully")
            
        except Exception as e:
            logger.error("configuration_loading_failed", error=str(e))
            raise
    
    def _load_config(self, filename: str) -> Dict[str, Any]:
        """Load a single configuration file"""
        config_path = self.config_dir / filename
        
        if not config_path.exists():
            logger.warning(f"configuration_file_not_found", file=filename)
            return {}
        
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                logger.debug(f"loaded_configuration", file=filename)
                return config
        except json.JSONDecodeError as e:
            logger.error(f"invalid_json_in_config", file=filename, error=str(e))
            raise
        except Exception as e:
            logger.error(f"config_loading_error", file=filename, error=str(e))
            raise
    
    def get_service_category(self, service_name: str) -> Optional[str]:
        """Get category for a service"""
        if not self.service_categories:
            return None
        
        categories = self.service_categories.get("categories", {})
        for category_name, category_data in categories.items():
            if service_name in category_data.get("services", []):
                return category_name
        
        return None
    
    def get_risk_weights(self) -> Dict[str, float]:
        """Get risk calculation weights"""
        if not self.risk_weights:
            return {}
        
        return self.risk_weights.get("category_weights", {})
    
    def get_service_criticality(self, service_name: str) -> float:
        """Get criticality score for a service"""
        if not self.risk_weights:
            return 0.6
        
        criticality_map = self.risk_weights.get("service_criticality", {})
        return criticality_map.get(service_name, self.risk_weights.get("default_criticality", 0.6))
    
    def get_asset_type(self, service_name: str) -> str:
        """Get asset type for a service"""
        if not self.asset_types:
            return "unknown"
        
        mapping = self.asset_types.get("service_asset_mapping", {})
        return mapping.get(service_name, "unknown")
    
    def get_discovery_priority(self, service_name: str) -> int:
        """Get discovery priority for a service"""
        if not self.discovery_priorities:
            return 3
        
        priorities = self.discovery_priorities.get("priority_levels", {})
        for priority_level, priority_data in priorities.items():
            if service_name in priority_data.get("services", []):
                return int(priority_level)
        
        return 3
    
    def get_security_analysis_types(self, service_name: str) -> List[str]:
        """Get security analysis types for a service"""
        if not self.security_analysis:
            return []
        
        mapping = self.security_analysis.get("service_analysis_mapping", {})
        return mapping.get(service_name, [])
    
    def get_compliance_frameworks(self, service_name: str) -> List[str]:
        """Get compliance frameworks for a service"""
        if not self.compliance_frameworks:
            return []
        
        mapping = self.compliance_frameworks.get("service_framework_mapping", {})
        return mapping.get(service_name, [])
    
    def reload_configurations(self):
        """Reload all configurations from files"""
        logger.info("reloading_all_configurations")
        self.load_all_configurations()
    
    def validate_configurations(self) -> bool:
        """Validate all loaded configurations"""
        try:
            required_files = [
                "service_categories.json",
                "risk_weights.json", 
                "asset_types.json",
                "discovery_priorities.json",
                "security_analysis.json",
                "compliance_frameworks.json"
            ]
            
            for filename in required_files:
                if not (self.config_dir / filename).exists():
                    logger.error(f"missing_required_config", file=filename)
                    return False
            
            logger.info("all_configurations_validated_successfully")
            return True
            
        except Exception as e:
            logger.error("configuration_validation_failed", error=str(e))
            return False
```

### **4. Migration Strategy**

#### **Phase 1: Create Configuration Files**
1. Create the `config/` directory structure
2. Generate all JSON configuration files
3. Validate JSON syntax and structure

#### **Phase 2: Update Code to Use Configuration Loader**
1. Replace hardcoded mappings with configuration loader calls
2. Update all classes to use externalized configurations
3. Add configuration validation and error handling

#### **Phase 3: Testing and Validation**
1. Test configuration loading and validation
2. Verify all functionality works with externalized configs
3. Add configuration hot-reload capabilities

#### **Phase 4: Documentation and Maintenance**
1. Document configuration file formats
2. Create configuration management procedures
3. Add configuration versioning and migration tools

## ✅ **Benefits of Externalization**

### **1. Maintainability**
- ✅ **Easy Updates**: Change configurations without code changes
- ✅ **Version Control**: Track configuration changes separately
- ✅ **Rollback Capability**: Revert configuration changes easily

### **2. Flexibility**
- ✅ **Environment-Specific**: Different configs for dev/staging/prod
- ✅ **Dynamic Updates**: Hot-reload configurations
- ✅ **Customization**: Easy to customize for different deployments

### **3. Separation of Concerns**
- ✅ **Code vs Configuration**: Clear separation
- ✅ **Business Logic**: Configuration separate from implementation
- ✅ **Testing**: Easier to test with different configurations

### **4. Scalability**
- ✅ **Multiple Environments**: Same code, different configs
- ✅ **Feature Flags**: Configuration-driven feature toggles
- ✅ **A/B Testing**: Easy configuration-based testing

## 🎯 **Implementation Priority**

**High Priority (Immediate):**
1. Service categories and asset types
2. Risk weights and criticality scores
3. Discovery priorities

**Medium Priority (Next Sprint):**
1. Security analysis configurations
2. Compliance framework mappings
3. Service relationships

**Low Priority (Future):**
1. Threat vectors
2. Engine configurations
3. Advanced analytics settings

This externalization will significantly improve your codebase maintainability and flexibility! 