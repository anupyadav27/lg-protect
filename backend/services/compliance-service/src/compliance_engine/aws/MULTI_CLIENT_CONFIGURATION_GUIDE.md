# 🔐 Multi-Client Configuration Guide

## 🎯 **Overview**

This guide explains how to configure the compliance scanning system for multiple AWS clients using a secure, scalable configuration approach that supports:

- ✅ **Multiple AWS Accounts**: Scan multiple client accounts
- ✅ **Different Credential Types**: Shared credentials, access keys, role assumption
- ✅ **Secret Management**: Local files, AWS Secrets Manager, HashiCorp Vault
- ✅ **Scalable Architecture**: Easy to add new clients
- ✅ **Secure Credentials**: Separate configuration from secrets

## 🏗️ **Architecture**

### **Configuration Files Structure**
```
config/
├── aws_credentials_config.json    # Main configuration (non-sensitive)
├── secrets_template.json          # Template for secrets file
└── secrets.json                   # Actual secrets (gitignored)
```

### **Components**
1. **Secret Manager** (`utils/secret_manager.py`)
2. **Secret Manager** (supports multiple backends)
3. **Multi-Client Scanner** (scans multiple accounts)
4. **Output Manager** (timestamped, organized results)

## 📋 **Configuration Setup**

### **1. Main Configuration File** (`config/aws_credentials_config.json`)

```json
{
  "aws_credentials": {
    "default_profile": "default",
    "profiles": {
      "default": {
        "type": "shared_credentials",
        "profile_name": "default",
        "region": "us-east-1"
      },
      "client1": {
        "type": "access_keys",
        "access_key_id": "YOUR_ACCESS_KEY_ID",
        "secret_access_key": "YOUR_SECRET_ACCESS_KEY",
        "region": "us-east-1"
      },
      "client2": {
        "type": "role_assumption",
        "role_arn": "arn:aws:iam::123456789012:role/ComplianceScanRole",
        "external_id": "YOUR_EXTERNAL_ID",
        "region": "us-west-2"
      }
    }
  },
  "scan_configuration": {
    "default_regions": ["us-east-1", "us-west-2", "eu-west-1"],
    "services_to_scan": ["acm", "account", "accessanalyzer", "iam", "s3", "ec2"],
    "max_workers": 10,
    "scan_timeout_seconds": 300
  },
  "output_configuration": {
    "output_directory": "output",
    "filename_prefix": "compliance_scan",
    "include_timestamp": true,
    "format": "json"
  },
  "secret_management": {
    "type": "local_file",
    "secret_file_path": "config/secrets.json",
    "encryption_enabled": false,
    "future_integration": {
      "aws_secrets_manager": {
        "enabled": false,
        "secret_name": "compliance-scan-credentials",
        "region": "us-east-1"
      },
      "hashicorp_vault": {
        "enabled": false,
        "vault_url": "https://vault.example.com",
        "secret_path": "aws/credentials"
      }
    }
  }
}
```

### **2. Secrets File** (`config/secrets.json`)

```json
{
  "aws_credentials": {
    "client1": {
      "access_key_id": "AKIAIOSFODNN7EXAMPLE",
      "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "account_id": "123456789012",
      "account_name": "Client 1 Production"
    },
    "client2": {
      "role_arn": "arn:aws:iam::987654321098:role/ComplianceScanRole",
      "external_id": "compliance-scan-external-id",
      "account_id": "987654321098",
      "account_name": "Client 2 Development"
    }
  },
  "api_keys": {
    "security_hub": "YOUR_SECURITY_HUB_API_KEY"
  }
}
```

## 🔧 **Credential Types**

### **1. Shared Credentials** (AWS CLI profiles)
```json
{
  "type": "shared_credentials",
  "profile_name": "default",
  "region": "us-east-1"
}
```

### **2. Access Keys** (Direct credentials)
```json
{
  "type": "access_keys",
  "access_key_id": "AKIAIOSFODNN7EXAMPLE",
  "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "region": "us-east-1"
}
```

### **3. Role Assumption** (Cross-account access)
```json
{
  "type": "role_assumption",
  "role_arn": "arn:aws:iam::123456789012:role/ComplianceScanRole",
  "external_id": "compliance-scan-external-id",
  "region": "us-east-1"
}
```

## 🚀 **Usage Examples**

### **1. Test Configuration**
```bash
python test_config_scan.py
```

### **2. Scan Single Client**
```python
from utils.secret_manager import get_secret_manager

secret_manager = get_secret_manager()
session = secret_manager.create_boto3_session('client1')
# Use session for scanning
```

### **3. Scan Multiple Clients**
```python
from utils.secret_manager import get_secret_manager

secret_manager = get_secret_manager()
profiles = secret_manager.get_all_profiles()

for profile in profiles:
    session = secret_manager.create_boto3_session(profile.name)
    # Scan this client
```

## 🔐 **Secret Management Integration**

### **Current Support**
- ✅ **Local Files**: `config/secrets.json`
- 🔄 **AWS Secrets Manager**: Ready for integration
- 🔄 **HashiCorp Vault**: Ready for integration

### **AWS Secrets Manager Integration**
```json
{
  "secret_management": {
    "type": "aws_secrets_manager",
    "aws_secrets_manager": {
      "enabled": true,
      "secret_name": "compliance-scan-credentials",
      "region": "us-east-1"
    }
  }
}
```

### **HashiCorp Vault Integration**
```json
{
  "secret_management": {
    "type": "hashicorp_vault",
    "hashicorp_vault": {
      "enabled": true,
      "vault_url": "https://vault.example.com",
      "secret_path": "aws/credentials"
    }
  }
}
```

## 📊 **Output Structure**

### **Multi-Client Scan Results**
```json
{
  "scan_id": "multi_client_scan_20250718_111323",
  "scan_timestamp": "2025-07-18T11:13:23.175689",
  "accounts_scanned": 3,
  "total_findings": 15,
  "summary": {
    "passed": 10,
    "failed": 3,
    "warnings": 2,
    "compliance_score": 66.7
  },
  "account_results": {
    "client1": {
      "account_id": "123456789012",
      "account_name": "Client 1 Production",
      "findings_count": 5
    },
    "client2": {
      "account_id": "987654321098",
      "account_name": "Client 2 Development",
      "findings_count": 10
    }
  },
  "findings": [
    {
      "check_name": "acm_certificates_expiration_check",
      "status": "FAIL",
      "status_extended": "Certificate expires in 5 days",
      "account_name": "Client 1 Production",
      "region": "us-east-1",
      "service": "acm"
    }
  ]
}
```

## 🎯 **Benefits**

### **✅ Scalability**
- Easy to add new clients
- Centralized configuration
- Consistent scanning approach

### **✅ Security**
- Separated configuration from secrets
- Support for multiple secret management systems
- No hardcoded credentials

### **✅ Flexibility**
- Multiple credential types
- Configurable scan parameters
- Customizable output formats

### **✅ Maintainability**
- Single configuration file
- Clear separation of concerns
- Easy to update and manage

## 📋 **Setup Steps**

### **1. Initial Setup**
```bash
# Copy template files
cp config/secrets_template.json config/secrets.json

# Update configuration
# Edit config/aws_credentials_config.json
# Edit config/secrets.json with real credentials
```

### **2. Test Configuration**
```bash
python test_config_scan.py
```

### **3. Run Multi-Client Scan**
```bash
python test_multi_client_scan.py
```

## 🔄 **Future Enhancements**

### **Planned Features**
1. **AWS Secrets Manager Integration**: Full implementation
2. **HashiCorp Vault Integration**: Full implementation
3. **Encryption**: Encrypt local secrets file
4. **Key Rotation**: Automatic credential rotation
5. **Audit Logging**: Track credential usage

### **Integration Points**
- **CI/CD Pipelines**: Automated scanning
- **Monitoring Systems**: Alert on findings
- **Reporting Tools**: Generate compliance reports
- **Dashboard**: Web-based results viewing

## 🎉 **Conclusion**

The multi-client configuration system provides a **secure, scalable, and maintainable** approach to AWS compliance scanning across multiple accounts. It's ready for production use and can easily integrate with enterprise secret management systems. 