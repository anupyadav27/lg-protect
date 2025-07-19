# Quick Reference - New Service Onboarding

## 🚀 Super Simple Process

### **Step 1: Add Your Service Folder**
```bash
mkdir -p checks/{new_service}/{check_name}
```

### **Step 2: Add Your Compliance Checks**
```
checks/{new_service}/
└── {check_name}/
    ├── {check_name}.py        # Your check implementation
    └── {check_name}.metadata.json  # Your check metadata
```

### **Step 3: Tell Me**
> "I have added a new services folder for XYZ under checks folder. Please make the enhancement in code as per other services without losing functionality and make sure it perfectly integrated with our current architecture and reporting."

### **Step 4: Done!**
I automatically handle everything else:
- ✅ Service client generation
- ✅ Scan runner integration  
- ✅ Hierarchical reporting
- ✅ Package exports
- ✅ Testing and validation

## 📋 What You Get Automatically

### **Commands Available:**
```bash
# Individual service scan
python run_individual_scan.py

# All services scan (includes your new service)
python run_all_services.py
```

### **Imports Available:**
```python
# Direct service scan
from utils.scan_runners import run_{service}_scan

# Comprehensive scan (includes your service)
from utils.scan_runners import run_comprehensive_scan
```

### **Reports Generated:**
```
output/scan_YYYY-MM-DD_HH-MM-SS/
├── overall/                    # Includes your service
└── services/
    └── {new_service}/          # Your service reports
        ├── {new_service}_report.json
        ├── {new_service}_report.csv
        ├── {new_service}_summary.txt
        └── checks/             # Individual check reports
            ├── {check_name}_report.json
            ├── {check_name}_report.csv
            └── {check_name}_summary.txt
```

## 🎯 Example: Adding S3 Service

### **1. Create Folder:**
```bash
mkdir -p checks/s3/s3_bucket_encryption
mkdir -p checks/s3/s3_bucket_public_access
```

### **2. Add Your Checks:**
```
checks/s3/
├── s3_bucket_encryption/
│   ├── s3_bucket_encryption.py
│   └── s3_bucket_encryption.metadata.json
└── s3_bucket_public_access/
    ├── s3_bucket_public_access.py
    └── s3_bucket_public_access.metadata.json
```

### **3. Tell Me:**
> "I have added a new services folder for S3 under checks folder. Please make the enhancement in code as per other services without losing functionality and make sure it perfectly integrated with our current architecture and reporting."

### **4. Use Your New Service:**
```bash
# Run S3 scan
python -c "from utils.scan_runners import run_s3_scan; run_s3_scan()"

# Run all services (includes S3)
python run_all_services.py
```

## ✅ That's It!

No manual integration needed. Just add your folder, tell me, and everything works automatically with the existing architecture! 