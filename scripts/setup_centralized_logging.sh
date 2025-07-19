#!/bin/bash

# LG-Protect Centralized Logging System Deployment Script
# This script sets up the centralized logging infrastructure

set -e

echo "🚀 Setting up LG-Protect Centralized Logging System..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}[SETUP]${NC} $1"
}

# Check if Docker and Docker Compose are installed
print_header "Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

print_status "Docker and Docker Compose are installed ✓"

# Create necessary directories
print_header "Creating log directory structure..."

# Base logs directory
mkdir -p logs

# Service-specific log directories
mkdir -p logs/services/inventory-service
mkdir -p logs/services/api-gateway
mkdir -p logs/services/compliance-service
mkdir -p logs/services/data-security-service
mkdir -p logs/services/alert-engine

# Specialized log directories
mkdir -p logs/api
mkdir -p logs/auth
mkdir -p logs/audit
mkdir -p logs/compliance
mkdir -p logs/security
mkdir -p logs/database
mkdir -p logs/events

# Monitoring directories
mkdir -p logs/monitoring/performance
mkdir -p logs/monitoring/health
mkdir -p logs/monitoring/errors

# System directories
mkdir -p logs/application
mkdir -p logs/nginx
mkdir -p logs/archived

# Set proper permissions
chmod -R 755 logs/

print_status "Log directory structure created ✓"

# Create environment file for logging configuration
print_header "Creating logging environment configuration..."

cat > .env.logging << 'EOF'
# LG-Protect Centralized Logging Configuration
# Copy these variables to your main .env file or docker-compose override

# Log levels
LOG_LEVEL=INFO
DEBUG_MODE=false

# Log rotation settings
LOG_MAX_SIZE_MB=50
LOG_BACKUP_COUNT=10

# Enterprise logging features
ENABLE_AUDIT_LOGGING=true
ENABLE_COMPLIANCE_LOGGING=true
ENABLE_SECURITY_LOGGING=true
ENABLE_PERFORMANCE_LOGGING=true

# Log aggregation
ENABLE_LOG_AGGREGATION=true
LOG_AGGREGATION_INTERVAL_MINUTES=60

# External log shipping (SIEM integration)
EXTERNAL_LOG_SHIPPING_ENABLED=false
SIEM_ENDPOINT=
SIEM_API_KEY=
SIEM_LOG_FORMAT=json
SIEM_BATCH_SIZE=100
SIEM_SHIPPING_INTERVAL=300

# Log archival settings
LOG_ARCHIVAL_ENABLED=true
LOG_ARCHIVE_AFTER_DAYS=30
LOG_DELETE_AFTER_DAYS=2555
LOG_COMPRESSION=gzip

# Service-specific log levels
INVENTORY_SERVICE_LOG_LEVEL=INFO
API_GATEWAY_LOG_LEVEL=INFO
COMPLIANCE_SERVICE_LOG_LEVEL=INFO
DATA_SECURITY_SERVICE_LOG_LEVEL=INFO
ALERT_ENGINE_LOG_LEVEL=INFO
EOF

print_status "Logging environment configuration created ✓"

# Create sample Fluent Bit configuration for log aggregation
print_header "Creating log aggregation configuration..."

cat > infrastructure/docker-compose/fluent-bit.conf << 'EOF'
[SERVICE]
    Flush         1
    Log_Level     info
    Daemon        off
    Parsers_File  parsers.conf

[INPUT]
    Name              tail
    Path              /logs/services/*/*.log
    Path_Key          filepath
    Tag               services.*
    Refresh_Interval  5
    Mem_Buf_Limit     50MB

[INPUT]
    Name              tail
    Path              /logs/api/*.log
    Path_Key          filepath
    Tag               api.*
    Refresh_Interval  5
    Mem_Buf_Limit     50MB

[INPUT]
    Name              tail
    Path              /logs/security/*.log
    Path_Key          filepath
    Tag               security.*
    Refresh_Interval  5
    Mem_Buf_Limit     50MB

[INPUT]
    Name              tail
    Path              /logs/audit/*.log
    Path_Key          filepath
    Tag               audit.*
    Refresh_Interval  5
    Mem_Buf_Limit     50MB

[INPUT]
    Name              tail
    Path              /logs/compliance/*.log
    Path_Key          filepath
    Tag               compliance.*
    Refresh_Interval  5
    Mem_Buf_Limit     50MB

[FILTER]
    Name              grep
    Match             security.*
    Regex             message SECURITY|CRITICAL|HIGH

[OUTPUT]
    Name              stdout
    Match             *
    Format            json_lines

# Optional: Forward to external SIEM
# [OUTPUT]
#     Name              http
#     Match             security.*
#     Host              your-siem-endpoint.com
#     Port              443
#     URI               /api/logs
#     Format            json
#     tls               on
#     Header            Authorization Bearer YOUR_API_KEY
EOF

print_status "Log aggregation configuration created ✓"

# Create a sample log analysis script
print_header "Creating log analysis utilities..."

cat > scripts/analyze_logs.sh << 'EOF'
#!/bin/bash

# LG-Protect Log Analysis Utilities

LOG_DIR="./logs"

echo "🔍 LG-Protect Log Analysis Dashboard"
echo "===================================="

# Check log directory size
echo "📊 Log Directory Usage:"
du -sh $LOG_DIR/*/ | sort -hr

echo ""
echo "🚨 Recent Errors (Last 100):"
find $LOG_DIR -name "*.log" -exec grep -l "ERROR\|CRITICAL" {} \; | head -5 | while read file; do
    echo "📄 $file:"
    grep "ERROR\|CRITICAL" "$file" | tail -20
    echo ""
done

echo ""
echo "🔒 Security Events (Last 24 hours):"
find $LOG_DIR/security -name "*.log" -newermt "24 hours ago" -exec cat {} \; | tail -20

echo ""
echo "📈 Performance Issues (Slow requests):"
find $LOG_DIR -name "*performance*.log" -exec grep -l "slow_request.*true" {} \; | while read file; do
    echo "📄 $file:"
    grep "slow_request.*true" "$file" | tail -10
    echo ""
done

echo ""
echo "✅ Health Check Summary:"
find $LOG_DIR -name "*health*.log" -exec tail -10 {} \;

echo ""
echo "📋 Compliance Events:"
find $LOG_DIR/compliance -name "*.log" -exec tail -10 {} \;
EOF

chmod +x scripts/analyze_logs.sh

print_status "Log analysis utilities created ✓"

# Create startup verification script
print_header "Creating logging verification script..."

cat > scripts/verify_logging.py << 'EOF'
#!/usr/bin/env python3
"""
LG-Protect Centralized Logging Verification Script
Tests that all logging components are working correctly
"""

import os
import sys
import json
import time
from pathlib import Path

def check_log_directories():
    """Check if all required log directories exist"""
    print("🔍 Checking log directory structure...")
    
    required_dirs = [
        "logs/services/inventory-service",
        "logs/services/api-gateway", 
        "logs/api",
        "logs/auth",
        "logs/audit",
        "logs/compliance",
        "logs/security",
        "logs/database",
        "logs/events",
        "logs/monitoring/performance",
        "logs/monitoring/health",
        "logs/monitoring/errors",
        "logs/application",
        "logs/archived"
    ]
    
    missing_dirs = []
    for dir_path in required_dirs:
        if not Path(dir_path).exists():
            missing_dirs.append(dir_path)
    
    if missing_dirs:
        print(f"❌ Missing directories: {missing_dirs}")
        return False
    else:
        print("✅ All log directories exist")
        return True

def test_logging_system():
    """Test the centralized logging system"""
    print("\n🧪 Testing centralized logging system...")
    
    try:
        # Import the logging system
        sys.path.append("backend/shared")
        from logging.logger import get_logger
        
        # Create a test logger
        logger = get_logger("test-service", "verification")
        
        # Test basic logging
        logger.info("Logging system verification test", extra_data={
            "test_type": "verification",
            "timestamp": time.time()
        })
        
        # Test specialized logging
        logger.log_security_event(
            event_type="verification_test",
            severity="low",
            details={"test": True}
        )
        
        logger.log_audit_event(
            action="verification_test",
            user_id="system",
            resource="logging_system",
            result="success"
        )
        
        logger.log_performance(
            operation="verification_test",
            duration_ms=10.5,
            extra_data={"test": True}
        )
        
        print("✅ Logging system test completed successfully")
        return True
        
    except Exception as e:
        print(f"❌ Logging system test failed: {e}")
        return False

def check_log_files():
    """Check if log files are being created"""
    print("\n📄 Checking for log files...")
    
    log_files = list(Path("logs").rglob("*.log"))
    
    if log_files:
        print(f"✅ Found {len(log_files)} log files")
        for log_file in log_files[:10]:  # Show first 10
            size = log_file.stat().st_size
            print(f"  📄 {log_file} ({size} bytes)")
        if len(log_files) > 10:
            print(f"  ... and {len(log_files) - 10} more files")
        return True
    else:
        print("⚠️  No log files found (services may not be running yet)")
        return False

def main():
    """Main verification function"""
    print("🚀 LG-Protect Centralized Logging Verification")
    print("=" * 50)
    
    checks = [
        check_log_directories(),
        test_logging_system(),
        check_log_files()
    ]
    
    if all(checks):
        print("\n🎉 All logging system checks passed!")
        return 0
    else:
        print("\n⚠️  Some logging system checks failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
EOF

chmod +x scripts/verify_logging.py

print_status "Logging verification script created ✓"

# Final setup instructions
print_header "Setup Complete! Next Steps:"

echo ""
echo "📋 Your centralized logging system is now ready. Here's what you can do:"
echo ""
echo "1. 🐳 Start the services with centralized logging:"
echo "   cd infrastructure/docker-compose"
echo "   docker-compose up -d"
echo ""
echo "2. 🔍 Verify logging is working:"
echo "   python3 scripts/verify_logging.py"
echo ""
echo "3. 📊 Analyze logs:"
echo "   ./scripts/analyze_logs.sh"
echo ""
echo "4. 🌐 Access log viewer (after starting services):"
echo "   http://localhost:8084"
echo ""
echo "5. 📈 Monitor with Grafana:"
echo "   http://localhost:3030 (admin/admin123)"
echo ""
echo "6. 🔧 Configure SIEM integration (optional):"
echo "   Edit .env.logging file with your SIEM endpoint details"
echo ""

print_status "Log directory: $(pwd)/logs"
print_status "Configuration: $(pwd)/.env.logging"
print_status "Analysis tools: $(pwd)/scripts/"

echo ""
print_header "Enterprise Logging Features Available:"
echo "✅ Automatic request/response logging with correlation IDs"
echo "✅ Security event tracking with severity levels"
echo "✅ Compliance logging for SOC2, HIPAA, PCI-DSS, ISO27001, GDPR"
echo "✅ Performance monitoring and slow request detection"
echo "✅ Audit trails for all user and system actions"
echo "✅ Database operation logging"
echo "✅ Event processing logging"
echo "✅ Health check monitoring"
echo "✅ Log rotation and archival"
echo "✅ Sensitive data filtering"

echo ""
echo "🎯 Ready to deploy your enterprise-grade CSPM platform!"