#!/bin/bash

# Setup centralized logging structure for LG-Protect services
LOG_BASE="/Users/apple/Desktop/lg-protect/logs"

echo "Setting up centralized logging structure..."

# Create main service directories
services=("inventory-service" "compliance-service" "data-security-service" "alert-engine" "api-gateway")

for service in "${services[@]}"; do
    echo "Setting up logging for $service..."
    
    # Create main service directory
    mkdir -p "$LOG_BASE/services/$service"
    
    # Create subdirectories for different log types
    mkdir -p "$LOG_BASE/services/$service/errors"
    mkdir -p "$LOG_BASE/services/$service/application"
    mkdir -p "$LOG_BASE/services/$service/audit"
    mkdir -p "$LOG_BASE/services/$service/performance"
    mkdir -p "$LOG_BASE/services/$service/security"
    mkdir -p "$LOG_BASE/services/$service/compliance"
    mkdir -p "$LOG_BASE/services/$service/events"
    
    # Create log files with proper permissions
    touch "$LOG_BASE/services/$service/errors/error.log"
    touch "$LOG_BASE/services/$service/application/app.log"
    touch "$LOG_BASE/services/$service/audit/audit.log"
    touch "$LOG_BASE/services/$service/performance/performance.log"
    touch "$LOG_BASE/services/$service/security/security.log"
    touch "$LOG_BASE/services/$service/compliance/compliance.log"
    touch "$LOG_BASE/services/$service/events/events.log"
    
    # Set proper permissions
    chmod -R 755 "$LOG_BASE/services/$service"
    chmod 644 "$LOG_BASE/services/$service"/*/*.log
done

# Create monitoring directories
echo "Setting up monitoring directories..."
mkdir -p "$LOG_BASE/monitoring/errors"
mkdir -p "$LOG_BASE/monitoring/health"
mkdir -p "$LOG_BASE/monitoring/performance"

# Create infrastructure directories
echo "Setting up infrastructure directories..."
mkdir -p "$LOG_BASE/nginx"
mkdir -p "$LOG_BASE/database"
mkdir -p "$LOG_BASE/auth"
mkdir -p "$LOG_BASE/events"
mkdir -p "$LOG_BASE/application"

# Create log files for infrastructure
touch "$LOG_BASE/nginx/access.log"
touch "$LOG_BASE/nginx/error.log"
touch "$LOG_BASE/database/db.log"
touch "$LOG_BASE/auth/auth.log"
touch "$LOG_BASE/events/events.log"
touch "$LOG_BASE/application/app.log"

# Set permissions for all logs
chmod -R 755 "$LOG_BASE"
find "$LOG_BASE" -name "*.log" -exec chmod 644 {} \;

echo "✅ Centralized logging structure setup complete!"
echo "📁 Log base directory: $LOG_BASE"
echo "📊 Services with logging: ${services[*]}"
echo "🔍 Monitoring: errors, health, performance"
echo "🏗️  Infrastructure: nginx, database, auth, events, application" 