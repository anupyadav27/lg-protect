#!/bin/bash

# LG-Protect Complete System Integration & Deployment Script
# This script ensures all components are properly stitched together

set -e  # Exit on any error

echo "🚀 LG-Protect System Integration & Deployment"
echo "============================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check prerequisites
echo ""
print_info "Checking prerequisites..."

# Check Docker
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi
print_status "Docker is installed"

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi
print_status "Docker Compose is installed"

# Check if Docker daemon is running
if ! docker info &> /dev/null; then
    print_error "Docker daemon is not running. Please start Docker first."
    exit 1
fi
print_status "Docker daemon is running"

# Navigate to docker-compose directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

print_info "Current directory: $(pwd)"

# Create necessary directories
echo ""
print_info "Creating necessary directories..."

mkdir -p ../../data/{inventory,compliance,security,reports}
mkdir -p ../../logs/{services,nginx,monitoring}
mkdir -p ./grafana/{dashboards,datasources}
mkdir -p ./ssl

print_status "Directories created"

# Set proper permissions
chmod -R 755 ../../data
chmod -R 755 ../../logs

print_status "Permissions set"

# Clean up any existing containers
echo ""
print_info "Cleaning up existing containers..."

docker-compose down --remove-orphans --volumes 2>/dev/null || true
docker system prune -f --volumes 2>/dev/null || true

print_status "Cleanup completed"

# Build and start services
echo ""
print_info "Building and starting all services..."

# Pull base images first
print_info "Pulling base images..."
docker-compose pull redis postgres nginx prometheus grafana redis-commander pgadmin uptime-kuma

# Build custom services
print_info "Building custom services..."
docker-compose build --no-cache

# Start infrastructure services first
print_info "Starting infrastructure services..."
docker-compose up -d redis postgres

# Wait for infrastructure to be ready
print_info "Waiting for infrastructure services to be ready..."
sleep 30

# Check Redis health
print_info "Checking Redis health..."
for i in {1..30}; do
    if docker exec lg-protect-redis redis-cli ping | grep -q "PONG"; then
        print_status "Redis is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        print_error "Redis failed to start properly"
        exit 1
    fi
    sleep 2
done

# Check PostgreSQL health
print_info "Checking PostgreSQL health..."
for i in {1..30}; do
    if docker exec lg-protect-postgres pg_isready -U lgprotect | grep -q "accepting connections"; then
        print_status "PostgreSQL is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        print_error "PostgreSQL failed to start properly"
        exit 1
    fi
    sleep 2
done

# Start core microservices
print_info "Starting core microservices..."
docker-compose up -d inventory-service compliance-service data-security-service alert-engine

# Wait for microservices to be ready
print_info "Waiting for microservices to be ready..."
sleep 45

# Start API Gateway
print_info "Starting API Gateway..."
docker-compose up -d api-gateway

# Wait for API Gateway
sleep 20

# Start remaining services
print_info "Starting remaining services..."
docker-compose up -d nginx prometheus grafana redis-commander pgadmin uptime-kuma

# Wait for all services to be fully ready
print_info "Waiting for all services to be fully ready..."
sleep 30

# Health check all services
echo ""
print_info "Performing health checks..."

services=(
    "redis:6379"
    "postgres:5432" 
    "inventory-service:3000"
    "compliance-service:3001"
    "data-security-service:3002"
    "alert-engine:3010"
    "api-gateway:8000"
    "nginx:80"
    "prometheus:9090"
    "grafana:3030"
    "redis-commander:8081"
    "pgadmin:8082"
    "uptime-kuma:8083"
)

failed_services=()

for service in "${services[@]}"; do
    service_name="${service%:*}"
    port="${service#*:}"
    
    print_info "Checking $service_name..."
    
    if timeout 10 bash -c "echo >/dev/tcp/localhost/$port" 2>/dev/null; then
        print_status "$service_name is responding"
    else
        print_error "$service_name is not responding"
        failed_services+=("$service_name")
    fi
done

# Test API Gateway endpoints
echo ""
print_info "Testing API Gateway endpoints..."

api_endpoints=(
    "http://localhost:8000/health"
    "http://localhost:8000/api/v1/inventory/service-mapping"
    "http://localhost:8000/api/v1/compliance/violations"
    "http://localhost:8000/api/v1/security/threats"
    "http://localhost:8000/api/v1/alerts"
)

for endpoint in "${api_endpoints[@]}"; do
    endpoint_name=$(echo "$endpoint" | sed 's/.*\///')
    print_info "Testing $endpoint_name..."
    
    if curl -s -f "$endpoint" > /dev/null; then
        print_status "$endpoint_name is working"
    else
        print_warning "$endpoint_name returned an error (may be expected for some endpoints)"
    fi
done

# Test Redis Event Bus
echo ""
print_info "Testing Redis Event Bus..."

if docker exec lg-protect-redis redis-cli eval "return 'Event bus ready'" 0 | grep -q "Event bus ready"; then
    print_status "Redis Event Bus is operational"
else
    print_error "Redis Event Bus test failed"
    failed_services+=("redis-event-bus")
fi

# Display service status
echo ""
echo "🎯 DEPLOYMENT SUMMARY"
echo "===================="

if [ ${#failed_services[@]} -eq 0 ]; then
    print_status "ALL SERVICES ARE RUNNING SUCCESSFULLY!"
    echo ""
    echo "🌐 Access Points:"
    echo "   • API Gateway:      http://localhost:8000"
    echo "   • Main Application: http://localhost:80" 
    echo "   • Grafana:          http://localhost:3030 (admin/admin123)"
    echo "   • Prometheus:       http://localhost:9090"
    echo "   • Redis Commander:  http://localhost:8081"
    echo "   • PgAdmin:          http://localhost:8082 (admin@lgprotect.com/admin123)"
    echo "   • Uptime Monitor:   http://localhost:8083"
    echo ""
    echo "🧪 Test Commands:"
    echo "   # Test full workflow"
    echo "   curl -X POST http://localhost:8000/api/v1/workflows/full-scan"
    echo ""
    echo "   # Get dashboard summary"
    echo "   curl http://localhost:8000/api/v1/dashboard/summary"
    echo ""
    echo "   # Trigger individual services"
    echo "   curl -X POST http://localhost:8000/api/v1/inventory/trigger-scan"
    echo "   curl -X POST http://localhost:8000/api/v1/compliance/check"
    echo "   curl -X POST http://localhost:8000/api/v1/security/scan"
    echo ""
    echo "📊 Monitoring:"
    echo "   • View logs: docker-compose logs -f [service-name]"
    echo "   • View all logs: docker-compose logs -f"
    echo "   • Service status: docker-compose ps"
    echo ""
else
    print_error "Some services failed to start properly:"
    for service in "${failed_services[@]}"; do
        echo "   - $service"
    done
    echo ""
    echo "🔧 Troubleshooting:"
    echo "   • Check logs: docker-compose logs [service-name]"
    echo "   • Restart failed service: docker-compose restart [service-name]"
    echo "   • Full restart: ./deploy-microservices.sh"
fi

# Show container status
echo ""
print_info "Container Status:"
docker-compose ps

echo ""
print_info "System integration complete! 🎉"

exit 0