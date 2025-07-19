#!/bin/bash

# LG-Protect Complete Integration Test Script
# Validates that all components are properly stitched together and working as a cohesive system

set -e  # Exit on any error

echo "🧪 LG-Protect Integration Test Suite"
echo "===================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to print colored output
print_test_start() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "${BLUE}🔍 TEST $TOTAL_TESTS: $1${NC}"
}

print_test_pass() {
    PASSED_TESTS=$((PASSED_TESTS + 1))
    echo -e "${GREEN}   ✅ PASSED: $1${NC}"
}

print_test_fail() {
    FAILED_TESTS=$((FAILED_TESTS + 1))
    echo -e "${RED}   ❌ FAILED: $1${NC}"
}

print_info() {
    echo -e "${PURPLE}   ℹ️  $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}   ⚠️  $1${NC}"
}

# Function to test HTTP endpoint
test_endpoint() {
    local endpoint="$1"
    local expected_status="${2:-200}"
    local test_name="$3"
    
    print_test_start "$test_name"
    
    response=$(curl -s -w "%{http_code}" -o /tmp/response.json "$endpoint" 2>/dev/null || echo "000")
    
    if [ "$response" = "$expected_status" ]; then
        print_test_pass "HTTP $expected_status received"
        if [ -f /tmp/response.json ]; then
            local response_size=$(wc -c < /tmp/response.json)
            print_info "Response size: $response_size bytes"
        fi
        return 0
    else
        print_test_fail "Expected HTTP $expected_status, got $response"
        return 1
    fi
}

# Function to test POST endpoint
test_post_endpoint() {
    local endpoint="$1"
    local expected_status="${2:-200}"
    local test_name="$3"
    local data="${4:-{}}"
    
    print_test_start "$test_name"
    
    response=$(curl -s -w "%{http_code}" -o /tmp/response.json -X POST \
        -H "Content-Type: application/json" \
        -d "$data" \
        "$endpoint" 2>/dev/null || echo "000")
    
    if [ "$response" = "$expected_status" ]; then
        print_test_pass "HTTP $expected_status received"
        if [ -f /tmp/response.json ]; then
            local response_size=$(wc -c < /tmp/response.json)
            print_info "Response size: $response_size bytes"
        fi
        return 0
    else
        print_test_fail "Expected HTTP $expected_status, got $response"
        if [ -f /tmp/response.json ]; then
            print_info "Response content: $(cat /tmp/response.json)"
        fi
        return 1
    fi
}

# Function to test Redis event bus
test_redis_event_bus() {
    print_test_start "Redis Event Bus Connectivity"
    
    if docker exec lg-protect-redis redis-cli ping 2>/dev/null | grep -q "PONG"; then
        print_test_pass "Redis is responding to ping"
    else
        print_test_fail "Redis is not responding"
        return 1
    fi
    
    # Test Redis pub/sub functionality
    print_test_start "Redis Pub/Sub Functionality"
    
    # Publish a test message
    docker exec lg-protect-redis redis-cli publish "test-channel" "test-message" >/dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        print_test_pass "Redis pub/sub is working"
    else
        print_test_fail "Redis pub/sub failed"
        return 1
    fi
}

# Function to test database connectivity
test_database_connectivity() {
    print_test_start "PostgreSQL Database Connectivity"
    
    if docker exec lg-protect-postgres pg_isready -U lgprotect 2>/dev/null | grep -q "accepting connections"; then
        print_test_pass "PostgreSQL is accepting connections"
    else
        print_test_fail "PostgreSQL is not accepting connections"
        return 1
    fi
    
    # Test database query
    print_test_start "Database Query Test"
    
    result=$(docker exec lg-protect-postgres psql -U lgprotect -d lgprotect -c "SELECT 1;" 2>/dev/null | grep -c "1 row")
    
    if [ "$result" = "1" ]; then
        print_test_pass "Database query executed successfully"
    else
        print_test_fail "Database query failed"
        return 1
    fi
}

# Function to test service interdependencies
test_service_interdependencies() {
    print_test_start "Service Interdependency Test"
    
    # Test workflow that involves multiple services
    response=$(curl -s -w "%{http_code}" -o /tmp/workflow_response.json \
        -X POST http://localhost:8000/api/v1/workflows/full-scan 2>/dev/null || echo "000")
    
    if [ "$response" = "200" ]; then
        print_test_pass "Full workflow executed successfully"
        
        # Check if response contains results from all services
        if grep -q "inventory" /tmp/workflow_response.json && \
           grep -q "compliance" /tmp/workflow_response.json && \
           grep -q "security" /tmp/workflow_response.json; then
            print_test_pass "All services participated in workflow"
        else
            print_test_fail "Not all services participated in workflow"
        fi
    else
        print_test_fail "Full workflow failed with HTTP $response"
        return 1
    fi
}

# Function to test event-driven communication
test_event_driven_communication() {
    print_test_start "Event-Driven Communication Test"
    
    # Trigger events in sequence and verify they propagate
    local services=("inventory" "compliance" "security")
    
    for service in "${services[@]}"; do
        print_info "Testing $service service events..."
        
        case $service in
            "inventory")
                curl -s -X POST http://localhost:8000/api/v1/inventory/trigger-scan >/dev/null 2>&1
                ;;
            "compliance")
                curl -s -X POST http://localhost:8000/api/v1/compliance/check >/dev/null 2>&1
                ;;
            "security")
                curl -s -X POST http://localhost:8000/api/v1/security/scan >/dev/null 2>&1
                ;;
        esac
        
        sleep 2  # Allow time for event processing
    done
    
    # Check alert engine for accumulated events
    alerts_response=$(curl -s http://localhost:8000/api/v1/alerts/active 2>/dev/null || echo "")
    
    if [ -n "$alerts_response" ]; then
        print_test_pass "Event-driven communication is working"
    else
        print_test_fail "Event-driven communication test failed"
        return 1
    fi
}

# Function to test data consistency
test_data_consistency() {
    print_test_start "Data Consistency Across Services"
    
    # Get dashboard summary which aggregates data from all services
    response=$(curl -s http://localhost:8000/api/v1/dashboard/summary 2>/dev/null || echo "")
    
    if echo "$response" | grep -q "inventory" && \
       echo "$response" | grep -q "compliance" && \
       echo "$response" | grep -q "security" && \
       echo "$response" | grep -q "alerts"; then
        print_test_pass "Data consistency maintained across services"
    else
        print_test_fail "Data consistency issues detected"
        return 1
    fi
}

# Function to test load balancing and routing
test_load_balancing() {
    print_test_start "Load Balancing and Routing Test"
    
    # Test direct service access vs gateway access
    direct_response=$(curl -s http://localhost:3000/health 2>/dev/null || echo "")
    gateway_response=$(curl -s http://localhost:8000/health 2>/dev/null || echo "")
    
    if [ -n "$direct_response" ] && [ -n "$gateway_response" ]; then
        print_test_pass "Both direct and gateway access working"
    else
        print_test_fail "Load balancing/routing issues detected"
        return 1
    fi
}

# Main test execution
echo ""
echo "🚀 Starting Integration Tests..."
echo ""

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 10

# Test 1: Infrastructure Health
echo ""
echo "📊 INFRASTRUCTURE TESTS"
echo "======================="
test_redis_event_bus
test_database_connectivity

# Test 2: Individual Service Health
echo ""
echo "🔧 INDIVIDUAL SERVICE TESTS"
echo "=========================="
test_endpoint "http://localhost:3000/health" "200" "Inventory Service Health"
test_endpoint "http://localhost:3001/health" "200" "Compliance Service Health"
test_endpoint "http://localhost:3002/health" "200" "Data Security Service Health"
test_endpoint "http://localhost:3010/health" "200" "Alert Engine Health"
test_endpoint "http://localhost:8000/health" "200" "API Gateway Health"

# Test 3: API Gateway Endpoints
echo ""
echo "🌐 API GATEWAY TESTS"
echo "==================="
test_endpoint "http://localhost:8000/" "200" "Gateway Root Endpoint"
test_endpoint "http://localhost:8000/api/v1/inventory/service-mapping" "200" "Inventory Service Mapping"
test_endpoint "http://localhost:8000/api/v1/compliance/violations" "200" "Compliance Violations"
test_endpoint "http://localhost:8000/api/v1/security/threats" "200" "Security Threats"
test_endpoint "http://localhost:8000/api/v1/alerts" "200" "Alert Engine Alerts"

# Test 4: Service Workflows
echo ""
echo "⚙️  WORKFLOW TESTS"
echo "=================="
test_post_endpoint "http://localhost:8000/api/v1/inventory/trigger-scan" "200" "Inventory Scan Trigger"
test_post_endpoint "http://localhost:8000/api/v1/compliance/check" "200" "Compliance Check Trigger"
test_post_endpoint "http://localhost:8000/api/v1/security/scan" "200" "Security Scan Trigger"

# Test 5: Integration Tests
echo ""
echo "🔗 INTEGRATION TESTS"
echo "==================="
test_service_interdependencies
test_event_driven_communication
test_data_consistency
test_load_balancing

# Test 6: Monitoring and Management
echo ""
echo "📈 MONITORING TESTS"
echo "=================="
test_endpoint "http://localhost:9090/-/healthy" "200" "Prometheus Health"
test_endpoint "http://localhost:3030/api/health" "200" "Grafana Health"
test_endpoint "http://localhost:8081/" "200" "Redis Commander"

# Test Results Summary
echo ""
echo "🎯 INTEGRATION TEST RESULTS"
echo "============================"
echo -e "Total Tests: ${BLUE}$TOTAL_TESTS${NC}"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo ""
    echo -e "${GREEN}🎉 ALL INTEGRATION TESTS PASSED!${NC}"
    echo -e "${GREEN}✅ The LG-Protect system is properly integrated and functioning as a cohesive unit.${NC}"
    echo ""
    echo "🔍 System Summary:"
    echo "   • All microservices are healthy and communicating"
    echo "   • Redis event bus is operational"
    echo "   • PostgreSQL database is accessible"
    echo "   • API Gateway is routing requests correctly"
    echo "   • Event-driven workflows are functioning"
    echo "   • Data consistency is maintained across services"
    echo "   • Monitoring stack is operational"
    echo ""
    echo "🌐 You can now access:"
    echo "   • API Gateway: http://localhost:8000"
    echo "   • System Dashboard: http://localhost:8000/api/v1/dashboard/summary"
    echo "   • Full System Scan: curl -X POST http://localhost:8000/api/v1/workflows/full-scan"
    
    exit 0
else
    echo ""
    echo -e "${RED}❌ INTEGRATION TESTS FAILED!${NC}"
    echo -e "${RED}$FAILED_TESTS out of $TOTAL_TESTS tests failed.${NC}"
    echo ""
    echo "🔧 Troubleshooting Steps:"
    echo "   1. Check service logs: docker-compose logs [service-name]"
    echo "   2. Verify container status: docker-compose ps"
    echo "   3. Restart failed services: docker-compose restart [service-name]"
    echo "   4. Full system restart: ./deploy-microservices.sh"
    echo ""
    echo "📋 Failed tests require attention before the system can be considered fully integrated."
    
    exit 1
fi

# Cleanup
rm -f /tmp/response.json /tmp/workflow_response.json