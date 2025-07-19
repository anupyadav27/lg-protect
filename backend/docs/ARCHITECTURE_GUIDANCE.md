# LG-Protect Architecture Guidance

## Overview

LG-Protect follows a **microservices architecture** with proper separation of concerns:

```
UI → API Gateway → Backend Services
                ├── Inventory Service
                ├── Compliance Service  
                ├── Data Security Service
                └── Alert Engine
```

## 🏗️ **Architecture Components**

### **1. Frontend (UI)**
- **Technology**: React/Vue/Angular (your choice)
- **Purpose**: User interface for LG-Protect platform
- **Connection**: Communicates only with API Gateway
- **Base URL**: `http://localhost:8000` (API Gateway)

### **2. API Gateway** (`backend/api-gateway/`)
- **Technology**: FastAPI
- **Purpose**: Central routing, authentication, orchestration
- **Port**: 8000 (main entry point)
- **Responsibilities**:
  - Route UI requests to appropriate services
  - Handle authentication/authorization
  - Event orchestration
  - Service health monitoring
  - Request/response transformation

### **3. Backend Services**
Each service is **isolated** and handles its own domain:

#### **Inventory Service** (`backend/services/inventory-service/`)
- **Port**: 3000 (internal)
- **Purpose**: Asset discovery and inventory management
- **API Base**: `/api/inventory/*` (internal endpoints)
- **Not directly exposed to UI**

#### **Compliance Service** (`backend/services/compliance-service/`)
- **Port**: 3001 (internal)
- **Purpose**: Compliance checking and reporting
- **API Base**: `/api/compliance/*` (internal endpoints)

#### **Data Security Service** (`backend/services/data-security-service/`)
- **Port**: 3002 (internal)
- **Purpose**: Data security analysis
- **API Base**: `/api/security/*` (internal endpoints)

#### **Alert Engine** (`backend/services/alert-engine/`)
- **Port**: 3010 (internal)
- **Purpose**: Alert generation and management
- **API Base**: `/api/alerts/*` (internal endpoints)

## 🔄 **Request Flow**

### **UI → API Gateway → Service Flow**
```
1. UI makes request to API Gateway
   GET http://localhost:8000/api/v1/inventory/assets

2. API Gateway routes to Inventory Service
   GET http://inventory-service:3000/api/inventory

3. Inventory Service processes request
   (Business logic, data processing)

4. Response flows back through API Gateway to UI
```

## 📋 **API Endpoints Structure**

### **UI Accessible Endpoints** (via API Gateway)
```
http://localhost:8000/api/v1/inventory/assets
http://localhost:8000/api/v1/inventory/search
http://localhost:8000/api/v1/inventory/summary
http://localhost:8000/api/v1/inventory/{asset_id}
http://localhost:8000/api/v1/inventory/{asset_id}/relationships
http://localhost:8000/api/v1/inventory/export
http://localhost:8000/api/v1/inventory/{asset_id}/review
http://localhost:8000/api/v1/inventory/tags
```

### **Internal Service Endpoints** (not directly accessible)
```
http://inventory-service:3000/api/inventory
http://inventory-service:3000/api/inventory/search
http://inventory-service:3000/api/inventory/summary
# ... etc
```

## ✅ **Benefits of This Architecture**

### **1. Service Isolation**
- Each service handles its own domain
- Independent development and deployment
- Clear separation of concerns

### **2. Scalability**
- Services can scale independently
- Load balancing at API Gateway level
- Horizontal scaling possible

### **3. Security**
- Single entry point (API Gateway)
- Centralized authentication
- Service-to-service communication isolated

### **4. Maintainability**
- Clear boundaries between services
- Independent versioning
- Easier debugging and testing

## 🚀 **Development Workflow**

### **Starting Services**
```bash
# Start API Gateway (main entry point)
cd backend/api-gateway
python app.py

# Start Inventory Service (internal)
cd backend/services/inventory-service/src
python main.py

# Start other services...
```

### **Frontend Development**
```javascript
// Frontend connects to API Gateway
const API_BASE_URL = 'http://localhost:8000';

// Example API calls
fetch(`${API_BASE_URL}/api/v1/inventory/assets`)
fetch(`${API_BASE_URL}/api/v1/inventory/search`, {
    method: 'POST',
    body: JSON.stringify(searchCriteria)
})
```

## 🔧 **Configuration**

### **Environment Variables**
```bash
# API Gateway
INVENTORY_SERVICE_URL=http://inventory-service:3000
COMPLIANCE_SERVICE_URL=http://compliance-service:3001
DATA_SECURITY_SERVICE_URL=http://data-security-service:3002
ALERT_ENGINE_URL=http://alert-engine:3010
```

### **Docker Compose** (for production)
```yaml
services:
  api-gateway:
    ports:
      - "8000:8000"
  
  inventory-service:
    ports:
      - "3000:3000"
    # No external port exposure needed
```

## 📊 **Monitoring & Health Checks**

### **API Gateway Health Check**
```
GET http://localhost:8000/health
```
Returns health status of all services.

### **Individual Service Health Checks**
```
GET http://inventory-service:3000/health
GET http://compliance-service:3001/health
# ... etc
```

## 🎯 **Best Practices**

### **1. Service Communication**
- Services communicate via API Gateway
- No direct service-to-service calls from UI
- Use event-driven architecture for async operations

### **2. Error Handling**
- API Gateway handles service failures gracefully
- Proper error responses to UI
- Service-specific error details logged

### **3. Authentication**
- Centralized at API Gateway level
- Service-specific authorization if needed
- JWT tokens or similar for session management

### **4. Data Flow**
- UI → API Gateway → Service → Database
- No direct UI → Service communication
- API Gateway acts as facade

## 🔍 **Debugging**

### **API Gateway Logs**
```bash
# Check API Gateway routing
tail -f logs/api-gateway.log
```

### **Service Logs**
```bash
# Check individual service logs
tail -f logs/inventory-service.log
tail -f logs/compliance-service.log
```

### **Network Debugging**
```bash
# Test service connectivity
curl http://localhost:8000/health
curl http://inventory-service:3000/health
```

## 📈 **Scaling Considerations**

### **Horizontal Scaling**
- Scale API Gateway independently
- Scale services based on load
- Use load balancers for multiple instances

### **Database Scaling**
- Each service can have its own database
- Shared databases for common data
- Read replicas for heavy read operations

## 🚨 **Security Considerations**

### **Network Security**
- Internal services not exposed to internet
- API Gateway as single entry point
- VPN for internal communication

### **Authentication**
- Centralized at API Gateway
- Service-specific roles if needed
- Audit logging for all operations

## ✅ **Summary**

**Keep the current structure** because it follows microservices best practices:

1. **UI connects only to API Gateway** (`http://localhost:8000`)
2. **API Gateway routes to appropriate services**
3. **Services handle their own business logic**
4. **Clear separation of concerns**
5. **Scalable and maintainable architecture**

This architecture provides the best balance of **isolation**, **scalability**, and **maintainability** for the LG-Protect platform. 