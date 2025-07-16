# API Reference

Complete API documentation for the LG-Protect platform.

## 🚀 Quick Start

### Base URLs
- **Local Development**: `http://localhost:8000`
- **Production**: `https://api.lg-protect.com`

### Authentication
```bash
# Get authentication token
curl -X POST /api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user@example.com", "password": "password"}'

# Use token in requests
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  /api/v1/scans
```

## 📚 API Categories

### 🔐 [Authentication](authentication.md)
- Login and token management
- User session handling
- API key management

### 📊 [Scanning API](scanning.md)
- Initiate security scans
- Monitor scan progress
- Retrieve scan results

### 📦 [Inventory API](inventory.md)
- AWS resource discovery
- Multi-account management
- Resource metadata queries

### 📋 [Compliance API](compliance.md)
- Framework validation
- Compliance status checks
- Policy evaluation

### 🚨 [Alerts API](alerts.md)
- Alert management
- Notification configuration
- Alert history

### 📈 [Analytics API](analytics.md)
- Risk scoring
- Trend analysis
- Executive reporting

### ⚡ [WebSocket API](websocket.md)
- Real-time event streaming
- Live scan updates
- Push notifications

## 🔧 Core API Endpoints

### Health & Status
```http
GET /health
GET /api/v1/status
GET /api/v1/services/status
```

### Scanning Operations
```http
POST /api/v1/scans
GET /api/v1/scans/{scan_id}
GET /api/v1/scans/{scan_id}/status
DELETE /api/v1/scans/{scan_id}
```

### Inventory Management
```http
GET /api/v1/inventory
GET /api/v1/inventory/services
GET /api/v1/inventory/accounts
POST /api/v1/inventory/accounts
```

### Real-time Events
```http
WS /ws/{tenant_id}
POST /api/v1/events/publish
GET /api/v1/events/history
```

## 📝 Request/Response Format

### Standard Response Structure
```json
{
  "success": true,
  "data": {
    // Response data
  },
  "metadata": {
    "timestamp": "2025-07-12T10:30:00Z",
    "request_id": "req_123456789",
    "version": "1.0.0"
  },
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 1250,
    "has_more": true
  }
}
```

### Error Response Structure
```json
{
  "success": false,
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Invalid scan configuration",
    "details": {
      "field": "regions",
      "issue": "Invalid region code 'us-invalid-1'"
    }
  },
  "metadata": {
    "timestamp": "2025-07-12T10:30:00Z",
    "request_id": "req_123456789"
  }
}
```

## 🚀 Quick Examples

### 1. Start a Security Scan
```bash
curl -X POST /api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Weekly Security Scan",
    "type": "full",
    "regions": ["us-east-1", "us-west-2"],
    "services": ["ec2", "s3", "iam"],
    "accounts": ["123456789012"]
  }'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "scan_id": "scan_20250712_103000_abc123",
    "status": "initiated",
    "estimated_duration": "5-10 minutes",
    "websocket_url": "/ws/tenant_123/scan_20250712_103000_abc123"
  }
}
```

### 2. Check Scan Progress
```bash
curl -H "Authorization: Bearer $TOKEN" \
  /api/v1/scans/scan_20250712_103000_abc123/status
```

**Response:**
```json
{
  "success": true,
  "data": {
    "scan_id": "scan_20250712_103000_abc123",
    "status": "running",
    "progress": {
      "percentage": 65,
      "current_stage": "compliance_validation",
      "completed_services": ["ec2", "s3"],
      "remaining_services": ["iam"],
      "resources_discovered": 142
    },
    "started_at": "2025-07-12T10:30:00Z",
    "estimated_completion": "2025-07-12T10:35:00Z"
  }
}
```

### 3. Get Scan Results
```bash
curl -H "Authorization: Bearer $TOKEN" \
  /api/v1/scans/scan_20250712_103000_abc123
```

**Response:**
```json
{
  "success": true,
  "data": {
    "scan_id": "scan_20250712_103000_abc123",
    "status": "completed",
    "summary": {
      "total_resources": 287,
      "enabled_services": 15,
      "compliance_score": 87.5,
      "high_risk_findings": 3,
      "recommendations": 12
    },
    "results": {
      "inventory": "/api/v1/scans/scan_20250712_103000_abc123/inventory",
      "compliance": "/api/v1/scans/scan_20250712_103000_abc123/compliance",
      "reports": "/api/v1/scans/scan_20250712_103000_abc123/reports"
    }
  }
}
```

### 4. Real-time Updates via WebSocket
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/tenant_123');

ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  console.log('Event:', data.event_type);
  console.log('Data:', data.data);
};

// Example event received:
{
  "event_type": "scan.progress",
  "tenant_id": "tenant_123",
  "data": {
    "scan_id": "scan_20250712_103000_abc123",
    "progress": 75,
    "current_service": "iam",
    "resources_found": 156
  },
  "timestamp": "2025-07-12T10:33:30Z"
}
```

## 🔑 Authentication Methods

### 1. JWT Tokens (Recommended)
```bash
# Login to get token
curl -X POST /api/v1/auth/login \
  -d '{"username": "user@company.com", "password": "password"}'

# Use token
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  /api/v1/scans
```

### 2. API Keys
```bash
curl -H "X-API-Key: lgp_1234567890abcdef" \
  /api/v1/scans
```

### 3. Service Account Tokens
```bash
curl -H "Authorization: ServiceAccount sa_token_123" \
  /api/v1/scans
```

## 📊 Rate Limiting

### Rate Limits
- **Standard Users**: 100 requests/minute
- **Premium Users**: 500 requests/minute
- **Enterprise**: 2000 requests/minute
- **WebSocket**: 10 connections per user

### Rate Limit Headers
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 1625097600
X-RateLimit-Window: 60
```

## 📄 Pagination

### Query Parameters
```bash
curl "/api/v1/inventory?page=1&limit=50&sort=created_at&order=desc"
```

### Response Metadata
```json
{
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 1250,
    "total_pages": 25,
    "has_previous": false,
    "has_next": true,
    "next_page": 2,
    "previous_page": null
  }
}
```

## 🔍 Filtering & Search

### Query Filters
```bash
# Filter by service type
/api/v1/inventory?service=ec2&region=us-east-1

# Filter by date range
/api/v1/scans?start_date=2025-07-01&end_date=2025-07-12

# Search by name
/api/v1/inventory?search=production&fields=name,tags

# Complex filtering
/api/v1/inventory?service=ec2&status=running&tags.environment=prod
```

### Supported Operators
- `eq` - Equals
- `ne` - Not equals
- `gt` - Greater than
- `gte` - Greater than or equal
- `lt` - Less than
- `lte` - Less than or equal
- `in` - In list
- `contains` - String contains

## 📈 Error Handling

### HTTP Status Codes
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict
- `429` - Rate Limited
- `500` - Internal Server Error

### Error Response Codes
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": {
      "field": "regions",
      "issue": "Invalid region code",
      "allowed_values": ["us-east-1", "us-west-2", "eu-west-1"]
    }
  }
}
```

### Common Error Codes
- `INVALID_REQUEST` - Request format or parameters invalid
- `AUTHENTICATION_FAILED` - Invalid credentials
- `AUTHORIZATION_FAILED` - Insufficient permissions
- `RESOURCE_NOT_FOUND` - Requested resource doesn't exist
- `RATE_LIMITED` - Too many requests
- `SERVICE_UNAVAILABLE` - Service temporarily unavailable

## 🔧 API Versioning

### Version Header
```bash
curl -H "Accept: application/vnd.lg-protect.v1+json" \
  /api/v1/scans
```

### URL Versioning
```bash
# Current version
/api/v1/scans

# Future version
/api/v2/scans
```

## 📚 SDKs & Libraries

### Python SDK
```python
from lg_protect import LGProtectClient

client = LGProtectClient(
    api_key="lgp_1234567890abcdef",
    base_url="https://api.lg-protect.com"
)

# Start scan
scan = client.scans.create({
    "name": "Security Scan",
    "type": "full",
    "regions": ["us-east-1"]
})

# Monitor progress
status = client.scans.get_status(scan.id)
```

### JavaScript SDK
```javascript
import { LGProtectClient } from '@lg-protect/sdk';

const client = new LGProtectClient({
  apiKey: 'lgp_1234567890abcdef',
  baseUrl: 'https://api.lg-protect.com'
});

// Start scan
const scan = await client.scans.create({
  name: 'Security Scan',
  type: 'full',
  regions: ['us-east-1']
});
```

## 🧪 Testing & Development

### Sandbox Environment
- **Base URL**: `https://sandbox-api.lg-protect.com`
- **Test Data**: Pre-populated with sample AWS resources
- **Rate Limits**: Relaxed for development

### API Testing Tools
- **Postman Collection**: [Download here](postman-collection.json)
- **OpenAPI Spec**: [View Swagger UI](swagger-ui.html)
- **curl Examples**: Complete curl command examples

---

*For detailed endpoint documentation, see the specific API sections linked above.*