# Inventory API Documentation

## Overview

The LG-Protect Inventory API provides comprehensive asset management capabilities for AWS resources discovered through the inventory service. The API supports asset listing, searching, filtering, export, and relationship analysis.

## Base URL

```
http://localhost:8000/api/inventory
```

## Authentication

Currently, the API does not require authentication for development purposes. In production, implement proper authentication mechanisms.

## API Endpoints

### 1. GET /api/inventory

**Description:** Fetch full asset list with optional filtering

**URL:** `GET /api/inventory`

**Query Parameters:**
- `limit` (optional): Maximum number of results (default: 100, max: 1000)
- `offset` (optional): Number of results to skip (default: 0)
- `service` (optional): Filter by AWS service (e.g., "ec2", "s3")
- `region` (optional): Filter by AWS region (e.g., "us-east-1")
- `risk_level` (optional): Filter by risk level (e.g., "high", "medium", "low")

**Response:**
```json
[
  {
    "asset_id": "ec2-001",
    "asset_type": "compute",
    "service_name": "ec2",
    "region": "us-east-1",
    "name": "web-server-01",
    "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
    "tags": {
      "Project": "web-app",
      "Environment": "production"
    },
    "risk_score": 75,
    "security_findings": [...],
    "compliance_status": {...},
    "relationships": {...},
    "state": "active",
    "created_at": "2025-01-12T10:30:00Z",
    "last_scan_at": "2025-01-12T15:45:00Z",
    "metadata": {...},
    "enhanced_risk_score": {...}
  }
]
```

**Example:**
```bash
curl -X GET "http://localhost:8000/api/inventory?limit=10&service=ec2"
```

### 2. POST /api/inventory/search

**Description:** Advanced search with multiple filter criteria

**URL:** `POST /api/inventory/search`

**Request Body:**
```json
{
  "services": ["ec2", "s3"],
  "regions": ["us-east-1", "us-west-2"],
  "resource_types": ["compute", "storage"],
  "risk_levels": ["high", "critical"],
  "compliance_frameworks": ["cis", "soc2"],
  "tags": {
    "Environment": "production"
  },
  "min_risk_score": 50,
  "max_risk_score": 100,
  "has_findings": true,
  "finding_severities": ["critical", "high"],
  "limit": 100,
  "offset": 0,
  "sort_by": "risk_score",
  "sort_order": "desc"
}
```

**Response:** Same as GET /api/inventory

**Example:**
```bash
curl -X POST "http://localhost:8000/api/inventory/search" \
  -H "Content-Type: application/json" \
  -d '{
    "services": ["ec2", "s3"],
    "limit": 10,
    "sort_by": "risk_score",
    "sort_order": "desc"
  }'
```

### 3. GET /api/inventory/summary

**Description:** Get comprehensive inventory summary statistics

**URL:** `GET /api/inventory/summary`

**Response:**
```json
{
  "total_assets": 150,
  "total_findings": 45,
  "by_cloud": {
    "aws": 150
  },
  "by_type": {
    "compute": 50,
    "storage": 30,
    "database": 20,
    "network": 25,
    "security": 15,
    "other": 10
  },
  "by_project": {
    "web-app": 80,
    "data-storage": 40,
    "unknown": 30
  },
  "by_risk_level": {
    "critical": 10,
    "high": 25,
    "medium": 60,
    "low": 45,
    "unknown": 10
  },
  "by_region": {
    "us-east-1": 80,
    "us-west-2": 45,
    "eu-west-1": 25
  },
  "by_service": {
    "ec2": 50,
    "s3": 30,
    "rds": 20,
    "lambda": 25,
    "iam": 15,
    "other": 10
  },
  "last_scan": "2025-01-12T15:45:00Z",
  "scan_status": "completed"
}
```

**Example:**
```bash
curl -X GET "http://localhost:8000/api/inventory/summary"
```

### 4. GET /api/inventory/{asset_id}

**Description:** Get detailed information for a specific asset

**URL:** `GET /api/inventory/{asset_id}`

**Path Parameters:**
- `asset_id`: Unique identifier of the asset

**Response:** Same as individual asset in GET /api/inventory

**Example:**
```bash
curl -X GET "http://localhost:8000/api/inventory/ec2-001"
```

### 5. GET /api/inventory/{asset_id}/relationships

**Description:** Get relationship graph data for a specific asset

**URL:** `GET /api/inventory/{asset_id}/relationships`

**Path Parameters:**
- `asset_id`: Unique identifier of the asset

**Response:**
```json
{
  "nodes": [
    {
      "id": "ec2-001",
      "label": "web-server-01",
      "type": "compute",
      "service": "ec2",
      "region": "us-east-1",
      "risk_score": 75,
      "is_main": true
    },
    {
      "id": "s3-001",
      "label": "data-bucket",
      "type": "storage",
      "service": "s3",
      "region": "us-east-1",
      "risk_score": 45,
      "is_main": false
    }
  ],
  "edges": [
    {
      "source": "ec2-001",
      "target": "s3-001",
      "type": "accesses",
      "data": {
        "permission_level": "read"
      }
    }
  ],
  "asset_id": "ec2-001",
  "relationship_types": ["accesses", "connects_to"]
}
```

**Example:**
```bash
curl -X GET "http://localhost:8000/api/inventory/ec2-001/relationships"
```

### 6. POST /api/inventory/export

**Description:** Export inventory data in various formats

**URL:** `POST /api/inventory/export`

**Request Body:**
```json
{
  "format": "json",
  "filters": {
    "services": ["ec2", "s3"],
    "regions": ["us-east-1"]
  },
  "include_relationships": true,
  "include_findings": true
}
```

**Parameters:**
- `format`: Export format ("json", "csv")
- `filters` (optional): Same as search filters
- `include_relationships`: Include relationship data
- `include_findings`: Include security findings

**Response:** File download (JSON or CSV)

**Example:**
```bash
curl -X POST "http://localhost:8000/api/inventory/export" \
  -H "Content-Type: application/json" \
  -d '{
    "format": "json",
    "include_relationships": true,
    "include_findings": true
  }' \
  --output inventory_export.json
```

### 7. PATCH /api/inventory/{asset_id}/review

**Description:** Mark an asset as reviewed

**URL:** `PATCH /api/inventory/{asset_id}/review`

**Path Parameters:**
- `asset_id`: Unique identifier of the asset

**Request Body:**
```json
{
  "reviewed_by": "security-analyst",
  "review_notes": "Asset reviewed and approved",
  "review_status": "reviewed"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Asset ec2-001 marked as reviewed",
  "asset_id": "ec2-001",
  "reviewed_by": "security-analyst",
  "reviewed_at": "2025-01-12T16:30:00Z"
}
```

**Example:**
```bash
curl -X PATCH "http://localhost:8000/api/inventory/ec2-001/review" \
  -H "Content-Type: application/json" \
  -d '{
    "reviewed_by": "security-analyst",
    "review_notes": "Asset reviewed and approved",
    "review_status": "reviewed"
  }'
```

### 8. GET /api/inventory/tags

**Description:** Get all unique tag keys and their values

**URL:** `GET /api/inventory/tags`

**Response:**
```json
[
  {
    "key": "Project",
    "values": ["web-app", "data-storage", "api-service"],
    "count": 3
  },
  {
    "key": "Environment",
    "values": ["production", "staging", "development"],
    "count": 3
  },
  {
    "key": "Owner",
    "values": ["team-a", "team-b"],
    "count": 2
  }
]
```

**Example:**
```bash
curl -X GET "http://localhost:8000/api/inventory/tags"
```

## Data Models

### Asset Model
```json
{
  "asset_id": "string",
  "asset_type": "compute|storage|database|network|security|identity|monitoring|analytics|application|other",
  "service_name": "string",
  "region": "string",
  "name": "string",
  "arn": "string",
  "tags": {
    "key": "value"
  },
  "risk_score": 0-100,
  "security_findings": [...],
  "compliance_status": {...},
  "relationships": {...},
  "state": "active|inactive|reviewed",
  "created_at": "ISO8601",
  "last_scan_at": "ISO8601",
  "metadata": {...},
  "enhanced_risk_score": {...}
}
```

### Security Finding Model
```json
{
  "finding_id": "string",
  "title": "string",
  "description": "string",
  "severity": "critical|high|medium|low|info",
  "finding_type": "string",
  "compliance_frameworks": ["cis", "soc2"],
  "remediation": "string",
  "created_at": "ISO8601",
  "resource_id": "string"
}
```

## Error Responses

### Standard Error Format
```json
{
  "detail": "Error message description"
}
```

### Common HTTP Status Codes
- `200 OK`: Request successful
- `400 Bad Request`: Invalid request parameters
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server error

## Rate Limiting

Currently, no rate limiting is implemented. In production, implement appropriate rate limiting based on your requirements.

## Testing

Use the provided test script to verify API functionality:

```bash
cd backend/services/inventory-service
python test_inventory_api.py
```

## Development

### Running the Service
```bash
cd backend/services/inventory-service/src
python main.py
```

### API Documentation
Once the service is running, visit:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Future Enhancements

1. **Authentication & Authorization**: Implement proper authentication mechanisms
2. **Rate Limiting**: Add rate limiting for API endpoints
3. **Caching**: Implement response caching for frequently accessed data
4. **Real-time Updates**: Add WebSocket support for real-time inventory updates
5. **Bulk Operations**: Support bulk asset operations
6. **Advanced Filtering**: Add more sophisticated filtering options
7. **Export Formats**: Support additional export formats (XLSX, PDF)
8. **Audit Logging**: Comprehensive audit trail for all operations 