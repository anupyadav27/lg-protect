# How to Add a New Service or Feature to the Inventory System

This guide explains how to extend the LG-Protect inventory system with new services or features. The inventory system is distributed across multiple components and follows an event-driven microservices architecture.

## 📋 Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Adding a New Cloud Service](#adding-a-new-cloud-service)
3. [Adding a New Feature to Existing Service](#adding-a-new-feature-to-existing-service)
4. [Event-Driven Integration](#event-driven-integration)
5. [Testing Your Changes](#testing-your-changes)
6. [Deployment Considerations](#deployment-considerations)

## 🏗️ Architecture Overview

The inventory system consists of several components:

- **Backend Inventory Service** (`backend/services/inventory-service/`)
- **CSPM Inventory Collector** (`cspm/cspm-platform/services/inventory-collector/`)
- **Core Inventory Engine** (`data/inventory/`)
- **Event Bus Integration** for real-time updates

### Key Components:

```
inventory-system/
├── backend/services/inventory-service/          # Main backend service
├── cspm/cspm-platform/services/inventory-collector/ # CSPM collector
├── data/inventory/                              # Data processing
└── frontend/components/                         # UI components
```

## ☁️ Adding a New Cloud Service

### Step 1: Update Service Definitions

First, add your new service to the service mapping configuration:

**File: `data/inventory/service_enablement_mapping.json`**

```json
{
  "your-new-service": {
    "service_name": "your-new-service",
    "display_name": "Your New Service",
    "category": "compute|storage|database|networking|security",
    "scope": "regional|global",
    "api_methods": [
      "list_resources",
      "describe_resource"
    ],
    "resource_identifiers": {
      "primary": "ResourceId",
      "secondary": "Name"
    },
    "regions": ["us-east-1", "us-west-2", "eu-west-1"]
  }
}
```

### Step 2: Update the Inventory Collection Engine

**File: `cspm/cspm-platform/services/inventory-collector/engine/inventory_collection.py`**

Add service-specific logic to the collection engine:

```python
# Add to the resolve_param function
def resolve_param(service, function_name, param, region):
    try:
        # Add your service-specific resolvers
        resolvers = {
            # ...existing code...
            "your-new-service": {
                "ResourceId": lambda c: get_default_resource_id(c),
                "ResourceType": lambda _: "your-resource-type"
            }
        }
        # ...existing code...
```

### Step 3: Update the Inventory Collector Service

**File: `csmp/cspm-platform/services/inventory-collector/index.js`**

Extend the scanning logic:

```javascript
async function performInventoryScan(scanParams = {}) {
  console.log('🔍 Performing inventory scan...');
  
  // ...existing services...
  
  // Add your new service
  const newService = {
    id: 'svc-new-001',
    name: 'Your New Service',
    type: 'your-category',
    provider: 'aws', // or 'azure', 'gcp'
    region: scanParams.region || 'us-east-1',
    status: 'active',
    resources: await countYourServiceResources(),
    lastUpdated: new Date().toISOString()
  };

  services.push(newService);
  
  // ...existing code...
}

// Add helper function for your service
async function countYourServiceResources() {
  // Implement resource counting logic
  try {
    // Call your service API
    const response = await yourServiceClient.listResources();
    return response.Resources ? response.Resources.length : 0;
  } catch (error) {
    console.error('Error counting resources for your service:', error);
    return 0;
  }
}
```

### Step 4: Add Service Configuration Files

Create configuration files for your new service:

**File: `cspm/cspm-platform/services/inventory-collector/config/your-service-config.json`**

```json
{
  "serviceName": "your-new-service",
  "version": "1.0.0",
  "endpoints": {
    "listResources": "list_your_resources",
    "describeResource": "describe_your_resource"
  },
  "rateLimits": {
    "requestsPerSecond": 10,
    "burstLimit": 50
  },
  "retryPolicy": {
    "maxRetries": 3,
    "backoffMultiplier": 2
  }
}
```

## 🔧 Adding a New Feature to Existing Service

### Step 1: Extend the Data Model

**File: `backend/services/inventory-service/models/inventory.py`** (if it exists)

```python
from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime

@dataclass
class InventoryResource:
    # ...existing fields...
    
    # Add your new feature fields
    new_feature_data: Optional[Dict] = None
    feature_enabled: bool = False
    feature_last_updated: Optional[datetime] = None

@dataclass
class InventoryService:
    # ...existing fields...
    
    # Add service-level feature data
    supported_features: List[str] = None
    feature_configurations: Dict = None
```

### Step 2: Update API Endpoints

**File: `cspm/cspm-platform/services/inventory-collector/index.js`**

Add new endpoints for your feature:

```javascript
// Add new endpoint for your feature
app.get('/api/inventory/features/:featureName', (req, res) => {
  const { featureName } = req.params;
  
  try {
    const featureData = getFeatureData(featureName);
    res.json({
      feature: featureName,
      data: featureData,
      lastUpdated: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error getting feature data:', error);
    res.status(500).json({ error: 'Failed to retrieve feature data' });
  }
});

app.post('/api/inventory/features/:featureName/enable', async (req, res) => {
  const { featureName } = req.params;
  
  try {
    const result = await enableFeature(featureName, req.body);
    
    // Publish feature enabled event
    await eventClient.publish('inventory.feature.enabled', {
      featureName,
      configuration: req.body,
      timestamp: new Date().toISOString()
    });
    
    res.json({
      message: `Feature ${featureName} enabled successfully`,
      result
    });
  } catch (error) {
    console.error('Error enabling feature:', error);
    res.status(500).json({ error: 'Failed to enable feature' });
  }
});

// Helper functions
function getFeatureData(featureName) {
  // Implement feature data retrieval
  return inventoryData.resources
    .filter(resource => resource.features && resource.features[featureName])
    .map(resource => ({
      resourceId: resource.id,
      featureData: resource.features[featureName]
    }));
}

async function enableFeature(featureName, configuration) {
  // Implement feature enabling logic
  console.log(`Enabling feature: ${featureName}`);
  
  // Update resources with new feature
  inventoryData.resources.forEach(resource => {
    if (!resource.features) {
      resource.features = {};
    }
    resource.features[featureName] = {
      enabled: true,
      configuration,
      enabledAt: new Date().toISOString()
    };
  });
  
  return { enabled: true, resourcesUpdated: inventoryData.resources.length };
}
```

## 📡 Event-Driven Integration

### Step 1: Define New Events

Add event definitions for your service or feature:

**File: `backend/events/event_types.py`**

```python
# Add new event types
class InventoryEventTypes:
    # ...existing events...
    
    # New service events
    NEW_SERVICE_DISCOVERED = "inventory.service.discovered"
    SERVICE_CONFIGURATION_CHANGED = "inventory.service.config.changed"
    
    # New feature events
    FEATURE_ENABLED = "inventory.feature.enabled"
    FEATURE_DISABLED = "inventory.feature.disabled"
    FEATURE_DATA_UPDATED = "inventory.feature.data.updated"
```

### Step 2: Add Event Handlers

**File: `backend/events/event_handler.py`**

```python
async def handle_new_service_discovered(event_data):
    """Handle new service discovery events"""
    try:
        service_info = event_data.get('service_info')
        
        # Process new service
        await process_new_service(service_info)
        
        # Notify other services
        await publish_event(
            InventoryEventTypes.SERVICE_CONFIGURATION_CHANGED,
            {
                'service_name': service_info['name'],
                'action': 'added',
                'timestamp': datetime.utcnow().isoformat()
            }
        )
        
    except Exception as e:
        logger.error(f"Error handling new service discovery: {e}")

async def handle_feature_enabled(event_data):
    """Handle feature enabled events"""
    try:
        feature_name = event_data.get('feature_name')
        configuration = event_data.get('configuration')
        
        # Update inventory with feature data
        await update_inventory_features(feature_name, configuration)
        
        # Trigger compliance re-evaluation if needed
        await publish_event(
            'compliance.reevaluation.requested',
            {
                'trigger': 'inventory_feature_enabled',
                'feature': feature_name
            }
        )
        
    except Exception as e:
        logger.error(f"Error handling feature enabled: {e}")
```

### Step 3: Update Event Router

**File: `backend/events/event_router.py`**

```python
# Add routing for new events
EVENT_HANDLERS = {
    # ...existing handlers...
    
    InventoryEventTypes.NEW_SERVICE_DISCOVERED: handle_new_service_discovered,
    InventoryEventTypes.FEATURE_ENABLED: handle_feature_enabled,
    InventoryEventTypes.FEATURE_DISABLED: handle_feature_disabled,
}
```

## 🧪 Testing Your Changes

### Step 1: Unit Tests

Create tests for your new service or feature:

**File: `tests/unit/inventory-service/test_new_service.py`**

```python
import pytest
from unittest.mock import Mock, patch
from your_service_module import YourNewService

class TestYourNewService:
    
    def setup_method(self):
        self.service = YourNewService()
    
    @patch('boto3.client')
    def test_list_resources(self, mock_client):
        # Mock AWS client response
        mock_client.return_value.list_your_resources.return_value = {
            'Resources': [
                {'ResourceId': 'res-123', 'Name': 'test-resource'}
            ]
        }
        
        # Test the service
        resources = self.service.list_resources()
        
        assert len(resources) == 1
        assert resources[0]['ResourceId'] == 'res-123'
    
    def test_count_resources(self):
        # Test resource counting
        with patch.object(self.service, 'list_resources') as mock_list:
            mock_list.return_value = [{'id': '1'}, {'id': '2'}]
            
            count = self.service.count_resources()
            assert count == 2

    @patch('your_service_module.eventClient')
    async def test_feature_enabling(self, mock_event_client):
        # Test feature enabling
        result = await self.service.enable_feature('test-feature', {})
        
        assert result['enabled'] is True
        mock_event_client.publish.assert_called_once()
```

### Step 2: Integration Tests

**File: `tests/integration/test_inventory_workflows.py`**

```python
async def test_new_service_integration():
    """Test end-to-end workflow for new service"""
    
    # 1. Trigger service discovery
    scan_result = await trigger_inventory_scan({
        'services': ['your-new-service'],
        'regions': ['us-east-1']
    })
    
    # 2. Verify service was discovered
    assert 'your-new-service' in scan_result['services']
    
    # 3. Verify events were published
    published_events = await get_published_events()
    assert any(e['type'] == 'inventory.service.discovered' for e in published_events)
    
    # 4. Verify data was stored
    inventory_data = await get_inventory_data()
    assert any(s['name'] == 'Your New Service' for s in inventory_data['services'])

async def test_feature_workflow():
    """Test feature enabling workflow"""
    
    # 1. Enable feature
    response = await enable_inventory_feature('test-feature', {
        'option1': 'value1'
    })
    
    assert response['enabled'] is True
    
    # 2. Verify feature data is accessible
    feature_data = await get_feature_data('test-feature')
    assert feature_data is not None
    
    # 3. Verify compliance re-evaluation was triggered
    compliance_events = await get_compliance_events()
    assert any(e['trigger'] == 'inventory_feature_enabled' for e in compliance_events)
```

### Step 3: Performance Tests

**File: `tests/performance/test_new_service_performance.py`**

```python
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor

async def test_service_scan_performance():
    """Test scanning performance for new service"""
    
    start_time = time.time()
    
    # Scan multiple regions concurrently
    tasks = []
    regions = ['us-east-1', 'us-west-2', 'eu-west-1']
    
    for region in regions:
        task = scan_service_in_region('your-new-service', region)
        tasks.append(task)
    
    results = await asyncio.gather(*tasks)
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Performance assertions
    assert duration < 30  # Should complete within 30 seconds
    assert len(results) == len(regions)
    assert all(r['status'] == 'success' for r in results)

def test_concurrent_feature_operations():
    """Test concurrent feature operations"""
    
    def enable_feature_worker(feature_name):
        return enable_feature(f"{feature_name}", {})
    
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for i in range(10):
            future = executor.submit(enable_feature_worker, f"feature-{i}")
            futures.append(future)
        
        results = [f.result() for f in futures]
    
    duration = time.time() - start_time
    
    # All operations should succeed
    assert all(r['enabled'] for r in results)
    # Should handle concurrency efficiently
    assert duration < 15
```

## 🚀 Deployment Considerations

### Step 1: Update Docker Configuration

**File: `infrastructure/docker-compose/docker-compose.yml`**

```yaml
services:
  # ...existing services...
  
  inventory-service:
    build:
      context: ../../backend/services/inventory-service
      dockerfile: Dockerfile
    environment:
      - NEW_SERVICE_ENABLED=true
      - FEATURE_FLAGS=your-new-feature:enabled
    depends_on:
      - event-bus
      - database
```

### Step 2: Update Kubernetes Manifests

**File: `infrastructure/kubernetes/inventory-service-deployment.yaml`**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inventory-service
spec:
  template:
    spec:
      containers:
      - name: inventory-service
        image: lg-protect/inventory-service:latest
        env:
        - name: NEW_SERVICE_ENABLED
          value: "true"
        - name: FEATURE_FLAGS
          value: "your-new-feature:enabled"
        # ...existing configuration...
```

### Step 3: Database Migrations

**File: `backend/services/inventory-service/migrations/add_new_service_support.sql`**

```sql
-- Add tables for new service
CREATE TABLE IF NOT EXISTS your_service_resources (
    id SERIAL PRIMARY KEY,
    resource_id VARCHAR(255) UNIQUE NOT NULL,
    resource_name VARCHAR(255),
    service_type VARCHAR(100) NOT NULL DEFAULT 'your-new-service',
    region VARCHAR(50),
    status VARCHAR(50) DEFAULT 'active',
    metadata JSONB,
    features JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add indexes for performance
CREATE INDEX idx_your_service_resources_region ON your_service_resources(region);
CREATE INDEX idx_your_service_resources_status ON your_service_resources(status);
CREATE INDEX idx_your_service_resources_features ON your_service_resources USING GIN(features);

-- Add feature tracking table
CREATE TABLE IF NOT EXISTS inventory_features (
    id SERIAL PRIMARY KEY,
    feature_name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT false,
    configuration JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 📝 Configuration Checklist

Before deploying your changes, ensure you've updated:

- [ ] Service mapping configuration files
- [ ] Event type definitions
- [ ] Event handlers and routing
- [ ] API endpoints and documentation
- [ ] Database schema (if needed)
- [ ] Docker and Kubernetes configurations
- [ ] Unit and integration tests
- [ ] Performance benchmarks
- [ ] Monitoring and alerting rules
- [ ] Documentation

## 🔍 Monitoring and Observability

Add monitoring for your new service or feature:

**File: `infrastructure/docker-compose/prometheus.yml`**

```yaml
# Add metrics collection for your service
- job_name: 'your-new-service'
  static_configs:
    - targets: ['inventory-service:3000']
  metrics_path: '/metrics/your-service'
  scrape_interval: 30s
```

## 📚 Additional Resources

- [Event Bus Documentation](../api/event-bus.md)
- [Database Schema Guide](../architecture/database-schema.md)
- [API Development Standards](../development/api-standards.md)
- [Testing Framework Guide](../development/testing-guide.md)

---

**Next Steps**: After implementing your changes, consider adding specific examples and updating the main architecture documentation to reflect your new service or feature.