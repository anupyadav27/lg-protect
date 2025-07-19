const express = require('express');
const execSync = require('child_process').execSync;
const fs = require('fs');
const path = require('path');

// Import event system (assuming we'll create a shared event client)
const EventClient = require('../../shared/event-client');

const app = express();
app.use(express.json());

// Initialize event client
const eventClient = new EventClient('inventory-collector');

// In-memory storage for inventory data
let inventoryData = {
  services: [],
  resources: [],
  lastScan: null
};

function freePort(port) {
  try {
    const result = execSync(`lsof -i :${port} -t`).toString();
    const pids = result.split('\n').filter(Boolean);
    pids.forEach(pid => execSync(`kill -9 ${pid}`));
    console.log(`Freed port ${port}`);
  } catch (error) {
    console.log(`Port ${port} is already free or could not be freed.`);
  }
}

const PORT = process.env.PORT || 3117;
freePort(PORT);

// Event handlers
eventClient.on('inventory.scan.requested', async (event) => {
  console.log('📦 Inventory scan requested:', event);
  
  try {
    // Simulate inventory scanning
    const scanResults = await performInventoryScan(event.data);
    
    // Update local inventory
    inventoryData.services = scanResults.services;
    inventoryData.resources = scanResults.resources;
    inventoryData.lastScan = new Date().toISOString();
    
    // Publish scan completed event
    await eventClient.publish('inventory.scan.completed', {
      requestId: event.requestId,
      correlationId: event.correlationId,
      services: scanResults.services,
      resources: scanResults.resources,
      timestamp: inventoryData.lastScan
    });
    
    console.log('✅ Inventory scan completed');
  } catch (error) {
    console.error('❌ Inventory scan failed:', error);
    
    // Publish scan failed event
    await eventClient.publish('inventory.scan.failed', {
      requestId: event.requestId,
      correlationId: event.correlationId,
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

eventClient.on('inventory.policy.updated', async (event) => {
  console.log('📋 Inventory policy updated:', event);
  
  try {
    // Re-evaluate current inventory against new policy
    const evaluationResults = await evaluateInventoryPolicy(event.data.policy);
    
    // Publish policy evaluation results
    await eventClient.publish('inventory.policy.evaluated', {
      requestId: event.requestId,
      correlationId: event.correlationId,
      results: evaluationResults,
      timestamp: new Date().toISOString()
    });
    
    console.log('✅ Inventory policy evaluation completed');
  } catch (error) {
    console.error('❌ Inventory policy evaluation failed:', error);
  }
});

// HTTP Endpoints
app.get('/', (req, res) => {
  res.json({
    service: 'Inventory Collector Service',
    status: 'running',
    lastScan: inventoryData.lastScan,
    servicesCount: inventoryData.services.length,
    resourcesCount: inventoryData.resources.length
  });
});

app.get('/api/inventory/services', (req, res) => {
  res.json({
    services: inventoryData.services,
    lastScan: inventoryData.lastScan,
    total: inventoryData.services.length
  });
});

app.get('/api/inventory/resources', (req, res) => {
  res.json({
    resources: inventoryData.resources,
    lastScan: inventoryData.lastScan,
    total: inventoryData.resources.length
  });
});

app.post('/api/inventory/scan', async (req, res) => {
  const requestId = `scan_${Date.now()}`;
  
  try {
    // Trigger scan via event
    await eventClient.publish('inventory.scan.requested', {
      requestId,
      correlationId: req.headers['x-correlation-id'] || requestId,
      data: req.body,
      timestamp: new Date().toISOString()
    });
    
    res.json({
      requestId,
      message: 'Inventory scan initiated',
      status: 'processing'
    });
  } catch (error) {
    console.error('Error initiating scan:', error);
    res.status(500).json({ error: 'Failed to initiate scan' });
  }
});

// Business logic functions
async function performInventoryScan(scanParams = {}) {
  console.log('🔍 Performing inventory scan...');
  
  // Simulate scanning different cloud services
  const services = [
    {
      id: 'svc-001',
      name: 'EC2 Instances',
      type: 'compute',
      provider: 'aws',
      region: 'us-east-1',
      status: 'active',
      resources: 12,
      lastUpdated: new Date().toISOString()
    },
    {
      id: 'svc-002',
      name: 'S3 Buckets',
      type: 'storage',
      provider: 'aws',
      region: 'us-east-1',
      status: 'active',
      resources: 5,
      lastUpdated: new Date().toISOString()
    },
    {
      id: 'svc-003',
      name: 'RDS Instances',
      type: 'database',
      provider: 'aws',
      region: 'us-east-1',
      status: 'active',
      resources: 3,
      lastUpdated: new Date().toISOString()
    }
  ];
  
  const resources = services.flatMap(service => 
    Array.from({ length: service.resources }, (_, i) => ({
      id: `${service.id}-res-${i + 1}`,
      serviceId: service.id,
      name: `${service.name} Resource ${i + 1}`,
      type: service.type,
      status: Math.random() > 0.1 ? 'healthy' : 'warning',
      tags: {
        Environment: Math.random() > 0.5 ? 'production' : 'development',
        Owner: 'DevOps Team'
      },
      lastUpdated: new Date().toISOString()
    }))
  );
  
  // Simulate scan delay
  await new Promise(resolve => setTimeout(resolve, 2000));
  
  return { services, resources };
}

async function evaluateInventoryPolicy(policy) {
  console.log('📊 Evaluating inventory against policy...');
  
  // Simulate policy evaluation
  const violations = [];
  const recommendations = [];
  
  // Check for untagged resources
  inventoryData.resources.forEach(resource => {
    if (!resource.tags || Object.keys(resource.tags).length === 0) {
      violations.push({
        resourceId: resource.id,
        type: 'missing_tags',
        severity: 'medium',
        message: 'Resource is missing required tags'
      });
      
      recommendations.push({
        resourceId: resource.id,
        action: 'add_tags',
        suggestion: 'Add Environment and Owner tags'
      });
    }
  });
  
  return {
    violations,
    recommendations,
    complianceScore: Math.max(0, 100 - (violations.length * 10))
  };
}

// Event client lifecycle
async function startService() {
  try {
    await eventClient.connect();
    console.log('📡 Connected to event bus');
    
    app.listen(PORT, () => {
      console.log(`📦 Inventory Collector Service is running on port ${PORT}`);
    });
  } catch (error) {
    console.error('❌ Failed to start service:', error);
    process.exit(1);
  }
}

async function stopService() {
  try {
    await eventClient.disconnect();
    console.log('📡 Disconnected from event bus');
  } catch (error) {
    console.error('Error disconnecting from event bus:', error);
  }
}

// Graceful shutdown
process.on('SIGTERM', stopService);
process.on('SIGINT', stopService);

// Start the service
startService();