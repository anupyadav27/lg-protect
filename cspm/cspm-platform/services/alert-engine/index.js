const express = require('express');
const EventClient = require('../../shared/event-client');

const app = express();
app.use(express.json());

// Initialize event client
const eventClient = new EventClient('alert-engine');

// In-memory storage for alerts
let alertsData = {
  active: [],
  resolved: [],
  rules: [
    {
      id: 'rule-001',
      name: 'High Severity Security Violation',
      condition: 'security.violation.severity == "high"',
      action: 'immediate_alert',
      enabled: true
    },
    {
      id: 'rule-002', 
      name: 'Compliance Drift Detected',
      condition: 'compliance.drift.detected',
      action: 'compliance_alert',
      enabled: true
    },
    {
      id: 'rule-003',
      name: 'Inventory Scan Failed',
      condition: 'inventory.scan.failed',
      action: 'operational_alert',
      enabled: true
    }
  ]
};

// Event handlers
eventClient.on('security.violation.detected', async (event) => {
  console.log('🚨 Security violation detected:', event);
  
  try {
    const alert = await generateSecurityAlert(event);
    alertsData.active.push(alert);
    
    // Publish alert generated event
    await eventClient.publish('alert.generated', {
      requestId: event.requestId,
      correlationId: event.correlationId,
      alert: alert,
      timestamp: new Date().toISOString()
    });
    
    // If high severity, also send notification
    if (alert.severity === 'high' || alert.severity === 'critical') {
      await eventClient.publish('notification.send', {
        type: 'security_alert',
        priority: 'high',
        alert: alert,
        timestamp: new Date().toISOString()
      });
    }
    
    console.log('✅ Security alert generated:', alert.id);
  } catch (error) {
    console.error('❌ Failed to generate security alert:', error);
  }
});

eventClient.on('compliance.drift.detected', async (event) => {
  console.log('📊 Compliance drift detected:', event);
  
  try {
    const alert = await generateComplianceAlert(event);
    alertsData.active.push(alert);
    
    await eventClient.publish('alert.generated', {
      requestId: event.requestId,
      correlationId: event.correlationId,
      alert: alert,
      timestamp: new Date().toISOString()
    });
    
    console.log('✅ Compliance alert generated:', alert.id);
  } catch (error) {
    console.error('❌ Failed to generate compliance alert:', error);
  }
});

eventClient.on('inventory.scan.failed', async (event) => {
  console.log('📦 Inventory scan failed:', event);
  
  try {
    const alert = await generateOperationalAlert(event);
    alertsData.active.push(alert);
    
    await eventClient.publish('alert.generated', {
      requestId: event.requestId,
      correlationId: event.correlationId,
      alert: alert,
      timestamp: new Date().toISOString()
    });
    
    console.log('✅ Operational alert generated:', alert.id);
  } catch (error) {
    console.error('❌ Failed to generate operational alert:', error);
  }
});

eventClient.on('alert.acknowledge', async (event) => {
  console.log('👤 Alert acknowledged:', event);
  
  try {
    const alertId = event.data.alertId;
    const alert = alertsData.active.find(a => a.id === alertId);
    
    if (alert) {
      alert.status = 'acknowledged';
      alert.acknowledgedBy = event.data.userId;
      alert.acknowledgedAt = new Date().toISOString();
      
      await eventClient.publish('alert.status.updated', {
        alertId: alertId,
        status: 'acknowledged',
        timestamp: new Date().toISOString()
      });
    }
  } catch (error) {
    console.error('❌ Failed to acknowledge alert:', error);
  }
});

eventClient.on('alert.resolve', async (event) => {
  console.log('✅ Alert resolution requested:', event);
  
  try {
    const alertId = event.data.alertId;
    const alertIndex = alertsData.active.findIndex(a => a.id === alertId);
    
    if (alertIndex !== -1) {
      const alert = alertsData.active[alertIndex];
      alert.status = 'resolved';
      alert.resolvedBy = event.data.userId;
      alert.resolvedAt = new Date().toISOString();
      alert.resolution = event.data.resolution;
      
      // Move to resolved alerts
      alertsData.resolved.push(alert);
      alertsData.active.splice(alertIndex, 1);
      
      await eventClient.publish('alert.status.updated', {
        alertId: alertId,
        status: 'resolved',
        timestamp: new Date().toISOString()
      });
    }
  } catch (error) {
    console.error('❌ Failed to resolve alert:', error);
  }
});

// HTTP Endpoints
app.get('/', (req, res) => {
  res.json({
    service: 'Alert Engine Service',
    status: 'running',
    activeAlerts: alertsData.active.length,
    resolvedAlerts: alertsData.resolved.length,
    alertRules: alertsData.rules.length
  });
});

app.get('/api/alerts', (req, res) => {
  const { status = 'active', severity, limit = 50 } = req.query;
  
  let alerts = status === 'resolved' ? alertsData.resolved : alertsData.active;
  
  if (severity) {
    alerts = alerts.filter(alert => alert.severity === severity);
  }
  
  alerts = alerts.slice(0, parseInt(limit));
  
  res.json({
    alerts,
    total: alerts.length,
    status: status
  });
});

app.get('/api/alerts/:alertId', (req, res) => {
  const { alertId } = req.params;
  
  const alert = [...alertsData.active, ...alertsData.resolved]
    .find(a => a.id === alertId);
  
  if (!alert) {
    return res.status(404).json({ error: 'Alert not found' });
  }
  
  res.json(alert);
});

app.post('/api/alerts/:alertId/acknowledge', async (req, res) => {
  const { alertId } = req.params;
  const { userId } = req.body;
  
  try {
    await eventClient.publish('alert.acknowledge', {
      requestId: `ack_${Date.now()}`,
      data: { alertId, userId },
      timestamp: new Date().toISOString()
    });
    
    res.json({ message: 'Alert acknowledgment initiated' });
  } catch (error) {
    console.error('Error acknowledging alert:', error);
    res.status(500).json({ error: 'Failed to acknowledge alert' });
  }
});

app.post('/api/alerts/:alertId/resolve', async (req, res) => {
  const { alertId } = req.params;
  const { userId, resolution } = req.body;
  
  try {
    await eventClient.publish('alert.resolve', {
      requestId: `resolve_${Date.now()}`,
      data: { alertId, userId, resolution },
      timestamp: new Date().toISOString()
    });
    
    res.json({ message: 'Alert resolution initiated' });
  } catch (error) {
    console.error('Error resolving alert:', error);
    res.status(500).json({ error: 'Failed to resolve alert' });
  }
});

app.get('/api/alert-rules', (req, res) => {
  res.json({
    rules: alertsData.rules,
    total: alertsData.rules.length
  });
});

// Alert generation functions
async function generateSecurityAlert(event) {
  const alertId = `sec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  
  return {
    id: alertId,
    type: 'security',
    severity: event.data.severity || 'high',
    title: `Security Violation: ${event.data.violationType}`,
    description: event.data.description || 'A security violation has been detected',
    source: event.data.source || 'Security Scanner',
    resourceId: event.data.resourceId,
    resourceType: event.data.resourceType,
    status: 'active',
    createdAt: new Date().toISOString(),
    details: {
      violationType: event.data.violationType,
      riskScore: event.data.riskScore,
      compliance: event.data.compliance,
      recommendations: event.data.recommendations || []
    },
    tags: ['security', 'violation', event.data.violationType].filter(Boolean)
  };
}

async function generateComplianceAlert(event) {
  const alertId = `comp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  
  return {
    id: alertId,
    type: 'compliance',
    severity: 'medium',
    title: `Compliance Drift: ${event.data.framework}`,
    description: `Compliance drift detected for ${event.data.framework} framework`,
    source: 'Compliance Service',
    resourceId: event.data.resourceId,
    resourceType: event.data.resourceType,
    status: 'active',
    createdAt: new Date().toISOString(),
    details: {
      framework: event.data.framework,
      driftType: event.data.driftType,
      previousScore: event.data.previousScore,
      currentScore: event.data.currentScore,
      affectedControls: event.data.affectedControls || []
    },
    tags: ['compliance', 'drift', event.data.framework].filter(Boolean)
  };
}

async function generateOperationalAlert(event) {
  const alertId = `ops_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  
  return {
    id: alertId,
    type: 'operational',
    severity: 'low',
    title: 'Service Operation Failed',
    description: event.data.error || 'A service operation has failed',
    source: event.source || 'System',
    status: 'active',
    createdAt: new Date().toISOString(),
    details: {
      operation: event.data.operation,
      error: event.data.error,
      service: event.source
    },
    tags: ['operational', 'failure', event.source].filter(Boolean)
  };
}

// Service lifecycle
async function startService() {
  try {
    await eventClient.connect();
    console.log('📡 Connected to event bus');
    
    const PORT = process.env.PORT || 3114;
    app.listen(PORT, () => {
      console.log(`🚨 Alert Engine Service is running on port ${PORT}`);
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