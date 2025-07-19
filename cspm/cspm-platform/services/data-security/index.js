const express = require('express');
const execSync = require('child_process').execSync;
const EventClient = require('../../shared/event-client');

const app = express();
app.use(express.json());

// Initialize event client
const eventClient = new EventClient('data-security');

// In-memory storage for security data
let securityData = {
  vulnerabilities: [],
  policies: [
    {
      id: 'pol-001',
      name: 'Data Encryption Policy',
      type: 'encryption',
      rules: ['data_at_rest_encrypted', 'data_in_transit_encrypted'],
      enabled: true
    },
    {
      id: 'pol-002',
      name: 'Access Control Policy',
      type: 'access',
      rules: ['least_privilege', 'mfa_required'],
      enabled: true
    },
    {
      id: 'pol-003',
      name: 'Network Security Policy',
      type: 'network',
      rules: ['no_public_access', 'secure_protocols_only'],
      enabled: true
    }
  ],
  scans: [],
  threats: []
};

// Event handlers
eventClient.on('security.scan.requested', async (event) => {
  console.log('🔒 Security scan requested:', event);
  
  try {
    const scanResults = await performSecurityScan(event.data);
    
    // Store scan results
    securityData.scans.push({
      id: `scan_${Date.now()}`,
      requestId: event.requestId,
      type: event.data.scanType || 'full',
      status: 'completed',
      results: scanResults,
      timestamp: new Date().toISOString()
    });
    
    // Update vulnerabilities
    securityData.vulnerabilities = scanResults.vulnerabilities;
    
    // Publish scan completed event
    await eventClient.publish('security.scan.completed', {
      requestId: event.requestId,
      correlationId: event.correlationId,
      vulnerabilities: scanResults.vulnerabilities,
      complianceScore: scanResults.complianceScore,
      timestamp: new Date().toISOString()
    });
    
    // If critical vulnerabilities found, trigger alert
    const criticalVulns = scanResults.vulnerabilities.filter(v => v.severity === 'critical');
    if (criticalVulns.length > 0) {
      await eventClient.publish('security.violation.detected', {
        requestId: event.requestId,
        correlationId: event.correlationId,
        type: 'critical_vulnerabilities',
        count: criticalVulns.length,
        vulnerabilities: criticalVulns,
        severity: 'high',
        timestamp: new Date().toISOString()
      });
    }
    
    console.log('✅ Security scan completed');
  } catch (error) {
    console.error('❌ Security scan failed:', error);
    
    await eventClient.publish('security.scan.failed', {
      requestId: event.requestId,
      correlationId: event.correlationId,
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

eventClient.on('security.policy.updated', async (event) => {
  console.log('📋 Security policy updated:', event);
  
  try {
    const policyId = event.data.policyId;
    const existingPolicyIndex = securityData.policies.findIndex(p => p.id === policyId);
    
    if (existingPolicyIndex !== -1) {
      securityData.policies[existingPolicyIndex] = { ...securityData.policies[existingPolicyIndex], ...event.data.policy };
    } else {
      securityData.policies.push({ id: policyId, ...event.data.policy });
    }
    
    // Re-evaluate compliance
    const complianceResults = await evaluateSecurityCompliance();
    
    await eventClient.publish('security.compliance.evaluated', {
      requestId: event.requestId,
      correlationId: event.correlationId,
      results: complianceResults,
      timestamp: new Date().toISOString()
    });
    
    console.log('✅ Security policy updated and compliance re-evaluated');
  } catch (error) {
    console.error('❌ Failed to update security policy:', error);
  }
});

eventClient.on('security.threat.detected', async (event) => {
  console.log('🚨 Security threat detected:', event);
  
  try {
    const threat = {
      id: `threat_${Date.now()}`,
      type: event.data.threatType,
      severity: event.data.severity,
      source: event.data.source,
      description: event.data.description,
      indicators: event.data.indicators || [],
      status: 'active',
      detectedAt: new Date().toISOString()
    };
    
    securityData.threats.push(threat);
    
    // Trigger immediate security violation
    await eventClient.publish('security.violation.detected', {
      requestId: event.requestId,
      correlationId: event.correlationId,
      type: 'security_threat',
      threat: threat,
      severity: threat.severity,
      timestamp: new Date().toISOString()
    });
    
    console.log('✅ Security threat processed and alert triggered');
  } catch (error) {
    console.error('❌ Failed to process security threat:', error);
  }
});

eventClient.on('security.remediation.requested', async (event) => {
  console.log('🔧 Security remediation requested:', event);
  
  try {
    const remediationResults = await performSecurityRemediation(event.data);
    
    await eventClient.publish('security.remediation.completed', {
      requestId: event.requestId,
      correlationId: event.correlationId,
      results: remediationResults,
      timestamp: new Date().toISOString()
    });
    
    console.log('✅ Security remediation completed');
  } catch (error) {
    console.error('❌ Security remediation failed:', error);
    
    await eventClient.publish('security.remediation.failed', {
      requestId: event.requestId,
      correlationId: event.correlationId,
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

const PORT = process.env.PORT || 3115;

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

freePort(PORT);

// HTTP Endpoints
app.get('/', (req, res) => {
  res.json({
    service: 'Data Security Service',
    status: 'running',
    vulnerabilities: securityData.vulnerabilities.length,
    policies: securityData.policies.length,
    threats: securityData.threats.length,
    lastScan: securityData.scans[securityData.scans.length - 1]?.timestamp || null
  });
});

app.get('/api/security/vulnerabilities', (req, res) => {
  const { severity, limit = 50 } = req.query;
  
  let vulnerabilities = securityData.vulnerabilities;
  
  if (severity) {
    vulnerabilities = vulnerabilities.filter(v => v.severity === severity);
  }
  
  vulnerabilities = vulnerabilities.slice(0, parseInt(limit));
  
  res.json({
    vulnerabilities,
    total: vulnerabilities.length
  });
});

app.get('/api/security/policies', (req, res) => {
  res.json({
    policies: securityData.policies,
    total: securityData.policies.length
  });
});

app.get('/api/security/threats', (req, res) => {
  const { status = 'active', limit = 50 } = req.query;
  
  let threats = securityData.threats.filter(t => t.status === status);
  threats = threats.slice(0, parseInt(limit));
  
  res.json({
    threats,
    total: threats.length
  });
});

app.post('/api/security/scan', async (req, res) => {
  const requestId = `scan_${Date.now()}`;
  
  try {
    await eventClient.publish('security.scan.requested', {
      requestId,
      correlationId: req.headers['x-correlation-id'] || requestId,
      data: req.body,
      timestamp: new Date().toISOString()
    });
    
    res.json({
      requestId,
      message: 'Security scan initiated',
      status: 'processing'
    });
  } catch (error) {
    console.error('Error initiating security scan:', error);
    res.status(500).json({ error: 'Failed to initiate security scan' });
  }
});

app.post('/api/security/policy', async (req, res) => {
  const requestId = `policy_${Date.now()}`;
  
  try {
    await eventClient.publish('security.policy.updated', {
      requestId,
      correlationId: req.headers['x-correlation-id'] || requestId,
      data: req.body,
      timestamp: new Date().toISOString()
    });
    
    res.json({
      requestId,
      message: 'Security policy update initiated',
      status: 'processing'
    });
  } catch (error) {
    console.error('Error updating security policy:', error);
    res.status(500).json({ error: 'Failed to update security policy' });
  }
});

// Business logic functions
async function performSecurityScan(scanParams = {}) {
  console.log('🔍 Performing security scan...');
  
  // Simulate security scanning
  const vulnerabilities = [
    {
      id: 'vuln-001',
      type: 'encryption',
      severity: 'high',
      resource: 'database-prod-01',
      description: 'Database encryption at rest is disabled',
      cve: 'CVE-2024-0001',
      impact: 'Data exposure risk',
      remediation: 'Enable database encryption'
    },
    {
      id: 'vuln-002',
      type: 'access',
      severity: 'medium',
      resource: 's3-bucket-logs',
      description: 'Public read access enabled on sensitive bucket',
      impact: 'Potential data leak',
      remediation: 'Remove public access permissions'
    },
    {
      id: 'vuln-003',
      type: 'network',
      severity: 'critical',
      resource: 'security-group-web',
      description: 'SSH access open to 0.0.0.0/0',
      impact: 'Unauthorized access risk',
      remediation: 'Restrict SSH access to specific IPs'
    }
  ];
  
  // Calculate compliance score
  const totalChecks = 20;
  const passedChecks = totalChecks - vulnerabilities.length;
  const complianceScore = Math.round((passedChecks / totalChecks) * 100);
  
  // Simulate scan delay
  await new Promise(resolve => setTimeout(resolve, 3000));
  
  return {
    vulnerabilities,
    complianceScore,
    scanType: scanParams.scanType || 'full',
    duration: '3.2s'
  };
}

async function evaluateSecurityCompliance() {
  console.log('📊 Evaluating security compliance...');
  
  const results = {
    overall: 85,
    policies: securityData.policies.map(policy => ({
      id: policy.id,
      name: policy.name,
      compliance: Math.floor(Math.random() * 30) + 70, // 70-100%
      violations: Math.floor(Math.random() * 5)
    }))
  };
  
  return results;
}

async function performSecurityRemediation(remediationParams) {
  console.log('🔧 Performing security remediation...');
  
  const { vulnerabilityId, action } = remediationParams;
  
  // Simulate remediation
  await new Promise(resolve => setTimeout(resolve, 2000));
  
  // Remove vulnerability from list if remediation successful
  const vulnIndex = securityData.vulnerabilities.findIndex(v => v.id === vulnerabilityId);
  if (vulnIndex !== -1) {
    securityData.vulnerabilities.splice(vulnIndex, 1);
  }
  
  return {
    vulnerabilityId,
    action,
    status: 'completed',
    message: 'Vulnerability successfully remediated'
  };
}

// Event client lifecycle
async function startService() {
  try {
    await eventClient.connect();
    console.log('📡 Connected to event bus');
    
    app.listen(PORT, () => {
      console.log(`🔒 Data Security Service is running on port ${PORT}`);
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