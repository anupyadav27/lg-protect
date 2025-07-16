#!/usr/bin/env python3
"""
Alert Engine Service - Redis Event-Driven Implementation
Handles real-time event processing and alert management
"""

import os
import asyncio
import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import sys
from pathlib import Path

# Add shared modules to path
sys.path.append(str(Path(__file__).parent.parent.parent / "shared"))

from event_bus import RedisEventBus, EventType, event_bus
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="LG-Protect Alert Engine",
    description="Real-time event processing and alert management",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Alert storage (in production, use database)
alerts = []
active_subscriptions = set()

@app.on_event("startup")
async def startup_event():
    """Initialize Redis event bus and start listening"""
    logger.info("🚀 Starting Alert Engine...")
    
    # Connect to Redis
    redis_url = os.getenv("REDIS_URL", "redis://redis:6379")
    event_bus.redis_url = redis_url
    
    if await event_bus.connect():
        # Subscribe to all event types
        await event_bus.subscribe(EventType.INVENTORY_DISCOVERED, handle_inventory_event)
        await event_bus.subscribe(EventType.INVENTORY_CHANGED, handle_inventory_event)
        await event_bus.subscribe(EventType.COMPLIANCE_VIOLATION, handle_compliance_event)
        await event_bus.subscribe(EventType.SECURITY_THREAT, handle_security_event)
        
        # Start background event listener
        asyncio.create_task(event_bus.listen_for_events())
        logger.info("✅ Alert Engine initialized and listening for events")
    else:
        logger.error("❌ Failed to initialize Redis event bus")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup Redis connections"""
    await event_bus.disconnect()
    logger.info("🛑 Alert Engine shutdown complete")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "alert-engine",
        "redis_connected": event_bus.redis_client is not None,
        "active_alerts": len(alerts),
        "subscriptions": len(active_subscriptions)
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "LG-Protect Alert Engine", "version": "1.0.0"}

@app.get("/api/v1/alerts")
async def get_alerts():
    """Get all alerts"""
    return {
        "status": "success",
        "alerts": alerts,
        "total": len(alerts)
    }

@app.get("/api/v1/alerts/active")
async def get_active_alerts():
    """Get only active alerts"""
    active_alerts = [alert for alert in alerts if alert.get("status") == "active"]
    return {
        "status": "success",
        "alerts": active_alerts,
        "total": len(active_alerts)
    }

@app.post("/api/v1/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str):
    """Resolve an alert"""
    for alert in alerts:
        if alert.get("alert_id") == alert_id:
            alert["status"] = "resolved"
            alert["resolved_at"] = datetime.utcnow().isoformat()
            
            # Publish resolution event
            await event_bus.publish_event(
                EventType.ALERT_RESOLVED,
                {"alert_id": alert_id, "alert": alert},
                "alert-engine"
            )
            
            return {"status": "success", "message": f"Alert {alert_id} resolved"}
    
    raise HTTPException(status_code=404, detail="Alert not found")

# Event Handlers
async def handle_inventory_event(event_data):
    """Handle inventory-related events"""
    try:
        logger.info(f"📦 Processing inventory event: {event_data['event_type']}")
        
        # Create alert for significant inventory changes
        if event_data['event_type'] == 'inventory.discovered':
            alert = create_alert(
                alert_type="inventory_discovery",
                severity="info",
                title="New Resources Discovered",
                description=f"New AWS resources discovered in {event_data.get('data', {}).get('region', 'unknown region')}",
                source_event=event_data
            )
            alerts.append(alert)
            
        elif event_data['event_type'] == 'inventory.changed':
            alert = create_alert(
                alert_type="inventory_change",
                severity="warning",
                title="Resource Configuration Changed",
                description="AWS resource configuration has been modified",
                source_event=event_data
            )
            alerts.append(alert)
            
        logger.info(f"✅ Created alert for inventory event")
        
    except Exception as e:
        logger.error(f"❌ Error handling inventory event: {str(e)}")

async def handle_compliance_event(event_data):
    """Handle compliance-related events"""
    try:
        logger.info(f"⚖️ Processing compliance event: {event_data['event_type']}")
        
        alert = create_alert(
            alert_type="compliance_violation",
            severity="high",
            title="Compliance Violation Detected",
            description=f"Compliance violation: {event_data.get('data', {}).get('violation_type', 'Unknown')}",
            source_event=event_data
        )
        alerts.append(alert)
        
        logger.info(f"✅ Created alert for compliance violation")
        
    except Exception as e:
        logger.error(f"❌ Error handling compliance event: {str(e)}")

async def handle_security_event(event_data):
    """Handle security-related events"""
    try:
        logger.info(f"🔒 Processing security event: {event_data['event_type']}")
        
        alert = create_alert(
            alert_type="security_threat",
            severity="critical",
            title="Security Threat Detected",
            description=f"Security threat: {event_data.get('data', {}).get('threat_type', 'Unknown')}",
            source_event=event_data
        )
        alerts.append(alert)
        
        # Publish alert trigger event
        await event_bus.publish_event(
            EventType.ALERT_TRIGGERED,
            {"alert": alert, "severity": "critical"},
            "alert-engine"
        )
        
        logger.info(f"✅ Created critical alert for security threat")
        
    except Exception as e:
        logger.error(f"❌ Error handling security event: {str(e)}")

def create_alert(alert_type: str, severity: str, title: str, description: str, source_event: dict):
    """Create a new alert"""
    from datetime import datetime
    
    alert_id = f"alert_{int(datetime.utcnow().timestamp())}"
    
    return {
        "alert_id": alert_id,
        "type": alert_type,
        "severity": severity,
        "title": title,
        "description": description,
        "status": "active",
        "created_at": datetime.utcnow().isoformat(),
        "source_service": source_event.get("source_service"),
        "source_event_id": source_event.get("event_id"),
        "event_data": source_event.get("data", {})
    }

if __name__ == "__main__":
    port = int(os.getenv("SERVICE_PORT", 3010))
    uvicorn.run(app, host="0.0.0.0", port=port)