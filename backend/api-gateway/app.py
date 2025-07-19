#!/usr/bin/env python3
"""
API Gateway - Central Router for LG-Protect Microservices
Handles authentication, routing, and service orchestration with event-driven capabilities
Enhanced with centralized logging system
"""

import os
import asyncio
import uvicorn
import httpx
from fastapi import FastAPI, HTTPException, Depends, Request, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime
import uuid
import sys
import time
from typing import Optional

# Add backend path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from events.event_bus import EventBus
from events.event_types import (
    InventoryEvent, ComplianceEvent, SecurityEvent, 
    EventCategory, EventPriority, EventSource
)
from shared.logging.logger import get_logger
from shared.logging.middleware import setup_fastapi_logging, log_auth_operation, log_security_event

# Initialize centralized logger
logger = get_logger("api-gateway", "main")

app = FastAPI(
    title="LG-Protect API Gateway",
    description="Central API Gateway for microservices orchestration with event-driven capabilities",
    version="2.0.0"
)

# Setup centralized logging middleware
setup_fastapi_logging(app, "api-gateway", "api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Event Bus
event_bus = EventBus()

# Service URLs from environment
INVENTORY_SERVICE_URL = os.getenv("INVENTORY_SERVICE_URL", "http://inventory-service:3000")
COMPLIANCE_SERVICE_URL = os.getenv("COMPLIANCE_SERVICE_URL", "http://compliance-service:3001")
DATA_SECURITY_SERVICE_URL = os.getenv("DATA_SECURITY_SERVICE_URL", "http://data-security-service:3002")
ALERT_ENGINE_URL = os.getenv("ALERT_ENGINE_URL", "http://alert-engine:3010")

@app.on_event("startup")
async def startup_event():
    """Initialize event bus connection on startup"""
    try:
        await event_bus.connect()
        logger.info("API Gateway startup completed", extra_data={
            "event_bus_status": "connected",
            "services": {
                "inventory": INVENTORY_SERVICE_URL,
                "compliance": COMPLIANCE_SERVICE_URL,
                "data_security": DATA_SECURITY_SERVICE_URL,
                "alert_engine": ALERT_ENGINE_URL
            }
        })
        
        # Log startup health check
        logger.log_health_check("starting", {
            "event_bus_connected": True,
            "services_configured": 4
        })
        
    except Exception as e:
        logger.error("Failed to connect to event bus during startup", exception=e)
        logger.log_health_check("startup_failed", {
            "event_bus_connected": False,
            "error": str(e)
        })

@app.on_event("shutdown")
async def shutdown_event():
    """Close event bus connection on shutdown"""
    try:
        await event_bus.disconnect()
        logger.info("API Gateway shutdown completed")
        logger.log_health_check("shutdown")
    except Exception as e:
        logger.error("Error during API Gateway shutdown", exception=e)

@app.get("/health")
async def health_check():
    """Health check for API Gateway and all services"""
    start_time = time.time()
    services_status = {}
    
    services = {
        "inventory-service": f"{INVENTORY_SERVICE_URL}/health",
        "compliance-service": f"{COMPLIANCE_SERVICE_URL}/health",
        "data-security-service": f"{DATA_SECURITY_SERVICE_URL}/health",
        "alert-engine": f"{ALERT_ENGINE_URL}/health"
    }
    
    async with httpx.AsyncClient(timeout=5.0) as client:
        for service_name, health_url in services.items():
            service_start_time = time.time()
            try:
                response = await client.get(health_url)
                response_time = (time.time() - service_start_time) * 1000
                
                services_status[service_name] = {
                    "status": "healthy" if response.status_code == 200 else "unhealthy",
                    "response_time": response_time
                }
                
                # Log individual service health
                logger.info(f"Health check for {service_name}", extra_data={
                    "service": service_name,
                    "status": services_status[service_name]["status"],
                    "response_time_ms": response_time
                })
                
            except Exception as e:
                services_status[service_name] = {
                    "status": "unreachable",
                    "error": str(e)
                }
                
                logger.warning(f"Service unreachable during health check: {service_name}", extra_data={
                    "service": service_name,
                    "error": str(e)
                })
    
    # Check event bus health
    event_bus_status = "healthy" if event_bus.redis_client else "disconnected"
    
    total_duration_ms = (time.time() - start_time) * 1000
    
    health_status = {
        "status": "healthy",
        "service": "api-gateway",
        "event_bus": event_bus_status,
        "services": services_status,
        "health_check_duration_ms": total_duration_ms
    }
    
    # Log comprehensive health check
    logger.log_health_check("healthy", {
        "event_bus_status": event_bus_status,
        "services_healthy": sum(1 for s in services_status.values() if s.get("status") == "healthy"),
        "total_services": len(services_status),
        "health_check_duration_ms": total_duration_ms
    })
    
    return health_status

@app.get("/")
async def root():
    """Root endpoint"""
    logger.info("API Gateway root endpoint accessed")
    return {
        "message": "LG-Protect API Gateway",
        "version": "2.0.0",
        "architecture": "event-driven microservices",
        "services": {
            "inventory": f"{INVENTORY_SERVICE_URL}/api/v1",
            "compliance": f"{COMPLIANCE_SERVICE_URL}/api/v1",
            "data-security": f"{DATA_SECURITY_SERVICE_URL}/api/v1",
            "alerts": f"{ALERT_ENGINE_URL}/api/v1"
        }
    }

# Event-driven endpoints (async operations)
@app.post("/api/v1/inventory/trigger-scan")
async def trigger_inventory_scan_async(background_tasks: BackgroundTasks):
    """Trigger inventory scan via event system (async)"""
    try:
        request_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        
        logger.info("Triggering inventory scan via event system", extra_data={
            "request_id": request_id,
            "event_id": event_id,
            "scan_type": "full"
        })
        
        # Create inventory scan event
        event = InventoryEvent(
            event_id=event_id,
            event_type="INVENTORY_SCAN_REQUESTED",
            source=EventSource.API_GATEWAY,
            category=EventCategory.INVENTORY,
            priority=EventPriority.MEDIUM,
            timestamp=datetime.utcnow(),
            data={
                "scan_type": "full",
                "requested_by": "api_gateway",
                "request_id": request_id
            }
        )
        
        # Publish event asynchronously
        background_tasks.add_task(event_bus.publish, "inventory.scan.requested", event)
        
        # Log event processing
        logger.log_event_processing(
            event_type="INVENTORY_SCAN_REQUESTED",
            event_id=event_id,
            status="queued",
            details={
                "request_id": request_id,
                "scan_type": "full"
            }
        )
        
        # Log audit event
        logger.log_audit_event(
            action="trigger_inventory_scan",
            user_id="system",  # In real implementation, get from auth
            resource="inventory_scanner",
            result="queued",
            details={
                "request_id": request_id,
                "event_id": event_id
            }
        )
        
        return {
            "status": "scan_requested",
            "message": "Inventory scan has been queued for processing",
            "request_id": request_id,
            "event_id": event_id
        }
    except Exception as e:
        logger.error("Failed to trigger inventory scan", exception=e, extra_data={
            "request_id": request_id if 'request_id' in locals() else "unknown"
        })
        raise HTTPException(status_code=500, detail="Failed to trigger inventory scan")

@log_security_event("compliance_check_requested", "medium")
@app.post("/api/v1/compliance/check")
async def trigger_compliance_check_async(background_tasks: BackgroundTasks):
    """Trigger compliance check via event system (async)"""
    try:
        request_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        
        logger.info("Triggering compliance check via event system", extra_data={
            "request_id": request_id,
            "event_id": event_id,
            "check_type": "full_compliance_audit"
        })
        
        # Create compliance check event
        event = ComplianceEvent(
            event_id=event_id,
            event_type="COMPLIANCE_CHECK_REQUESTED",
            source=EventSource.API_GATEWAY,
            category=EventCategory.COMPLIANCE,
            priority=EventPriority.HIGH,
            timestamp=datetime.utcnow(),
            data={
                "check_type": "full_compliance_audit",
                "requested_by": "api_gateway",
                "request_id": request_id
            }
        )
        
        # Publish event asynchronously
        background_tasks.add_task(event_bus.publish, "compliance.check.requested", event)
        
        # Log compliance event
        logger.log_compliance_event(
            compliance_framework="GENERAL",
            rule_id="COMPLIANCE_CHECK_TRIGGER",
            resource_id="all_resources",
            status="initiated",
            details={
                "request_id": request_id,
                "check_type": "full_compliance_audit"
            }
        )
        
        # Log event processing
        logger.log_event_processing(
            event_type="COMPLIANCE_CHECK_REQUESTED",
            event_id=event_id,
            status="queued",
            details={
                "request_id": request_id,
                "check_type": "full_compliance_audit"
            }
        )
        
        return {
            "status": "check_requested",
            "message": "Compliance check has been queued for processing",
            "request_id": request_id,
            "event_id": event_id
        }
    except Exception as e:
        logger.error("Failed to trigger compliance check", exception=e, extra_data={
            "request_id": request_id if 'request_id' in locals() else "unknown"
        })
        raise HTTPException(status_code=500, detail="Failed to trigger compliance check")

@log_security_event("security_scan_requested", "high")
@app.post("/api/v1/security/scan")
async def trigger_security_scan_async(background_tasks: BackgroundTasks):
    """Trigger security scan via event system (async)"""
    try:
        request_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        
        logger.info("Triggering security scan via event system", extra_data={
            "request_id": request_id,
            "event_id": event_id,
            "scan_type": "data_security_audit"
        })
        
        # Create security scan event
        event = SecurityEvent(
            event_id=event_id,
            event_type="SECURITY_SCAN_REQUESTED",
            source=EventSource.API_GATEWAY,
            category=EventCategory.SECURITY,
            priority=EventPriority.HIGH,
            timestamp=datetime.utcnow(),
            data={
                "scan_type": "data_security_audit",
                "requested_by": "api_gateway",
                "request_id": request_id
            }
        )
        
        # Publish event asynchronously
        background_tasks.add_task(event_bus.publish, "security.scan.requested", event)
        
        # Log security event
        logger.log_security_event(
            event_type="security_scan_initiated",
            severity="high",
            details={
                "request_id": request_id,
                "scan_type": "data_security_audit",
                "event_id": event_id
            }
        )
        
        # Log event processing
        logger.log_event_processing(
            event_type="SECURITY_SCAN_REQUESTED",
            event_id=event_id,
            status="queued",
            details={
                "request_id": request_id,
                "scan_type": "data_security_audit"
            }
        )
        
        return {
            "status": "scan_requested",
            "message": "Security scan has been queued for processing",
            "request_id": request_id,
            "event_id": event_id
        }
    except Exception as e:
        logger.error("Failed to trigger security scan", exception=e, extra_data={
            "request_id": request_id if 'request_id' in locals() else "unknown"
        })
        raise HTTPException(status_code=500, detail="Failed to trigger security scan")

# Direct HTTP endpoints (synchronous operations for immediate data)
@app.get("/api/v1/inventory/service-mapping")
async def get_service_mapping():
    """Get current service mapping (direct HTTP call for immediate data)"""
    start_time = time.time()
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{INVENTORY_SERVICE_URL}/api/v1/service-mapping")
            duration_ms = (time.time() - start_time) * 1000
            
            logger.info("Service mapping retrieved successfully", extra_data={
                "target_service": "inventory-service",
                "response_time_ms": duration_ms,
                "status_code": response.status_code
            })
            
            # Log performance
            logger.log_performance(
                operation="get_service_mapping_proxy",
                duration_ms=duration_ms,
                extra_data={
                    "target_service": "inventory-service",
                    "status_code": response.status_code
                }
            )
            
            return response.json()
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Failed to retrieve service mapping", exception=e, extra_data={
                "target_service": "inventory-service",
                "duration_ms": duration_ms
            })
            raise HTTPException(status_code=503, detail=f"Inventory service unavailable: {str(e)}")

@app.get("/api/v1/compliance/violations")
async def get_compliance_violations():
    """Get current compliance violations (direct HTTP call for immediate data)"""
    start_time = time.time()
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{COMPLIANCE_SERVICE_URL}/api/v1/violations")
            duration_ms = (time.time() - start_time) * 1000
            
            logger.info("Compliance violations retrieved successfully", extra_data={
                "target_service": "compliance-service",
                "response_time_ms": duration_ms,
                "status_code": response.status_code
            })
            
            # Log performance
            logger.log_performance(
                operation="get_compliance_violations_proxy",
                duration_ms=duration_ms,
                extra_data={
                    "target_service": "compliance-service",
                    "status_code": response.status_code
                }
            )
            
            return response.json()
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Failed to retrieve compliance violations", exception=e, extra_data={
                "target_service": "compliance-service",
                "duration_ms": duration_ms
            })
            raise HTTPException(status_code=503, detail=f"Compliance service unavailable: {str(e)}")

@app.get("/api/v1/security/threats")
async def get_security_threats():
    """Get current security threats (direct HTTP call for immediate data)"""
    start_time = time.time()
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{DATA_SECURITY_SERVICE_URL}/api/v1/threats")
            duration_ms = (time.time() - start_time) * 1000
            
            logger.info("Security threats retrieved successfully", extra_data={
                "target_service": "data-security-service",
                "response_time_ms": duration_ms,
                "status_code": response.status_code
            })
            
            # Log performance and security event
            logger.log_performance(
                operation="get_security_threats_proxy",
                duration_ms=duration_ms,
                extra_data={
                    "target_service": "data-security-service",
                    "status_code": response.status_code
                }
            )
            
            logger.log_security_event(
                event_type="security_threats_accessed",
                severity="medium",
                details={
                    "target_service": "data-security-service",
                    "access_method": "api_gateway_proxy"
                }
            )
            
            return response.json()
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Failed to retrieve security threats", exception=e, extra_data={
                "target_service": "data-security-service",
                "duration_ms": duration_ms
            })
            raise HTTPException(status_code=503, detail=f"Data security service unavailable: {str(e)}")

# Event status tracking endpoints
@app.get("/api/v1/events/status/{request_id}")
async def get_event_status(request_id: str):
    """Get status of an event-driven operation by request ID"""
    try:
        logger.info("Event status requested", extra_data={"request_id": request_id})
        
        # In a production system, this would query a database or cache
        # For now, return a placeholder response
        return {
            "request_id": request_id,
            "status": "processing",
            "message": "Event is being processed by the appropriate service"
        }
    except Exception as e:
        logger.error("Failed to get event status", exception=e, extra_data={"request_id": request_id})
        raise HTTPException(status_code=500, detail="Failed to get event status")

# System orchestration endpoints
@app.post("/api/v1/system/full-scan")
async def trigger_full_system_scan(background_tasks: BackgroundTasks):
    """Trigger a full system scan across all services via events"""
    try:
        request_id = str(uuid.uuid4())
        timestamp = datetime.utcnow()
        
        logger.info("Triggering full system scan across all services", extra_data={
            "request_id": request_id,
            "services": ["inventory", "compliance", "security"]
        })
        
        # Create events for all services
        events = [
            InventoryEvent(
                event_id=str(uuid.uuid4()),
                event_type="INVENTORY_SCAN_REQUESTED",
                source=EventSource.API_GATEWAY,
                category=EventCategory.INVENTORY,
                priority=EventPriority.MEDIUM,
                timestamp=timestamp,
                data={
                    "scan_type": "full",
                    "requested_by": "system_orchestration",
                    "parent_request_id": request_id
                }
            ),
            ComplianceEvent(
                event_id=str(uuid.uuid4()),
                event_type="COMPLIANCE_CHECK_REQUESTED",
                source=EventSource.API_GATEWAY,
                category=EventCategory.COMPLIANCE,
                priority=EventPriority.HIGH,
                timestamp=timestamp,
                data={
                    "check_type": "full_compliance_audit",
                    "requested_by": "system_orchestration",
                    "parent_request_id": request_id
                }
            ),
            SecurityEvent(
                event_id=str(uuid.uuid4()),
                event_type="SECURITY_SCAN_REQUESTED",
                source=EventSource.API_GATEWAY,
                category=EventCategory.SECURITY,
                priority=EventPriority.HIGH,
                timestamp=timestamp,
                data={
                    "scan_type": "data_security_audit",
                    "requested_by": "system_orchestration",
                    "parent_request_id": request_id
                }
            )
        ]
        
        # Publish all events
        for event in events:
            if isinstance(event, InventoryEvent):
                background_tasks.add_task(event_bus.publish, "inventory.scan.requested", event)
            elif isinstance(event, ComplianceEvent):
                background_tasks.add_task(event_bus.publish, "compliance.check.requested", event)
            elif isinstance(event, SecurityEvent):
                background_tasks.add_task(event_bus.publish, "security.scan.requested", event)
        
        # Log comprehensive audit event
        logger.log_audit_event(
            action="trigger_full_system_scan",
            user_id="system",  # In real implementation, get from auth
            resource="all_services",
            result="initiated",
            details={
                "request_id": request_id,
                "events_triggered": len(events),
                "services": ["inventory", "compliance", "security"]
            }
        )
        
        # Log each event processing
        for event in events:
            logger.log_event_processing(
                event_type=event.event_type,
                event_id=event.event_id,
                status="queued",
                details={
                    "parent_request_id": request_id,
                    "service_type": event.category.value
                }
            )
        
        logger.info("Full system scan events published successfully", extra_data={
            "request_id": request_id,
            "events_triggered": len(events)
        })
        
        return {
            "status": "full_scan_requested",
            "message": "Full system scan across all services has been initiated",
            "request_id": request_id,
            "events_triggered": len(events),
            "services": ["inventory", "compliance", "security"]
        }
    except Exception as e:
        logger.error("Failed to trigger full system scan", exception=e, extra_data={
            "request_id": request_id if 'request_id' in locals() else "unknown"
        })
        raise HTTPException(status_code=500, detail="Failed to trigger full system scan")

# Add inventory API routing endpoints
@app.get("/api/v1/inventory/assets")
async def get_inventory_assets(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    service: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None)
):
    """Get inventory assets - routed to inventory service"""
    try:
        params = {
            "limit": limit,
            "offset": offset
        }
        if service:
            params["service"] = service
        if region:
            params["region"] = region
        if risk_level:
            params["risk_level"] = risk_level
            
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{INVENTORY_SERVICE_URL}/api/inventory", params=params)
            response.raise_for_status()
            return response.json()
            
    except Exception as e:
        logger.error("Error routing inventory assets request", exception=e)
        raise HTTPException(status_code=500, detail=f"Error retrieving inventory assets: {str(e)}")

@app.post("/api/v1/inventory/search")
async def search_inventory(search_request: dict):
    """Search inventory assets - routed to inventory service"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{INVENTORY_SERVICE_URL}/api/inventory/search",
                json=search_request
            )
            response.raise_for_status()
            return response.json()
            
    except Exception as e:
        logger.error("Error routing inventory search request", exception=e)
        raise HTTPException(status_code=500, detail=f"Error searching inventory: {str(e)}")

@app.get("/api/v1/inventory/summary")
async def get_inventory_summary():
    """Get inventory summary - routed to inventory service"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{INVENTORY_SERVICE_URL}/api/inventory/summary")
            response.raise_for_status()
            return response.json()
            
    except Exception as e:
        logger.error("Error routing inventory summary request", exception=e)
        raise HTTPException(status_code=500, detail=f"Error retrieving inventory summary: {str(e)}")

@app.get("/api/v1/inventory/{asset_id}")
async def get_asset_detail(asset_id: str):
    """Get asset detail - routed to inventory service"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{INVENTORY_SERVICE_URL}/api/inventory/{asset_id}")
            response.raise_for_status()
            return response.json()
            
    except Exception as e:
        logger.error("Error routing asset detail request", exception=e)
        raise HTTPException(status_code=500, detail=f"Error retrieving asset detail: {str(e)}")

@app.get("/api/v1/inventory/{asset_id}/relationships")
async def get_asset_relationships(asset_id: str):
    """Get asset relationships - routed to inventory service"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{INVENTORY_SERVICE_URL}/api/inventory/{asset_id}/relationships")
            response.raise_for_status()
            return response.json()
            
    except Exception as e:
        logger.error("Error routing asset relationships request", exception=e)
        raise HTTPException(status_code=500, detail=f"Error retrieving asset relationships: {str(e)}")

@app.post("/api/v1/inventory/export")
async def export_inventory(export_request: dict):
    """Export inventory data - routed to inventory service"""
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{INVENTORY_SERVICE_URL}/api/inventory/export",
                json=export_request
            )
            response.raise_for_status()
            return response.json()
            
    except Exception as e:
        logger.error("Error routing inventory export request", exception=e)
        raise HTTPException(status_code=500, detail=f"Error exporting inventory: {str(e)}")

@app.patch("/api/v1/inventory/{asset_id}/review")
async def review_asset(asset_id: str, review_request: dict):
    """Review asset - routed to inventory service"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.patch(
                f"{INVENTORY_SERVICE_URL}/api/inventory/{asset_id}/review",
                json=review_request
            )
            response.raise_for_status()
            return response.json()
            
    except Exception as e:
        logger.error("Error routing asset review request", exception=e)
        raise HTTPException(status_code=500, detail=f"Error reviewing asset: {str(e)}")

@app.get("/api/v1/inventory/tags")
async def get_inventory_tags():
    """Get inventory tags - routed to inventory service"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{INVENTORY_SERVICE_URL}/api/inventory/tags")
            response.raise_for_status()
            return response.json()
            
    except Exception as e:
        logger.error("Error routing inventory tags request", exception=e)
        raise HTTPException(status_code=500, detail=f"Error retrieving inventory tags: {str(e)}")

if __name__ == "__main__":
    logger.info("Starting API Gateway main process", extra_data={
        "host": "0.0.0.0",
        "port": 8000
    })
    uvicorn.run(app, host="0.0.0.0", port=8000)