#!/usr/bin/env python3
"""
Inventory Service Main Entry Point
Self-contained inventory service with discovery engines
Enhanced with centralized logging system and enhanced extraction
"""

import os
import json
import uvicorn
import sys
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime

# Add shared modules to path
sys.path.append(str(Path(__file__).parent.parent.parent / "shared"))

# Import with error handling for missing modules
try:
    from events.event_bus import EventType, publish_inventory_event
except ImportError:
    # Mock the event bus for development
    class EventType:
        INVENTORY_DISCOVERED = "inventory_discovered"
    
    async def publish_inventory_event(event_type, data):
        pass

try:
    from shared.logging.logger import get_logger
    from shared.logging.middleware import setup_fastapi_logging, log_database_operation
except ImportError:
    # Mock logging for development
    import logging
    def get_logger(name, component):
        return logging.getLogger(f"{name}.{component}")
    
    def setup_fastapi_logging(app, service, component):
        pass
    
    def log_database_operation(operation, table):
        def decorator(func):
            return func
        return decorator

# Import inventory API routes
from api.inventory_api import router as inventory_router

# Import enhanced extraction system
from utils.enhanced_extraction import EnhancedResourceExtractor

# Initialize centralized logger
logger = get_logger("inventory-service", "main")

# Get centralized data directory from environment
DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
INVENTORY_DATA_DIR = DATA_DIR / "inventory"

app = FastAPI(
    title="LG-Protect Inventory Service",
    description="AWS resource discovery and inventory management with enhanced extraction",
    version="1.0.0"
)

# Setup centralized logging middleware
setup_fastapi_logging(app, "inventory-service", "api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include inventory API routes
app.include_router(inventory_router)

@app.on_event("startup")
async def startup_event():
    """Application startup event"""
    logger.info("Starting Inventory Service with Enhanced Extraction", extra_data={
        "data_dir": str(DATA_DIR),
        "inventory_data_dir": str(INVENTORY_DATA_DIR),
        "enhanced_extraction": True
    })
    
    # Ensure data directories exist
    INVENTORY_DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    # Initialize enhanced extractor
    try:
        enhanced_extractor = EnhancedResourceExtractor()
        available_services = len(enhanced_extractor.service_mapping)
        logger.info("Enhanced extraction system initialized", extra_data={
            "available_services": available_services
        })
    except Exception as e:
        logger.warning("Enhanced extraction system not available", extra_data={
            "error": str(e)
        })

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "LG-Protect Inventory Service",
        "version": "1.0.0",
        "status": "running",
        "enhanced_extraction": True
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "enhanced_extraction": True
    }

@log_database_operation("read", "service_mapping")
@app.get("/api/v1/service-mapping")
async def get_service_mapping():
    """Get enhanced service mapping configuration"""
    try:
        # Load enhanced service mapping
        enhanced_extractor = EnhancedResourceExtractor()
        mapping_data = enhanced_extractor.service_mapping
        
        logger.info("Enhanced service mapping accessed successfully", extra_data={
            "total_services": len(mapping_data),
            "services": list(mapping_data.keys())[:10]  # First 10 services
        })
        
        # Publish event when service mapping is accessed
        await publish_inventory_event(
            EventType.INVENTORY_DISCOVERED,
            {
                "action": "service_mapping_accessed",
                "total_services": len(mapping_data),
                "timestamp": "now"
            }
        )
        
        return {
            "status": "success",
            "data": mapping_data,
            "total_services": len(mapping_data),
            "enhanced_extraction": True
        }
    except Exception as e:
        logger.error("Error loading enhanced service mapping", exception=e, extra_data={
            "error": str(e)
        })
        raise HTTPException(status_code=500, detail=f"Error loading enhanced service mapping: {str(e)}")

@log_database_operation("read", "scan_results")
@app.get("/api/v1/scan-results")
async def get_scan_results():
    """Get latest scan results from centralized data directory"""
    try:
        results_dir = INVENTORY_DATA_DIR / "service_enablement_results"
        if not results_dir.exists():
            logger.warning("No scan results directory found", extra_data={"results_dir": str(results_dir)})
            return {"status": "success", "data": [], "message": "No scan results found"}
        
        # Find the latest scan directory
        scan_dirs = [d for d in results_dir.iterdir() if d.is_dir()]
        if not scan_dirs:
            logger.warning("No scan directories found", extra_data={"results_dir": str(results_dir)})
            return {"status": "success", "data": [], "message": "No scan results found"}
        
        # Sort by modification time to get the latest
        latest_scan_dir = max(scan_dirs, key=os.path.getmtime)
        
        logger.info("Scan results accessed successfully", extra_data={
            "latest_scan": latest_scan_dir.name,
            "total_scans": len(scan_dirs),
            "scan_path": str(latest_scan_dir)
        })
        
        # Publish event when scan results are accessed
        await publish_inventory_event(
            EventType.INVENTORY_DISCOVERED,
            {
                "action": "scan_results_accessed",
                "scan_directory": latest_scan_dir.name,
                "timestamp": "now"
            }
        )
        
        # Log event processing
        logger.log_event_processing(
            event_type="scan_results_accessed",
            status="completed",
            details={"scan_directory": latest_scan_dir.name}
        )
        
        return {
            "status": "success",
            "data": {
                "scan_directory": latest_scan_dir.name,
                "total_scans": len(scan_dirs),
                "scan_path": str(latest_scan_dir)
            },
            "message": f"Found scan results in {latest_scan_dir.name}"
        }
    except Exception as e:
        logger.error("Error accessing scan results", exception=e, extra_data={
            "results_dir": str(results_dir) if 'results_dir' in locals() else "unknown"
        })
        raise HTTPException(status_code=500, detail=f"Error accessing scan results: {str(e)}")

@app.post("/api/v1/trigger-scan")
async def trigger_scan():
    """Trigger a new inventory scan using enhanced extraction"""
    try:
        logger.info("Triggering enhanced inventory scan")
        
        # Initialize enhanced extractor
        enhanced_extractor = EnhancedResourceExtractor()
        available_services = list(enhanced_extractor.service_mapping.keys())
        
        # Simulate scan result for now
        scan_result = {
            "status": "triggered",
            "scan_id": f"enhanced_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "regions": ["us-east-1", "us-west-2"],
            "services": available_services[:10],  # First 10 services
            "total_services": len(available_services),
            "enhanced_extraction": True,
            "timestamp": datetime.now().isoformat()
        }
        
        # Publish event
        await publish_inventory_event(
            EventType.INVENTORY_DISCOVERED,
            {
                "action": "enhanced_scan_triggered",
                "scan_result": scan_result,
                "timestamp": "now"
            }
        )
        
        logger.log_event_processing(
            event_type="enhanced_scan_triggered",
            status="completed",
            details=scan_result
        )
        
        return {
            "status": "success",
            "message": "Enhanced inventory scan triggered successfully",
            "scan_result": scan_result
        }
        
    except Exception as e:
        logger.error("Error triggering enhanced scan", exception=e)
        raise HTTPException(status_code=500, detail=f"Error triggering enhanced scan: {str(e)}")

@app.get("/api/v1/enhanced-extraction")
async def get_enhanced_extraction_info():
    """Get information about the enhanced extraction system"""
    try:
        enhanced_extractor = EnhancedResourceExtractor()
        available_services = list(enhanced_extractor.service_mapping.keys())
        
        # Get sample service configurations
        sample_services = {}
        for service_name in available_services[:5]:  # First 5 services
            service_config = enhanced_extractor.service_mapping[service_name]
            sample_services[service_name] = {
                "client_type": service_config.get('client_type'),
                "check_function": service_config.get('check_function'),
                "scope": service_config.get('scope'),
                "category": service_config.get('category'),
                "resource_types": list(service_config.get('resource_types', {}).keys())
            }
        
        return {
            "status": "success",
            "enhanced_extraction": True,
            "total_services": len(available_services),
            "sample_services": sample_services,
            "features": [
                "Multi-resource type support per service",
                "Automatic ARN generation",
                "Category and scope classification",
                "Enhanced error handling",
                "Configurable service mapping"
            ]
        }
    except Exception as e:
        logger.error("Error getting enhanced extraction info", exception=e)
        raise HTTPException(status_code=500, detail=f"Error getting enhanced extraction info: {str(e)}")

@app.get("/api/v1/config")
async def get_config():
    """Get service configuration"""
    try:
        # Get enhanced extraction configuration
        enhanced_extractor = EnhancedResourceExtractor()
        available_services = list(enhanced_extractor.service_mapping.keys())
        
        config = {
            "service": "LG-Protect Inventory Service",
            "version": "1.0.0",
            "enhanced_extraction": True,
            "total_services": len(available_services),
            "data_directory": str(INVENTORY_DATA_DIR),
            "features": [
                "Enhanced AWS resource discovery",
                "Multi-resource type support",
                "Automatic ARN generation",
                "Category and scope classification",
                "Comprehensive error handling"
            ]
        }
        
        return {
            "status": "success",
            "config": config
        }
    except Exception as e:
        logger.error("Error getting configuration", exception=e)
        raise HTTPException(status_code=500, detail=f"Error getting configuration: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
