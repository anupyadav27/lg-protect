#!/usr/bin/env python3
"""
Data Security Service - Redis Event-Driven Implementation
Handles sensitive data detection and security threats
"""

import os
import asyncio
import uvicorn
import sys
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Add shared modules to path
sys.path.append(str(Path(__file__).parent.parent.parent / "shared"))

from event_bus import EventType, publish_security_event
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="LG-Protect Data Security Service",
    description="Sensitive data detection and security threat management",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Sample security threats
security_threats = []

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "data-security-service",
        "threats": len(security_threats)
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "LG-Protect Data Security Service", "version": "1.0.0"}

@app.get("/api/v1/threats")
async def get_threats():
    """Get all security threats"""
    return {
        "status": "success",
        "threats": security_threats,
        "total": len(security_threats)
    }

@app.post("/api/v1/scan-data")
async def scan_data():
    """Trigger data security scan"""
    try:
        logger.info("🔒 Running data security scan...")
        
        # Simulate security threat detection
        threat = {
            "threat_type": "SENSITIVE_DATA_EXPOSURE",
            "resource": "arn:aws:s3:::my-bucket/sensitive-data.csv",
            "severity": "critical",
            "description": "PII data found in unencrypted S3 bucket",
            "data_types": ["SSN", "Credit Card", "Email"],
            "remediation": "Enable S3 bucket encryption and restrict access"
        }
        
        security_threats.append(threat)
        
        # Publish security threat event
        await publish_security_event(
            EventType.SECURITY_THREAT,
            threat
        )
        
        logger.info("✅ Security threat detected and event published")
        
        return {
            "status": "success",
            "message": "Data security scan completed",
            "threats_found": 1,
            "threat": threat
        }
        
    except Exception as e:
        logger.error(f"❌ Error during data security scan: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error during data security scan: {str(e)}")

@app.get("/api/v1/scan-status")
async def get_scan_status():
    """Get current scan status"""
    return {
        "status": "success",
        "scan_status": "ready",
        "last_scan": "never",
        "threats_detected": len(security_threats)
    }

if __name__ == "__main__":
    port = int(os.getenv("SERVICE_PORT", 3002))
    uvicorn.run(app, host="0.0.0.0", port=port)
