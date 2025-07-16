#!/usr/bin/env python3
"""
Compliance Service - Redis Event-Driven Implementation
Handles compliance checks and policy violations
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

from event_bus import EventType, publish_compliance_event
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="LG-Protect Compliance Service",
    description="Compliance checks and policy violation detection",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Sample compliance violations
compliance_violations = []

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "compliance-service",
        "violations": len(compliance_violations)
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "LG-Protect Compliance Service", "version": "1.0.0"}

@app.get("/api/v1/violations")
async def get_violations():
    """Get all compliance violations"""
    return {
        "status": "success",
        "violations": compliance_violations,
        "total": len(compliance_violations)
    }

@app.post("/api/v1/check-compliance")
async def check_compliance():
    """Trigger compliance check"""
    try:
        logger.info("🔍 Running compliance check...")
        
        # Simulate compliance violation detection
        violation = {
            "violation_type": "CIS_1_1_MFA_NOT_ENABLED",
            "resource": "arn:aws:iam::123456789012:user/test-user",
            "severity": "high",
            "description": "MFA not enabled for IAM user",
            "remediation": "Enable MFA for the IAM user"
        }
        
        compliance_violations.append(violation)
        
        # Publish compliance violation event
        await publish_compliance_event(
            EventType.COMPLIANCE_VIOLATION,
            violation
        )
        
        logger.info("✅ Compliance violation detected and event published")
        
        return {
            "status": "success",
            "message": "Compliance check completed",
            "violations_found": 1,
            "violation": violation
        }
        
    except Exception as e:
        logger.error(f"❌ Error during compliance check: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error during compliance check: {str(e)}")

if __name__ == "__main__":
    port = int(os.getenv("SERVICE_PORT", 3001))
    uvicorn.run(app, host="0.0.0.0", port=port)
