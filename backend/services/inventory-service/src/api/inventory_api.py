#!/usr/bin/env python3
"""
Inventory API Endpoints for LG-Protect
Comprehensive inventory management with search, filtering, and export capabilities
"""

import json
import csv
import io
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
from fastapi import APIRouter, HTTPException, Query, Depends, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
import structlog

from models.asset_models import Asset, AssetFilter, AssetInfo, RiskLevel, AssetType
from models.relationship_models import AssetRelationship
from utils.service_enablement_integration import get_service_enablement_integration

logger = structlog.get_logger(__name__)

# Initialize router
router = APIRouter(prefix="/api/inventory", tags=["inventory"])

# Pydantic models for API requests/responses
class SearchRequest(BaseModel):
    """Search and filter request model"""
    services: Optional[List[str]] = Field(default=None, description="Filter by AWS services")
    regions: Optional[List[str]] = Field(default=None, description="Filter by AWS regions")
    resource_types: Optional[List[str]] = Field(default=None, description="Filter by resource types")
    risk_levels: Optional[List[str]] = Field(default=None, description="Filter by risk levels")
    compliance_frameworks: Optional[List[str]] = Field(default=None, description="Filter by compliance frameworks")
    tags: Optional[Dict[str, str]] = Field(default=None, description="Filter by tags")
    min_risk_score: Optional[float] = Field(default=None, ge=0, le=100, description="Minimum risk score")
    max_risk_score: Optional[float] = Field(default=None, ge=0, le=100, description="Maximum risk score")
    has_findings: Optional[bool] = Field(default=None, description="Filter assets with/without findings")
    finding_severities: Optional[List[str]] = Field(default=None, description="Filter by finding severities")
    limit: Optional[int] = Field(default=100, ge=1, le=1000, description="Maximum number of results")
    offset: Optional[int] = Field(default=0, ge=0, description="Number of results to skip")
    sort_by: Optional[str] = Field(default="risk_score", description="Sort field")
    sort_order: Optional[str] = Field(default="desc", description="Sort order (asc/desc)")

class AssetReviewRequest(BaseModel):
    """Asset review request model"""
    reviewed_by: str = Field(..., description="User who reviewed the asset")
    review_notes: Optional[str] = Field(default=None, description="Review notes")
    review_status: str = Field(default="reviewed", description="Review status")

class ExportRequest(BaseModel):
    """Export request model"""
    format: str = Field(default="json", description="Export format (json, csv, xlsx)")
    filters: Optional[SearchRequest] = Field(default=None, description="Export filters")
    include_relationships: bool = Field(default=True, description="Include relationship data")
    include_findings: bool = Field(default=True, description="Include security findings")

class InventorySummary(BaseModel):
    """Inventory summary model"""
    total_assets: int
    total_findings: int
    by_cloud: Dict[str, int]
    by_type: Dict[str, int]
    by_project: Dict[str, int]
    by_risk_level: Dict[str, int]
    by_region: Dict[str, int]
    by_service: Dict[str, int]
    last_scan: Optional[str] = None
    scan_status: str = "unknown"

class AssetDetail(BaseModel):
    """Detailed asset information"""
    asset_id: str
    asset_type: str
    service_name: str
    region: str
    name: str
    arn: Optional[str] = None
    tags: Dict[str, str]
    risk_score: int
    security_findings: List[Dict[str, Any]]
    compliance_status: Dict[str, str]
    relationships: Dict[str, List[str]]
    state: str
    created_at: str
    last_scan_at: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    enhanced_risk_score: Optional[Dict[str, Any]] = None

class RelationshipGraph(BaseModel):
    """Asset relationship graph"""
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    asset_id: str
    relationship_types: List[str]

class TagInfo(BaseModel):
    """Tag information"""
    key: str
    values: List[str]
    count: int

# Mock data storage (replace with actual database)
_inventory_data: Dict[str, Asset] = {}
_relationships: List[AssetRelationship] = []

def get_inventory_service():
    """Dependency to get inventory service"""
    return {
        "data": _inventory_data,
        "relationships": _relationships
    }

@router.get("/", response_model=List[AssetDetail])
async def get_inventory(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    service: Optional[str] = Query(None, description="Filter by service"),
    region: Optional[str] = Query(None, description="Filter by region"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    inventory_service: Dict = Depends(get_inventory_service)
):
    """
    GET /api/inventory – fetch full asset list
    
    Returns a paginated list of all assets with optional filtering.
    """
    try:
        assets = list(inventory_service["data"].values())
        
        # Apply filters
        if service:
            assets = [a for a in assets if a.service_name == service]
        if region:
            assets = [a for a in assets if a.region == region]
        if risk_level:
            assets = [a for a in assets if a.enhanced_risk_score and a.enhanced_risk_score.risk_level == risk_level]
        
        # Sort by risk score (descending)
        assets.sort(key=lambda x: x.risk_score, reverse=True)
        
        # Apply pagination
        total_count = len(assets)
        assets = assets[offset:offset + limit]
        
        # Convert to response format
        asset_details = []
        for asset in assets:
            asset_detail = AssetDetail(
                asset_id=asset.asset_id,
                asset_type=asset.asset_type.value,
                service_name=asset.service_name,
                region=asset.region,
                name=asset.name,
                arn=asset.arn,
                tags=asset.tags,
                risk_score=asset.risk_score,
                security_findings=[
                    {
                        "finding_id": f.finding_id,
                        "title": f.title,
                        "description": f.description,
                        "severity": f.severity,
                        "finding_type": f.finding_type,
                        "compliance_frameworks": f.compliance_frameworks,
                        "remediation": f.remediation,
                        "created_at": f.created_at.isoformat() if f.created_at else None,
                        "resource_id": f.resource_id
                    } for f in asset.security_findings
                ],
                compliance_status=asset.compliance_status,
                relationships=asset.relationships,
                state=asset.state,
                created_at=asset.created_at.isoformat(),
                last_scan_at=asset.last_scan_at.isoformat() if asset.last_scan_at else None,
                metadata=asset.metadata.to_dict() if asset.metadata else None,
                enhanced_risk_score=asset.enhanced_risk_score.to_dict() if asset.enhanced_risk_score else None
            )
            asset_details.append(asset_detail)
        
        logger.info("inventory_assets_retrieved", 
                   total_count=total_count,
                   returned_count=len(asset_details),
                   filters_applied={
                       "service": service,
                       "region": region,
                       "risk_level": risk_level
                   })
        
        return asset_details
        
    except Exception as e:
        logger.error("error_retrieving_inventory", error=str(e))
        raise HTTPException(status_code=500, detail=f"Error retrieving inventory: {str(e)}")

@router.post("/search", response_model=List[AssetDetail])
async def search_inventory(
    search_request: SearchRequest,
    inventory_service: Dict = Depends(get_inventory_service)
):
    """
    POST /api/inventory/search – apply filters
    
    Advanced search with multiple filter criteria.
    """
    try:
        assets = list(inventory_service["data"].values())
        
        # Apply filters
        if search_request.services:
            assets = [a for a in assets if a.service_name in search_request.services]
        
        if search_request.regions:
            assets = [a for a in assets if a.region in search_request.regions]
        
        if search_request.resource_types:
            assets = [a for a in assets if a.asset_type.value in search_request.resource_types]
        
        if search_request.risk_levels:
            assets = [a for a in assets if a.enhanced_risk_score and a.enhanced_risk_score.risk_level in search_request.risk_levels]
        
        if search_request.min_risk_score is not None:
            assets = [a for a in assets if a.risk_score >= search_request.min_risk_score]
        
        if search_request.max_risk_score is not None:
            assets = [a for a in assets if a.risk_score <= search_request.max_risk_score]
        
        if search_request.has_findings is not None:
            if search_request.has_findings:
                assets = [a for a in assets if a.security_findings]
            else:
                assets = [a for a in assets if not a.security_findings]
        
        if search_request.finding_severities:
            assets = [a for a in assets if any(f.severity in search_request.finding_severities for f in a.security_findings)]
        
        if search_request.tags:
            for key, value in search_request.tags.items():
                assets = [a for a in assets if a.tags.get(key) == value]
        
        # Sort
        reverse = search_request.sort_order.lower() == "desc"
        if search_request.sort_by == "risk_score":
            assets.sort(key=lambda x: x.risk_score, reverse=reverse)
        elif search_request.sort_by == "name":
            assets.sort(key=lambda x: x.name, reverse=reverse)
        elif search_request.sort_by == "created_at":
            assets.sort(key=lambda x: x.created_at, reverse=reverse)
        
        # Apply pagination
        total_count = len(assets)
        assets = assets[search_request.offset:search_request.offset + search_request.limit]
        
        # Convert to response format
        asset_details = []
        for asset in assets:
            asset_detail = AssetDetail(
                asset_id=asset.asset_id,
                asset_type=asset.asset_type.value,
                service_name=asset.service_name,
                region=asset.region,
                name=asset.name,
                arn=asset.arn,
                tags=asset.tags,
                risk_score=asset.risk_score,
                security_findings=[
                    {
                        "finding_id": f.finding_id,
                        "title": f.title,
                        "description": f.description,
                        "severity": f.severity,
                        "finding_type": f.finding_type,
                        "compliance_frameworks": f.compliance_frameworks,
                        "remediation": f.remediation,
                        "created_at": f.created_at.isoformat() if f.created_at else None,
                        "resource_id": f.resource_id
                    } for f in asset.security_findings
                ],
                compliance_status=asset.compliance_status,
                relationships=asset.relationships,
                state=asset.state,
                created_at=asset.created_at.isoformat(),
                last_scan_at=asset.last_scan_at.isoformat() if asset.last_scan_at else None,
                metadata=asset.metadata.to_dict() if asset.metadata else None,
                enhanced_risk_score=asset.enhanced_risk_score.to_dict() if asset.enhanced_risk_score else None
            )
            asset_details.append(asset_detail)
        
        logger.info("inventory_search_completed", 
                   total_count=total_count,
                   returned_count=len(asset_details),
                   filters_applied=search_request.dict())
        
        return asset_details
        
    except Exception as e:
        logger.error("error_searching_inventory", error=str(e))
        raise HTTPException(status_code=500, detail=f"Error searching inventory: {str(e)}")

@router.get("/summary", response_model=InventorySummary)
async def get_inventory_summary(
    inventory_service: Dict = Depends(get_inventory_service)
):
    """
    GET /api/inventory/summary – get total count by cloud, type, project, etc.
    
    Returns comprehensive inventory summary statistics.
    """
    try:
        assets = list(inventory_service["data"].values())
        
        if not assets:
            return InventorySummary(
                total_assets=0,
                total_findings=0,
                by_cloud={"aws": 0},
                by_type={},
                by_project={},
                by_risk_level={},
                by_region={},
                by_service={},
                last_scan=None,
                scan_status="no_data"
            )
        
        # Calculate summaries
        total_assets = len(assets)
        total_findings = sum(len(asset.security_findings) for asset in assets)
        
        # By cloud (all AWS for now)
        by_cloud = {"aws": total_assets}
        
        # By type
        by_type = {}
        for asset in assets:
            asset_type = asset.asset_type.value
            by_type[asset_type] = by_type.get(asset_type, 0) + 1
        
        # By project (using tags)
        by_project = {}
        for asset in assets:
            project = asset.tags.get("Project", asset.tags.get("project", "unknown"))
            by_project[project] = by_project.get(project, 0) + 1
        
        # By risk level
        by_risk_level = {}
        for asset in assets:
            if asset.enhanced_risk_score and asset.enhanced_risk_score.risk_level:
                risk_level = asset.enhanced_risk_score.risk_level
                by_risk_level[risk_level] = by_risk_level.get(risk_level, 0) + 1
            else:
                by_risk_level["unknown"] = by_risk_level.get("unknown", 0) + 1
        
        # By region
        by_region = {}
        for asset in assets:
            by_region[asset.region] = by_region.get(asset.region, 0) + 1
        
        # By service
        by_service = {}
        for asset in assets:
            by_service[asset.service_name] = by_service.get(asset.service_name, 0) + 1
        
        # Get last scan info
        last_scan = None
        scan_status = "unknown"
        if assets:
            latest_asset = max(assets, key=lambda x: x.last_scan_at if x.last_scan_at else datetime.min)
            if latest_asset.last_scan_at:
                last_scan = latest_asset.last_scan_at.isoformat()
                scan_status = "completed"
        
        summary = InventorySummary(
            total_assets=total_assets,
            total_findings=total_findings,
            by_cloud=by_cloud,
            by_type=by_type,
            by_project=by_project,
            by_risk_level=by_risk_level,
            by_region=by_region,
            by_service=by_service,
            last_scan=last_scan,
            scan_status=scan_status
        )
        
        logger.info("inventory_summary_generated", 
                   total_assets=total_assets,
                   total_findings=total_findings,
                   summary_stats={
                       "clouds": len(by_cloud),
                       "types": len(by_type),
                       "projects": len(by_project),
                       "regions": len(by_region),
                       "services": len(by_service)
                   })
        
        return summary
        
    except Exception as e:
        logger.error("error_generating_summary", error=str(e))
        raise HTTPException(status_code=500, detail=f"Error generating inventory summary: {str(e)}")

@router.get("/{asset_id}", response_model=AssetDetail)
async def get_asset_detail(
    asset_id: str,
    inventory_service: Dict = Depends(get_inventory_service)
):
    """
    GET /api/inventory/:id – detailed asset info
    
    Returns detailed information for a specific asset.
    """
    try:
        asset = inventory_service["data"].get(asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
        
        asset_detail = AssetDetail(
            asset_id=asset.asset_id,
            asset_type=asset.asset_type.value,
            service_name=asset.service_name,
            region=asset.region,
            name=asset.name,
            arn=asset.arn,
            tags=asset.tags,
            risk_score=asset.risk_score,
            security_findings=[
                {
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                    "finding_type": f.finding_type,
                    "compliance_frameworks": f.compliance_frameworks,
                    "remediation": f.remediation,
                    "created_at": f.created_at.isoformat() if f.created_at else None,
                    "resource_id": f.resource_id
                } for f in asset.security_findings
            ],
            compliance_status=asset.compliance_status,
            relationships=asset.relationships,
            state=asset.state,
            created_at=asset.created_at.isoformat(),
            last_scan_at=asset.last_scan_at.isoformat() if asset.last_scan_at else None,
            metadata=asset.metadata.to_dict() if asset.metadata else None,
            enhanced_risk_score=asset.enhanced_risk_score.to_dict() if asset.enhanced_risk_score else None
        )
        
        logger.info("asset_detail_retrieved", asset_id=asset_id)
        return asset_detail
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("error_retrieving_asset_detail", asset_id=asset_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Error retrieving asset detail: {str(e)}")

@router.get("/{asset_id}/relationships", response_model=RelationshipGraph)
async def get_asset_relationships(
    asset_id: str,
    inventory_service: Dict = Depends(get_inventory_service)
):
    """
    GET /api/inventory/:id/relationships – graph edges/nodes
    
    Returns relationship graph data for a specific asset.
    """
    try:
        asset = inventory_service["data"].get(asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
        
        # Get all relationships involving this asset
        relationships = inventory_service["relationships"]
        asset_relationships = [r for r in relationships if r.source_asset_id == asset_id or r.target_asset_id == asset_id]
        
        # Build nodes and edges
        nodes = []
        edges = []
        relationship_types = set()
        
        # Add the main asset as a node
        nodes.append({
            "id": asset.asset_id,
            "label": asset.name,
            "type": asset.asset_type.value,
            "service": asset.service_name,
            "region": asset.region,
            "risk_score": asset.risk_score,
            "is_main": True
        })
        
        # Process relationships
        for rel in asset_relationships:
            relationship_types.add(rel.relationship_type)
            
            # Add target asset as node if it's not the main asset
            if rel.target_asset_id != asset_id:
                target_asset = inventory_service["data"].get(rel.target_asset_id)
                if target_asset:
                    nodes.append({
                        "id": target_asset.asset_id,
                        "label": target_asset.name,
                        "type": target_asset.asset_type.value,
                        "service": target_asset.service_name,
                        "region": target_asset.region,
                        "risk_score": target_asset.risk_score,
                        "is_main": False
                    })
            
            # Add edge
            edges.append({
                "source": rel.source_asset_id,
                "target": rel.target_asset_id,
                "type": rel.relationship_type,
                "data": rel.relationship_data
            })
        
        graph = RelationshipGraph(
            nodes=nodes,
            edges=edges,
            asset_id=asset_id,
            relationship_types=list(relationship_types)
        )
        
        logger.info("asset_relationships_retrieved", 
                   asset_id=asset_id,
                   nodes_count=len(nodes),
                   edges_count=len(edges),
                   relationship_types=list(relationship_types))
        
        return graph
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("error_retrieving_relationships", asset_id=asset_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Error retrieving asset relationships: {str(e)}")

@router.post("/export")
async def export_inventory(
    export_request: ExportRequest,
    background_tasks: BackgroundTasks,
    inventory_service: Dict = Depends(get_inventory_service)
):
    """
    POST /api/inventory/export – export current results
    
    Exports inventory data in various formats (JSON, CSV, XLSX).
    """
    try:
        # Get filtered assets
        assets = list(inventory_service["data"].values())
        
        # Apply filters if provided
        if export_request.filters:
            # Apply the same filtering logic as search endpoint
            if export_request.filters.services:
                assets = [a for a in assets if a.service_name in export_request.filters.services]
            if export_request.filters.regions:
                assets = [a for a in assets if a.region in export_request.filters.regions]
            # ... apply other filters as needed
        
        # Convert to export format
        export_data = []
        for asset in assets:
            asset_data = {
                "asset_id": asset.asset_id,
                "asset_type": asset.asset_type.value,
                "service_name": asset.service_name,
                "region": asset.region,
                "name": asset.name,
                "arn": asset.arn,
                "risk_score": asset.risk_score,
                "state": asset.state,
                "created_at": asset.created_at.isoformat(),
                "last_scan_at": asset.last_scan_at.isoformat() if asset.last_scan_at else None,
                "tags": json.dumps(asset.tags),
                "compliance_status": json.dumps(asset.compliance_status)
            }
            
            if export_request.include_findings:
                asset_data["findings_count"] = len(asset.security_findings)
                asset_data["critical_findings"] = len([f for f in asset.security_findings if f.severity == "critical"])
                asset_data["high_findings"] = len([f for f in asset.security_findings if f.severity == "high"])
            
            if export_request.include_relationships:
                asset_data["relationships_count"] = len(asset.relationships)
            
            export_data.append(asset_data)
        
        # Generate export based on format
        if export_request.format.lower() == "json":
            content = json.dumps(export_data, indent=2)
            media_type = "application/json"
            filename = f"inventory_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        elif export_request.format.lower() == "csv":
            if not export_data:
                content = ""
            else:
                # Create CSV content
                output = io.StringIO()
                writer = csv.DictWriter(output, fieldnames=export_data[0].keys())
                writer.writeheader()
                writer.writerows(export_data)
                content = output.getvalue()
            
            media_type = "text/csv"
            filename = f"inventory_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported export format: {export_request.format}")
        
        logger.info("inventory_export_generated", 
                   format=export_request.format,
                   assets_count=len(export_data),
                   include_findings=export_request.include_findings,
                   include_relationships=export_request.include_relationships)
        
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        logger.error("error_exporting_inventory", error=str(e))
        raise HTTPException(status_code=500, detail=f"Error exporting inventory: {str(e)}")

@router.patch("/{asset_id}/review")
async def review_asset(
    asset_id: str,
    review_request: AssetReviewRequest,
    inventory_service: Dict = Depends(get_inventory_service)
):
    """
    PATCH /api/inventory/:id/review – mark asset reviewed
    
    Marks an asset as reviewed with optional notes.
    """
    try:
        asset = inventory_service["data"].get(asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
        
        # Update asset review status
        asset.state = review_request.review_status
        if not hasattr(asset, 'review_info'):
            asset.review_info = {}
        
        asset.review_info.update({
            "reviewed_by": review_request.reviewed_by,
            "review_notes": review_request.review_notes,
            "reviewed_at": datetime.now().isoformat(),
            "review_status": review_request.review_status
        })
        
        logger.info("asset_reviewed", 
                   asset_id=asset_id,
                   reviewed_by=review_request.reviewed_by,
                   review_status=review_request.review_status)
        
        return {
            "status": "success",
            "message": f"Asset {asset_id} marked as {review_request.review_status}",
            "asset_id": asset_id,
            "reviewed_by": review_request.reviewed_by,
            "reviewed_at": asset.review_info["reviewed_at"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("error_reviewing_asset", asset_id=asset_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Error reviewing asset: {str(e)}")

@router.get("/tags", response_model=List[TagInfo])
async def get_tags(
    inventory_service: Dict = Depends(get_inventory_service)
):
    """
    GET /api/inventory/tags – fetch unique tag keys/values
    
    Returns all unique tag keys and their values across all assets.
    """
    try:
        assets = list(inventory_service["data"].values())
        
        # Collect all tags
        tag_data = {}
        for asset in assets:
            for key, value in asset.tags.items():
                if key not in tag_data:
                    tag_data[key] = set()
                tag_data[key].add(value)
        
        # Convert to response format
        tag_info = []
        for key, values in tag_data.items():
            tag_info.append(TagInfo(
                key=key,
                values=list(values),
                count=len(values)
            ))
        
        # Sort by count (descending)
        tag_info.sort(key=lambda x: x.count, reverse=True)
        
        logger.info("tags_retrieved", 
                   unique_keys=len(tag_info),
                   total_values=sum(tag.count for tag in tag_info))
        
        return tag_info
        
    except Exception as e:
        logger.error("error_retrieving_tags", error=str(e))
        raise HTTPException(status_code=500, detail=f"Error retrieving tags: {str(e)}")

# Helper function to load mock data (replace with actual data loading)
def load_mock_inventory_data():
    """Load mock inventory data for testing"""
    global _inventory_data, _relationships
    
    # Create some mock assets
    mock_assets = [
        Asset(
            asset_id="ec2-001",
            asset_type=AssetType.COMPUTE,
            service_name="ec2",
            region="us-east-1",
            name="web-server-01",
            arn="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
            tags={"Project": "web-app", "Environment": "production"},
            risk_score=75
        ),
        Asset(
            asset_id="s3-001",
            asset_type=AssetType.STORAGE,
            service_name="s3",
            region="us-east-1",
            name="data-bucket",
            arn="arn:aws:s3:::data-bucket",
            tags={"Project": "data-storage", "Environment": "production"},
            risk_score=45
        ),
        Asset(
            asset_id="rds-001",
            asset_type=AssetType.DATABASE,
            service_name="rds",
            region="us-west-2",
            name="prod-database",
            arn="arn:aws:rds:us-west-2:123456789012:db:prod-database",
            tags={"Project": "web-app", "Environment": "production"},
            risk_score=60
        )
    ]
    
    # Add to global data
    for asset in mock_assets:
        _inventory_data[asset.asset_id] = asset
    
    # Create some mock relationships
    mock_relationships = [
        AssetRelationship(
            source_asset_id="ec2-001",
            target_asset_id="s3-001",
            relationship_type="accesses"
        ),
        AssetRelationship(
            source_asset_id="ec2-001",
            target_asset_id="rds-001",
            relationship_type="connects_to"
        )
    ]
    
    _relationships.extend(mock_relationships)
    
    logger.info("mock_inventory_data_loaded", 
               assets_count=len(_inventory_data),
               relationships_count=len(_relationships))

# Load mock data on module import
load_mock_inventory_data() 