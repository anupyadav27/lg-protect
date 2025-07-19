#!/usr/bin/env python3
"""
Asset Relationship Data Models for LG-Protect Inventory System

Provides comprehensive data structures for mapping relationships and dependencies
between assets in enterprise cloud environments.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field, asdict
import structlog

logger = structlog.get_logger(__name__)

class RelationshipType(Enum):
    """Types of relationships between assets"""
    # Containment relationships
    CONTAINED_IN = "contained_in"           # EC2 instance in VPC
    CONTAINS = "contains"                   # VPC contains subnets
    
    # Security relationships  
    PROTECTED_BY = "protected_by"           # Instance protected by security group
    PROTECTS = "protects"                   # Security group protects instances
    
    # Network relationships
    CONNECTS_TO = "connects_to"             # Instance connects to RDS
    CONNECTED_FROM = "connected_from"       # RDS receives connections from instance
    
    # Access relationships
    ACCESSES = "accesses"                   # Role accesses S3 bucket
    ACCESSED_BY = "accessed_by"             # S3 bucket accessed by role
    
    # Dependency relationships
    DEPENDS_ON = "depends_on"               # Lambda depends on VPC
    DEPENDENCY_OF = "dependency_of"         # VPC is dependency of Lambda
    
    # Composition relationships
    PART_OF = "part_of"                     # EBS volume part of EC2 instance
    HAS_PART = "has_part"                   # EC2 instance has EBS volume
    
    # Data flow relationships
    SENDS_TO = "sends_to"                   # SQS sends to Lambda
    RECEIVES_FROM = "receives_from"         # Lambda receives from SQS
    
    # Management relationships
    MANAGES = "manages"                     # IAM role manages EC2 instance
    MANAGED_BY = "managed_by"               # EC2 instance managed by IAM role
    
    # Configuration relationships
    CONFIGURES = "configures"               # Config rule configures resource
    CONFIGURED_BY = "configured_by"         # Resource configured by config rule

class RelationshipStrength(Enum):
    """Strength/criticality of the relationship"""
    CRITICAL = "critical"     # Relationship failure breaks functionality
    HIGH = "high"            # Relationship failure degrades performance
    MEDIUM = "medium"        # Relationship failure causes minor issues
    LOW = "low"              # Relationship failure has minimal impact
    INFORMATIONAL = "info"   # Relationship is for information only

class RelationshipStatus(Enum):
    """Status of the relationship"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"

@dataclass
class RelationshipMetadata:
    """Metadata for relationship discovery and validation"""
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_validated: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    discovery_method: str = ""
    confidence_score: float = 1.0  # 0.0 to 1.0
    validation_source: str = ""
    
    def update_validation_timestamp(self):
        """Update last validation timestamp"""
        self.last_validated = datetime.now(timezone.utc).isoformat()

@dataclass
class RelationshipContext:
    """Context and configuration details for the relationship"""
    configuration: Dict[str, Any] = field(default_factory=dict)
    network_details: Dict[str, Any] = field(default_factory=dict)
    security_context: Dict[str, Any] = field(default_factory=dict)
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    
    def add_context(self, context_type: str, context_data: Dict[str, Any]) -> None:
        """Add context data by type"""
        if context_type == "network":
            self.network_details.update(context_data)
        elif context_type == "security":
            self.security_context.update(context_data)
        elif context_type == "performance":
            self.performance_metrics.update(context_data)
        else:
            self.configuration.update(context_data)

@dataclass
class AssetRelationship:
    """
    Enterprise-grade asset relationship model
    
    Supports:
    - Bidirectional relationship mapping
    - Relationship validation and monitoring
    - Security impact analysis
    - Performance impact tracking
    - Change detection and alerting
    """
    
    # Core Identity
    relationship_id: str = field(default_factory=lambda: f"rel-{str(uuid.uuid4())}")
    
    # Relationship Definition
    source_asset_id: str = ""
    target_asset_id: str = ""
    relationship_type: RelationshipType = RelationshipType.DEPENDS_ON
    
    # Relationship Properties
    strength: RelationshipStrength = RelationshipStrength.MEDIUM
    status: RelationshipStatus = RelationshipStatus.UNKNOWN
    is_bidirectional: bool = False
    
    # Context and Details
    context: RelationshipContext = field(default_factory=RelationshipContext)
    description: str = ""
    
    # Asset Context (for performance - avoid frequent lookups)
    source_asset_type: str = ""
    target_asset_type: str = ""
    source_service: str = ""
    target_service: str = ""
    
    # Location Context
    same_account: bool = True
    same_region: bool = True
    same_vpc: bool = False
    
    # Security Analysis
    security_implications: List[str] = field(default_factory=list)
    compliance_impact: Dict[str, str] = field(default_factory=dict)
    
    # Monitoring
    health_check_enabled: bool = False
    last_health_check: Optional[str] = None
    health_status: str = "unknown"
    
    # Metadata
    metadata: RelationshipMetadata = field(default_factory=RelationshipMetadata)
    tags: Dict[str, str] = field(default_factory=dict)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization validation and setup"""
        try:
            # Validate required fields
            self._validate_required_fields()
            
            # Set default description if not provided
            if not self.description:
                self.description = self._generate_default_description()
            
            # Determine if relationship should be bidirectional
            if not hasattr(self, '_bidirectional_set'):
                self.is_bidirectional = self._should_be_bidirectional()
            
            logger.debug("asset_relationship_created", 
                        relationship_id=self.relationship_id,
                        relationship_type=self.relationship_type.value,
                        source_asset=self.source_asset_id,
                        target_asset=self.target_asset_id)
                        
        except Exception as e:
            logger.error("asset_relationship_creation_failed", 
                        relationship_id=getattr(self, 'relationship_id', 'unknown'),
                        error=str(e))
            raise
    
    def _validate_required_fields(self):
        """Validate required fields for relationship creation"""
        required_fields = {
            'relationship_id': self.relationship_id,
            'source_asset_id': self.source_asset_id,
            'target_asset_id': self.target_asset_id
        }
        
        missing_fields = [field for field, value in required_fields.items() if not value]
        
        if missing_fields:
            raise ValueError(f"Missing required relationship fields: {missing_fields}")
        
        if self.source_asset_id == self.target_asset_id:
            raise ValueError("Source and target assets cannot be the same")
    
    def _generate_default_description(self) -> str:
        """Generate default description for the relationship"""
        try:
            return f"{self.source_service or 'Asset'} {self.relationship_type.value.replace('_', ' ')} {self.target_service or 'Asset'}"
        except Exception as e:
            logger.warning("relationship_description_generation_failed", 
                          relationship_id=self.relationship_id,
                          error=str(e))
            return f"Relationship: {self.relationship_type.value}"
    
    def _should_be_bidirectional(self) -> bool:
        """Determine if relationship should be bidirectional based on type"""
        # All relationships with inverse mappings should be bidirectional
        inverse_mappings = {
            RelationshipType.CONTAINED_IN: RelationshipType.CONTAINS,
            RelationshipType.CONTAINS: RelationshipType.CONTAINED_IN,
            RelationshipType.PROTECTED_BY: RelationshipType.PROTECTS,
            RelationshipType.PROTECTS: RelationshipType.PROTECTED_BY,
            RelationshipType.CONNECTS_TO: RelationshipType.CONNECTED_FROM,
            RelationshipType.CONNECTED_FROM: RelationshipType.CONNECTS_TO,
            RelationshipType.ACCESSES: RelationshipType.ACCESSED_BY,
            RelationshipType.ACCESSED_BY: RelationshipType.ACCESSES,
            RelationshipType.DEPENDS_ON: RelationshipType.DEPENDENCY_OF,
            RelationshipType.DEPENDENCY_OF: RelationshipType.DEPENDS_ON,
            RelationshipType.PART_OF: RelationshipType.HAS_PART,
            RelationshipType.HAS_PART: RelationshipType.PART_OF,
            RelationshipType.SENDS_TO: RelationshipType.RECEIVES_FROM,
            RelationshipType.RECEIVES_FROM: RelationshipType.SENDS_TO,
            RelationshipType.MANAGES: RelationshipType.MANAGED_BY,
            RelationshipType.MANAGED_BY: RelationshipType.MANAGES,
            RelationshipType.CONFIGURES: RelationshipType.CONFIGURED_BY,
            RelationshipType.CONFIGURED_BY: RelationshipType.CONFIGURES,
        }
        return self.relationship_type in inverse_mappings
    
    def add_security_implication(self, implication: str) -> None:
        """Add security implication for the relationship"""
        try:
            if implication not in self.security_implications:
                self.security_implications.append(implication)
                logger.debug("relationship_security_implication_added", 
                           relationship_id=self.relationship_id,
                           implication=implication)
        except Exception as e:
            logger.error("relationship_security_implication_addition_failed", 
                        relationship_id=self.relationship_id,
                        error=str(e))
    
    def update_health_status(self, status: str, check_details: Dict[str, Any] = None) -> None:
        """Update relationship health status"""
        try:
            old_status = self.health_status
            self.health_status = status
            self.last_health_check = datetime.now(timezone.utc).isoformat()
            
            if check_details:
                self.custom_fields['last_health_check_details'] = check_details
            
            self.metadata.update_validation_timestamp()
            
            logger.info("relationship_health_status_updated", 
                       relationship_id=self.relationship_id,
                       old_status=old_status,
                       new_status=status)
                       
        except Exception as e:
            logger.error("relationship_health_status_update_failed", 
                        relationship_id=self.relationship_id,
                        error=str(e))
            raise
    
    def update_status(self, new_status: RelationshipStatus, reason: str = "") -> None:
        """Update relationship status with validation"""
        try:
            old_status = self.status
            self.status = new_status
            
            if reason:
                self.custom_fields['status_change_reason'] = reason
                self.custom_fields['status_updated_at'] = datetime.now(timezone.utc).isoformat()
            
            self.metadata.update_validation_timestamp()
            
            logger.info("relationship_status_updated", 
                       relationship_id=self.relationship_id,
                       old_status=old_status.value,
                       new_status=new_status.value)
                       
        except Exception as e:
            logger.error("relationship_status_update_failed", 
                        relationship_id=self.relationship_id,
                        error=str(e))
            raise
    
    def add_network_context(self, network_data: Dict[str, Any]) -> None:
        """Add network-specific context to the relationship"""
        try:
            self.context.add_context("network", network_data)
            logger.debug("relationship_network_context_added", 
                       relationship_id=self.relationship_id,
                       context_keys=list(network_data.keys()))
        except Exception as e:
            logger.error("relationship_network_context_addition_failed", 
                        relationship_id=self.relationship_id,
                        error=str(e))
    
    def add_security_context(self, security_data: Dict[str, Any]) -> None:
        """Add security-specific context to the relationship"""
        try:
            self.context.add_context("security", security_data)
            logger.debug("relationship_security_context_added", 
                       relationship_id=self.relationship_id,
                       context_keys=list(security_data.keys()))
        except Exception as e:
            logger.error("relationship_security_context_addition_failed", 
                        relationship_id=self.relationship_id,
                        error=str(e))
    
    def get_inverse_relationship_type(self) -> Optional[RelationshipType]:
        """Get the inverse relationship type if bidirectional"""
        inverse_mappings = {
            RelationshipType.CONTAINED_IN: RelationshipType.CONTAINS,
            RelationshipType.CONTAINS: RelationshipType.CONTAINED_IN,
            RelationshipType.PROTECTED_BY: RelationshipType.PROTECTS,
            RelationshipType.PROTECTS: RelationshipType.PROTECTED_BY,
            RelationshipType.CONNECTS_TO: RelationshipType.CONNECTED_FROM,
            RelationshipType.CONNECTED_FROM: RelationshipType.CONNECTS_TO,
            RelationshipType.ACCESSES: RelationshipType.ACCESSED_BY,
            RelationshipType.ACCESSED_BY: RelationshipType.ACCESSES,
            RelationshipType.DEPENDS_ON: RelationshipType.DEPENDENCY_OF,
            RelationshipType.DEPENDENCY_OF: RelationshipType.DEPENDS_ON,
            RelationshipType.PART_OF: RelationshipType.HAS_PART,
            RelationshipType.HAS_PART: RelationshipType.PART_OF,
            RelationshipType.SENDS_TO: RelationshipType.RECEIVES_FROM,
            RelationshipType.RECEIVES_FROM: RelationshipType.SENDS_TO,
            RelationshipType.MANAGES: RelationshipType.MANAGED_BY,
            RelationshipType.MANAGED_BY: RelationshipType.MANAGES,
            RelationshipType.CONFIGURES: RelationshipType.CONFIGURED_BY,
            RelationshipType.CONFIGURED_BY: RelationshipType.CONFIGURES,
        }
        
        return inverse_mappings.get(self.relationship_type)
    
    def create_inverse_relationship(self) -> Optional['AssetRelationship']:
        """Create inverse relationship if this relationship is bidirectional"""
        try:
            if not self.is_bidirectional:
                return None
            
            inverse_type = self.get_inverse_relationship_type()
            if not inverse_type:
                return None
            
            inverse_relationship = AssetRelationship(
                source_asset_id=self.target_asset_id,
                target_asset_id=self.source_asset_id,
                relationship_type=inverse_type,
                strength=self.strength,
                status=self.status,
                is_bidirectional=True,
                source_asset_type=self.target_asset_type,
                target_asset_type=self.source_asset_type,
                source_service=self.target_service,
                target_service=self.source_service,
                same_account=self.same_account,
                same_region=self.same_region,
                same_vpc=self.same_vpc,
                description=f"Inverse of: {self.description}"
            )
            
            # Mark that bidirectional was explicitly set to avoid recursion
            inverse_relationship._bidirectional_set = True
            
            logger.debug("inverse_relationship_created", 
                       original_id=self.relationship_id,
                       inverse_id=inverse_relationship.relationship_id)
            
            return inverse_relationship
            
        except Exception as e:
            logger.error("inverse_relationship_creation_failed", 
                        relationship_id=self.relationship_id,
                        error=str(e))
            return None
    
    def is_cross_account(self) -> bool:
        """Check if relationship spans multiple AWS accounts"""
        return not self.same_account
    
    def is_cross_region(self) -> bool:
        """Check if relationship spans multiple AWS regions"""
        return not self.same_region
    
    def get_security_risk_level(self) -> str:
        """Calculate security risk level based on relationship properties"""
        try:
            risk_factors = 0
            
            # Cross-account relationships are higher risk
            if self.is_cross_account():
                risk_factors += 3
            
            # Cross-region relationships add complexity
            if self.is_cross_region():
                risk_factors += 1
            
            # Certain relationship types are inherently riskier
            high_risk_types = {
                RelationshipType.ACCESSES,
                RelationshipType.MANAGES,
                RelationshipType.CONFIGURES
            }
            if self.relationship_type in high_risk_types:
                risk_factors += 2
            
            # Security implications increase risk
            risk_factors += len(self.security_implications)
            
            # Map to risk levels
            if risk_factors >= 5:
                return "high"
            elif risk_factors >= 3:
                return "medium"
            elif risk_factors >= 1:
                return "low"
            else:
                return "minimal"
                
        except Exception as e:
            logger.error("relationship_security_risk_calculation_failed", 
                        relationship_id=self.relationship_id,
                        error=str(e))
            return "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert relationship to dictionary for serialization"""
        try:
            relationship_dict = asdict(self)
            
            # Convert enums to strings
            relationship_dict['relationship_type'] = self.relationship_type.value
            relationship_dict['strength'] = self.strength.value
            relationship_dict['status'] = self.status.value
            
            return relationship_dict
            
        except Exception as e:
            logger.error("relationship_serialization_failed", 
                        relationship_id=self.relationship_id,
                        error=str(e))
            raise
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AssetRelationship':
        """Create relationship from dictionary with validation"""
        try:
            # Convert string enums back to enum objects
            if 'relationship_type' in data and isinstance(data['relationship_type'], str):
                data['relationship_type'] = RelationshipType(data['relationship_type'])
            if 'strength' in data and isinstance(data['strength'], str):
                data['strength'] = RelationshipStrength(data['strength'])
            if 'status' in data and isinstance(data['status'], str):
                data['status'] = RelationshipStatus(data['status'])
            
            # Handle nested objects
            if 'metadata' in data and isinstance(data['metadata'], dict):
                data['metadata'] = RelationshipMetadata(**data['metadata'])
            if 'context' in data and isinstance(data['context'], dict):
                data['context'] = RelationshipContext(**data['context'])
            
            return cls(**data)
            
        except Exception as e:
            logger.error("relationship_deserialization_failed", 
                        data_keys=list(data.keys()) if isinstance(data, dict) else "invalid_data",
                        error=str(e))
            raise
    
    def __str__(self) -> str:
        """String representation for debugging"""
        return f"AssetRelationship(id={self.relationship_id}, type={self.relationship_type.value}, {self.source_asset_id} -> {self.target_asset_id})"
    
    def __repr__(self) -> str:
        """Detailed representation for debugging"""
        return f"AssetRelationship(relationship_id='{self.relationship_id}', type={self.relationship_type}, source='{self.source_asset_id}', target='{self.target_asset_id}', status={self.status})"


@dataclass
class RelationshipGraph:
    """
    Container for managing asset relationships as a graph structure
    
    Supports:
    - Efficient relationship queries
    - Graph traversal operations
    - Dependency analysis
    - Impact assessment
    """
    
    graph_id: str = field(default_factory=lambda: f"graph-{str(uuid.uuid4())}")
    relationships: Dict[str, AssetRelationship] = field(default_factory=dict)
    
    # Indexes for efficient querying
    _source_index: Dict[str, Set[str]] = field(default_factory=lambda: {})
    _target_index: Dict[str, Set[str]] = field(default_factory=lambda: {})
    _type_index: Dict[RelationshipType, Set[str]] = field(default_factory=lambda: {})
    
    def add_relationship(self, relationship: AssetRelationship) -> None:
        """Add relationship to the graph with indexing"""
        try:
            # Add to main storage
            self.relationships[relationship.relationship_id] = relationship
            
            # Update indexes
            self._update_indexes_add(relationship)
            
            # Create inverse relationship if bidirectional
            if relationship.is_bidirectional:
                inverse = relationship.create_inverse_relationship()
                if inverse:
                    self.relationships[inverse.relationship_id] = inverse
                    self._update_indexes_add(inverse)
            
            logger.debug("relationship_added_to_graph", 
                       graph_id=self.graph_id,
                       relationship_id=relationship.relationship_id)
                       
        except Exception as e:
            logger.error("relationship_graph_addition_failed", 
                        graph_id=self.graph_id,
                        relationship_id=getattr(relationship, 'relationship_id', 'unknown'),
                        error=str(e))
            raise
    
    def _update_indexes_add(self, relationship: AssetRelationship) -> None:
        """Update indexes when adding relationship"""
        # Source index
        if relationship.source_asset_id not in self._source_index:
            self._source_index[relationship.source_asset_id] = set()
        self._source_index[relationship.source_asset_id].add(relationship.relationship_id)
        
        # Target index
        if relationship.target_asset_id not in self._target_index:
            self._target_index[relationship.target_asset_id] = set()
        self._target_index[relationship.target_asset_id].add(relationship.relationship_id)
        
        # Type index
        if relationship.relationship_type not in self._type_index:
            self._type_index[relationship.relationship_type] = set()
        self._type_index[relationship.relationship_type].add(relationship.relationship_id)
    
    def get_relationships_from_asset(self, asset_id: str) -> List[AssetRelationship]:
        """Get all relationships where asset is the source"""
        try:
            relationship_ids = self._source_index.get(asset_id, set())
            return [self.relationships[rel_id] for rel_id in relationship_ids if rel_id in self.relationships]
        except Exception as e:
            logger.error("relationship_graph_source_query_failed", 
                        graph_id=self.graph_id,
                        asset_id=asset_id,
                        error=str(e))
            return []
    
    def get_relationships_to_asset(self, asset_id: str) -> List[AssetRelationship]:
        """Get all relationships where asset is the target"""
        try:
            relationship_ids = self._target_index.get(asset_id, set())
            return [self.relationships[rel_id] for rel_id in relationship_ids if rel_id in self.relationships]
        except Exception as e:
            logger.error("relationship_graph_target_query_failed", 
                        graph_id=self.graph_id,
                        asset_id=asset_id,
                        error=str(e))
            return []
    
    def get_all_relationships_for_asset(self, asset_id: str) -> List[AssetRelationship]:
        """Get all relationships involving an asset (as source or target)"""
        try:
            relationships = []
            relationships.extend(self.get_relationships_from_asset(asset_id))
            relationships.extend(self.get_relationships_to_asset(asset_id))
            
            # Remove duplicates
            seen_ids = set()
            unique_relationships = []
            for rel in relationships:
                if rel.relationship_id not in seen_ids:
                    unique_relationships.append(rel)
                    seen_ids.add(rel.relationship_id)
            
            return unique_relationships
            
        except Exception as e:
            logger.error("relationship_graph_all_query_failed", 
                        graph_id=self.graph_id,
                        asset_id=asset_id,
                        error=str(e))
            return []
    
    def get_relationships_by_type(self, relationship_type: RelationshipType) -> List[AssetRelationship]:
        """Get all relationships of a specific type"""
        try:
            relationship_ids = self._type_index.get(relationship_type, set())
            return [self.relationships[rel_id] for rel_id in relationship_ids if rel_id in self.relationships]
        except Exception as e:
            logger.error("relationship_graph_type_query_failed", 
                        graph_id=self.graph_id,
                        relationship_type=relationship_type.value,
                        error=str(e))
            return []
    
    def find_dependency_chain(self, asset_id: str, max_depth: int = 5) -> List[List[str]]:
        """Find dependency chains starting from an asset"""
        try:
            chains = []
            visited = set()
            
            def _traverse_dependencies(current_asset: str, current_chain: List[str], depth: int):
                if depth > max_depth or current_asset in visited:
                    return
                
                visited.add(current_asset)
                current_chain.append(current_asset)
                
                # Get dependencies (assets this asset depends on)
                dependencies = self.get_relationships_from_asset(current_asset)
                dependency_relations = [
                    rel for rel in dependencies 
                    if rel.relationship_type == RelationshipType.DEPENDS_ON
                ]
                
                if not dependency_relations:
                    # End of chain, add to results
                    chains.append(current_chain.copy())
                else:
                    # Continue traversing
                    for rel in dependency_relations:
                        _traverse_dependencies(rel.target_asset_id, current_chain.copy(), depth + 1)
                
                visited.remove(current_asset)
            
            _traverse_dependencies(asset_id, [], 0)
            return chains
            
        except Exception as e:
            logger.error("dependency_chain_analysis_failed", 
                        graph_id=self.graph_id,
                        asset_id=asset_id,
                        error=str(e))
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get graph statistics for monitoring and analysis"""
        try:
            stats = {
                'total_relationships': len(self.relationships),
                'unique_assets': len(set(list(self._source_index.keys()) + list(self._target_index.keys()))),
                'relationship_types': {rt.value: len(rels) for rt, rels in self._type_index.items()},
                'cross_account_relationships': sum(1 for rel in self.relationships.values() if rel.is_cross_account()),
                'cross_region_relationships': sum(1 for rel in self.relationships.values() if rel.is_cross_region()),
                'bidirectional_relationships': sum(1 for rel in self.relationships.values() if rel.is_bidirectional)
            }
            
            return stats
            
        except Exception as e:
            logger.error("relationship_graph_statistics_failed", 
                        graph_id=self.graph_id,
                        error=str(e))
            return {}