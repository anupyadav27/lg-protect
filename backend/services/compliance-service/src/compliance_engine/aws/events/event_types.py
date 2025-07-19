"""
Event Types for LG-Protect Event System
Centralized event type definitions following API Gateway → Events → Services pattern
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, Optional
from datetime import datetime


class EventCategory(Enum):
    """High-level event categories"""
    INVENTORY = "inventory"
    COMPLIANCE = "compliance"
    SECURITY = "security"
    ALERT = "alert"
    SYSTEM = "system"
    USER = "user"


class EventType(Enum):
    """All supported event types in the system"""
    
    # Inventory Events
    INVENTORY_DISCOVERED = "inventory.discovered"
    INVENTORY_CHANGED = "inventory.changed"
    INVENTORY_DELETED = "inventory.deleted"
    INVENTORY_SCAN_STARTED = "inventory.scan.started"
    INVENTORY_SCAN_COMPLETED = "inventory.scan.completed"
    
    # Compliance Events
    COMPLIANCE_VIOLATION = "compliance.violation"
    COMPLIANCE_RESOLVED = "compliance.resolved"
    COMPLIANCE_SCAN_STARTED = "compliance.scan.started"
    COMPLIANCE_SCAN_COMPLETED = "compliance.scan.completed"
    COMPLIANCE_POLICY_UPDATED = "compliance.policy.updated"
    
    # Security Events
    SECURITY_THREAT = "security.threat"
    SECURITY_RESOLVED = "security.resolved"
    SECURITY_MISCONFIGURATION = "security.misconfiguration"
    SECURITY_DRIFT_DETECTED = "security.drift.detected"
    SECURITY_VULNERABILITY = "security.vulnerability"
    
    # Alert Events
    ALERT_TRIGGERED = "alert.triggered"
    ALERT_RESOLVED = "alert.resolved"
    ALERT_ESCALATED = "alert.escalated"
    ALERT_ACKNOWLEDGED = "alert.acknowledged"
    
    # System Events
    SERVICE_STARTED = "system.service.started"
    SERVICE_STOPPED = "system.service.stopped"
    SERVICE_HEALTH_CHECK = "system.service.health"
    
    # User Events
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    USER_ACTION = "user.action"


class EventPriority(Enum):
    """Event priority levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class EventData:
    """Base event data structure"""
    event_type: EventType
    timestamp: datetime
    source_service: str
    event_id: str
    priority: EventPriority = EventPriority.MEDIUM
    data: Dict[str, Any] = None
    correlation_id: Optional[str] = None
    user_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event data to dictionary"""
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "source_service": self.source_service,
            "event_id": self.event_id,
            "priority": self.priority.value,
            "data": self.data or {},
            "correlation_id": self.correlation_id,
            "user_id": self.user_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EventData':
        """Create event data from dictionary"""
        return cls(
            event_type=EventType(data["event_type"]),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            source_service=data["source_service"],
            event_id=data["event_id"],
            priority=EventPriority(data.get("priority", "medium")),
            data=data.get("data", {}),
            correlation_id=data.get("correlation_id"),
            user_id=data.get("user_id")
        )


# Event routing configuration
EVENT_ROUTING = {
    EventCategory.INVENTORY: [
        "inventory-service",
        "compliance-service",
        "report-generator"
    ],
    EventCategory.COMPLIANCE: [
        "compliance-service",
        "alert-engine",
        "report-generator"
    ],
    EventCategory.SECURITY: [
        "data-security-service",
        "alert-engine",
        "compliance-service"
    ],
    EventCategory.ALERT: [
        "alert-engine",
        "report-generator"
    ],
    EventCategory.SYSTEM: [
        "api-gateway",
        "alert-engine"
    ],
    EventCategory.USER: [
        "api-gateway",
        "report-generator"
    ]
}


def get_event_category(event_type: EventType) -> EventCategory:
    """Get the category for an event type"""
    event_name = event_type.value
    
    if event_name.startswith("inventory"):
        return EventCategory.INVENTORY
    elif event_name.startswith("compliance"):
        return EventCategory.COMPLIANCE
    elif event_name.startswith("security"):
        return EventCategory.SECURITY
    elif event_name.startswith("alert"):
        return EventCategory.ALERT
    elif event_name.startswith("system"):
        return EventCategory.SYSTEM
    elif event_name.startswith("user"):
        return EventCategory.USER
    else:
        return EventCategory.SYSTEM  # Default