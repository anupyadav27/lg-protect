"""
Event Handler for LG-Protect Event System
Handles event processing and service-specific event logic
"""

import asyncio
import logging
from typing import Dict, Any, Callable, List
from datetime import datetime

from .event_types import EventType, EventData, EventPriority, get_event_category
from .event_bus import event_bus

logger = logging.getLogger(__name__)


class EventHandler:
    """Central event handler for processing events from API Gateway to Services"""
    
    def __init__(self, service_name: str):
        self.service_name = service_name
        self.event_handlers: Dict[EventType, List[Callable]] = {}
        self.middleware: List[Callable] = []
        
    def register_handler(self, event_type: EventType, handler: Callable):
        """Register a handler for a specific event type"""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)
        logger.info(f"📋 Registered handler for {event_type.value} in {self.service_name}")
    
    def add_middleware(self, middleware: Callable):
        """Add middleware for event processing"""
        self.middleware.append(middleware)
        logger.info(f"🔧 Added middleware to {self.service_name}")
    
    async def handle_event(self, event_data: EventData):
        """Process an incoming event through middleware and handlers"""
        try:
            # Apply middleware
            for middleware in self.middleware:
                event_data = await middleware(event_data)
                if event_data is None:
                    logger.warning(f"⚠️ Event filtered by middleware in {self.service_name}")
                    return
            
            # Route to specific handlers
            if event_data.event_type in self.event_handlers:
                handlers = self.event_handlers[event_data.event_type]
                await asyncio.gather(*[handler(event_data) for handler in handlers])
                logger.info(f"✅ Processed {event_data.event_type.value} event in {self.service_name}")
            else:
                logger.debug(f"🔇 No handlers for {event_data.event_type.value} in {self.service_name}")
                
        except Exception as e:
            logger.error(f"❌ Error handling event {event_data.event_type.value}: {str(e)}")
    
    async def publish_event(self, event_type: EventType, data: Dict[str, Any], 
                          priority: EventPriority = EventPriority.MEDIUM,
                          correlation_id: str = None, user_id: str = None):
        """Publish an event from this service"""
        event_data = EventData(
            event_type=event_type,
            timestamp=datetime.utcnow(),
            source_service=self.service_name,
            event_id=f"{self.service_name}_{int(datetime.utcnow().timestamp())}",
            priority=priority,
            data=data,
            correlation_id=correlation_id,
            user_id=user_id
        )
        
        await event_bus.publish_event(event_data)
        logger.info(f"📤 Published {event_type.value} from {self.service_name}")


# Middleware functions
async def logging_middleware(event_data: EventData) -> EventData:
    """Log all events for debugging"""
    logger.debug(f"🎯 Event: {event_data.event_type.value} from {event_data.source_service}")
    return event_data


async def priority_filter_middleware(min_priority: EventPriority = EventPriority.LOW):
    """Filter events by minimum priority"""
    async def middleware(event_data: EventData) -> EventData:
        priority_order = [EventPriority.LOW, EventPriority.MEDIUM, EventPriority.HIGH, EventPriority.CRITICAL]
        if priority_order.index(event_data.priority) >= priority_order.index(min_priority):
            return event_data
        return None
    return middleware


async def correlation_middleware(event_data: EventData) -> EventData:
    """Add correlation ID if missing"""
    if not event_data.correlation_id:
        event_data.correlation_id = f"auto_{event_data.event_id}"
    return event_data


# Service-specific event handlers
class InventoryEventHandler(EventHandler):
    """Event handler for inventory service"""
    
    def __init__(self):
        super().__init__("inventory-service")
        self._register_inventory_handlers()
    
    def _register_inventory_handlers(self):
        """Register inventory-specific event handlers"""
        self.register_handler(EventType.INVENTORY_SCAN_STARTED, self._handle_scan_started)
        self.register_handler(EventType.COMPLIANCE_POLICY_UPDATED, self._handle_policy_update)
    
    async def _handle_scan_started(self, event_data: EventData):
        """Handle inventory scan started event"""
        logger.info(f"🔍 Starting inventory scan: {event_data.data}")
        # Trigger inventory collection logic
        
    async def _handle_policy_update(self, event_data: EventData):
        """Handle compliance policy update"""
        logger.info(f"📜 Policy updated, re-scanning inventory: {event_data.data}")
        # Trigger re-evaluation of inventory against new policies


class ComplianceEventHandler(EventHandler):
    """Event handler for compliance service"""
    
    def __init__(self):
        super().__init__("compliance-service")
        self._register_compliance_handlers()
    
    def _register_compliance_handlers(self):
        """Register compliance-specific event handlers"""
        self.register_handler(EventType.INVENTORY_DISCOVERED, self._handle_inventory_discovered)
        self.register_handler(EventType.INVENTORY_CHANGED, self._handle_inventory_changed)
    
    async def _handle_inventory_discovered(self, event_data: EventData):
        """Handle new inventory discovery"""
        logger.info(f"🔍 Evaluating compliance for new resource: {event_data.data}")
        # Run compliance checks on new resource
        
    async def _handle_inventory_changed(self, event_data: EventData):
        """Handle inventory changes"""
        logger.info(f"🔄 Re-evaluating compliance for changed resource: {event_data.data}")
        # Re-run compliance checks


class SecurityEventHandler(EventHandler):
    """Event handler for data security service"""
    
    def __init__(self):
        super().__init__("data-security-service")
        self._register_security_handlers()
    
    def _register_security_handlers(self):
        """Register security-specific event handlers"""
        self.register_handler(EventType.INVENTORY_DISCOVERED, self._handle_security_scan)
        self.register_handler(EventType.COMPLIANCE_VIOLATION, self._handle_compliance_violation)
    
    async def _handle_security_scan(self, event_data: EventData):
        """Handle security scanning for new resources"""
        logger.info(f"🔒 Running security scan for: {event_data.data}")
        # Run security analysis
        
    async def _handle_compliance_violation(self, event_data: EventData):
        """Handle compliance violations from security perspective"""
        logger.info(f"⚠️ Analyzing security implications of violation: {event_data.data}")
        # Analyze security impact


class AlertEventHandler(EventHandler):
    """Event handler for alert engine"""
    
    def __init__(self):
        super().__init__("alert-engine")
        self._register_alert_handlers()
    
    def _register_alert_handlers(self):
        """Register alert-specific event handlers"""
        self.register_handler(EventType.COMPLIANCE_VIOLATION, self._handle_violation_alert)
        self.register_handler(EventType.SECURITY_THREAT, self._handle_security_alert)
    
    async def _handle_violation_alert(self, event_data: EventData):
        """Handle compliance violation alerts"""
        logger.info(f"🚨 Creating alert for compliance violation: {event_data.data}")
        # Create and route alert
        
    async def _handle_security_alert(self, event_data: EventData):
        """Handle security threat alerts"""
        logger.info(f"🚨 Creating alert for security threat: {event_data.data}")
        # Create and route security alert