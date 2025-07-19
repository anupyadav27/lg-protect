"""
Event Router for LG-Protect Event System
Routes events from API Gateway through the event system to appropriate services
"""

import asyncio
import logging
from typing import Dict, List, Set
from datetime import datetime

from .event_types import EventType, EventData, EventCategory, EVENT_ROUTING, get_event_category
from .event_handler import EventHandler

logger = logging.getLogger(__name__)


class EventRouter:
    """
    Central event router that implements the API Gateway → Events → Services pattern
    Routes events to appropriate services based on event type and category
    """
    
    def __init__(self):
        self.service_handlers: Dict[str, EventHandler] = {}
        self.event_subscriptions: Dict[str, Set[EventType]] = {}
        self.routing_rules: Dict[EventCategory, List[str]] = EVENT_ROUTING.copy()
        self.stats = {
            "events_routed": 0,
            "events_failed": 0,
            "services_active": 0
        }
    
    def register_service_handler(self, service_name: str, handler: EventHandler):
        """Register a service handler for event routing"""
        self.service_handlers[service_name] = handler
        self.stats["services_active"] = len(self.service_handlers)
        logger.info(f"🎯 Registered service handler: {service_name}")
    
    def subscribe_service(self, service_name: str, event_types: List[EventType]):
        """Subscribe a service to specific event types"""
        if service_name not in self.event_subscriptions:
            self.event_subscriptions[service_name] = set()
        
        self.event_subscriptions[service_name].update(event_types)
        logger.info(f"📋 Service {service_name} subscribed to {len(event_types)} event types")
    
    def add_routing_rule(self, event_category: EventCategory, target_services: List[str]):
        """Add or update routing rule for an event category"""
        self.routing_rules[event_category] = target_services
        logger.info(f"🛤️ Updated routing rule for {event_category.value} → {target_services}")
    
    async def route_event(self, event_data: EventData) -> Dict[str, bool]:
        """
        Route an event to appropriate services
        Returns a dictionary of service names and whether routing was successful
        """
        results = {}
        
        try:
            # Get target services based on event category
            event_category = get_event_category(event_data.event_type)
            target_services = self._get_target_services(event_data.event_type, event_category)
            
            if not target_services:
                logger.warning(f"⚠️ No target services for event {event_data.event_type.value}")
                return results
            
            # Route to each target service
            routing_tasks = []
            for service_name in target_services:
                if service_name in self.service_handlers:
                    task = self._route_to_service(service_name, event_data)
                    routing_tasks.append((service_name, task))
                else:
                    logger.warning(f"⚠️ Service handler not found: {service_name}")
                    results[service_name] = False
            
            # Execute routing tasks concurrently
            if routing_tasks:
                task_results = await asyncio.gather(
                    *[task for _, task in routing_tasks],
                    return_exceptions=True
                )
                
                for i, (service_name, _) in enumerate(routing_tasks):
                    if isinstance(task_results[i], Exception):
                        logger.error(f"❌ Failed to route to {service_name}: {task_results[i]}")
                        results[service_name] = False
                        self.stats["events_failed"] += 1
                    else:
                        results[service_name] = True
                        self.stats["events_routed"] += 1
            
            logger.info(f"✅ Routed {event_data.event_type.value} to {len([r for r in results.values() if r])} services")
            
        except Exception as e:
            logger.error(f"❌ Error routing event {event_data.event_type.value}: {str(e)}")
            self.stats["events_failed"] += 1
        
        return results
    
    def _get_target_services(self, event_type: EventType, event_category: EventCategory) -> List[str]:
        """Get target services for an event based on routing rules and subscriptions"""
        target_services = set()
        
        # Get services from routing rules
        if event_category in self.routing_rules:
            target_services.update(self.routing_rules[event_category])
        
        # Get services from explicit subscriptions
        for service_name, subscribed_events in self.event_subscriptions.items():
            if event_type in subscribed_events:
                target_services.add(service_name)
        
        return list(target_services)
    
    async def _route_to_service(self, service_name: str, event_data: EventData):
        """Route an event to a specific service"""
        handler = self.service_handlers[service_name]
        await handler.handle_event(event_data)
        logger.debug(f"📤 Routed {event_data.event_type.value} to {service_name}")
    
    def get_routing_stats(self) -> Dict[str, any]:
        """Get routing statistics"""
        return {
            **self.stats,
            "routing_rules": {cat.value: services for cat, services in self.routing_rules.items()},
            "active_services": list(self.service_handlers.keys()),
            "subscriptions": {
                service: [event.value for event in events] 
                for service, events in self.event_subscriptions.items()
            }
        }
    
    def health_check(self) -> Dict[str, any]:
        """Perform health check on the event router"""
        return {
            "status": "healthy" if self.service_handlers else "no_services",
            "services_count": len(self.service_handlers),
            "routing_rules_count": len(self.routing_rules),
            "total_subscriptions": sum(len(events) for events in self.event_subscriptions.values()),
            "last_check": datetime.utcnow().isoformat()
        }


class APIGatewayEventRouter:
    """
    Special router for API Gateway that handles incoming events from external sources
    and routes them into the internal event system
    """
    
    def __init__(self, event_router: EventRouter):
        self.event_router = event_router
        self.external_event_mappings = {}
        self.rate_limits = {}
        
    def map_external_event(self, external_event_type: str, internal_event_type: EventType):
        """Map external event types to internal event types"""
        self.external_event_mappings[external_event_type] = internal_event_type
        logger.info(f"🔗 Mapped external event {external_event_type} → {internal_event_type.value}")
    
    async def process_external_event(self, external_event: Dict[str, any]) -> bool:
        """Process an external event through the API Gateway"""
        try:
            # Extract event type from external event
            external_type = external_event.get("type") or external_event.get("event_type")
            if not external_type:
                logger.error("❌ External event missing type field")
                return False
            
            # Map to internal event type
            if external_type not in self.external_event_mappings:
                logger.warning(f"⚠️ Unknown external event type: {external_type}")
                return False
            
            internal_event_type = self.external_event_mappings[external_type]
            
            # Create internal event data
            event_data = EventData(
                event_type=internal_event_type,
                timestamp=datetime.utcnow(),
                source_service="api-gateway",
                event_id=f"gw_{external_event.get('id', int(datetime.utcnow().timestamp()))}",
                data=external_event.get("data", {}),
                correlation_id=external_event.get("correlation_id"),
                user_id=external_event.get("user_id")
            )
            
            # Route through the event system
            results = await self.event_router.route_event(event_data)
            success_count = len([r for r in results.values() if r])
            
            logger.info(f"🌐 API Gateway processed external event: {external_type} → {success_count} services")
            return success_count > 0
            
        except Exception as e:
            logger.error(f"❌ Error processing external event: {str(e)}")
            return False


# Global event router instance
event_router = EventRouter()
api_gateway_router = APIGatewayEventRouter(event_router)