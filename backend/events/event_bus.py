"""
Redis Event Bus for LG-Protect Microservices
Centralized event publishing and subscription system
"""

import json
import redis
import asyncio
import logging
from typing import Dict, Any, Callable, Optional
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)

class EventType(Enum):
    """Supported event types in the system"""
    INVENTORY_DISCOVERED = "inventory.discovered"
    INVENTORY_CHANGED = "inventory.changed"
    COMPLIANCE_VIOLATION = "compliance.violation"
    COMPLIANCE_RESOLVED = "compliance.resolved"
    SECURITY_THREAT = "security.threat"
    SECURITY_RESOLVED = "security.resolved"
    ALERT_TRIGGERED = "alert.triggered"
    ALERT_RESOLVED = "alert.resolved"

class RedisEventBus:
    """Redis-based event bus for microservice communication"""
    
    def __init__(self, redis_url: str = "redis://redis:6379"):
        self.redis_url = redis_url
        self.redis_client = None
        self.pubsub = None
        self.subscribers: Dict[str, list] = {}
        
    async def connect(self):
        """Connect to Redis"""
        try:
            self.redis_client = redis.from_url(self.redis_url, decode_responses=True)
            self.pubsub = self.redis_client.pubsub()
            logger.info(f"✅ Connected to Redis event bus at {self.redis_url}")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to connect to Redis: {str(e)}")
            return False
    
    async def publish_event(self, event_type: EventType, data: Dict[str, Any], source_service: str):
        """Publish an event to the event bus"""
        try:
            event = {
                "event_type": event_type.value,
                "timestamp": datetime.utcnow().isoformat(),
                "source_service": source_service,
                "data": data,
                "event_id": f"{source_service}_{int(datetime.utcnow().timestamp())}"
            }
            
            # Publish to specific channel and general events channel
            channels = [event_type.value, "events.all"]
            
            for channel in channels:
                await self._publish_to_channel(channel, event)
            
            logger.info(f"📤 Published {event_type.value} event from {source_service}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to publish event: {str(e)}")
            return False
    
    async def _publish_to_channel(self, channel: str, event: Dict[str, Any]):
        """Publish event to a specific Redis channel"""
        if self.redis_client:
            self.redis_client.publish(channel, json.dumps(event))
    
    async def subscribe(self, event_type: EventType, callback: Callable):
        """Subscribe to specific event type"""
        try:
            channel = event_type.value
            if channel not in self.subscribers:
                self.subscribers[channel] = []
            
            self.subscribers[channel].append(callback)
            
            # Subscribe to Redis channel
            await self.pubsub.subscribe(channel)
            logger.info(f"📥 Subscribed to {event_type.value} events")
            
        except Exception as e:
            logger.error(f"❌ Failed to subscribe to {event_type.value}: {str(e)}")
    
    async def listen_for_events(self):
        """Listen for incoming events and route to subscribers"""
        try:
            logger.info("🎧 Starting event listener...")
            
            async for message in self.pubsub.listen():
                if message['type'] == 'message':
                    await self._handle_message(message)
                    
        except Exception as e:
            logger.error(f"❌ Event listener error: {str(e)}")
    
    async def _handle_message(self, message):
        """Handle incoming Redis message"""
        try:
            channel = message['channel']
            data = json.loads(message['data'])
            
            # Route to subscribers
            if channel in self.subscribers:
                for callback in self.subscribers[channel]:
                    try:
                        await callback(data)
                    except Exception as e:
                        logger.error(f"❌ Subscriber callback error: {str(e)}")
            
        except Exception as e:
            logger.error(f"❌ Message handling error: {str(e)}")
    
    async def disconnect(self):
        """Disconnect from Redis"""
        if self.pubsub:
            await self.pubsub.close()
        if self.redis_client:
            self.redis_client.close()
        logger.info("🔌 Disconnected from Redis event bus")

# Global event bus instance
event_bus = RedisEventBus()

# Convenience functions for services
async def publish_inventory_event(event_type: EventType, resource_data: Dict[str, Any]):
    """Publish inventory-related events"""
    await event_bus.publish_event(event_type, resource_data, "inventory-service")

async def publish_compliance_event(event_type: EventType, violation_data: Dict[str, Any]):
    """Publish compliance-related events"""
    await event_bus.publish_event(event_type, violation_data, "compliance-service")

async def publish_security_event(event_type: EventType, threat_data: Dict[str, Any]):
    """Publish security-related events"""
    await event_bus.publish_event(event_type, threat_data, "data-security-service")

async def publish_alert_event(event_type: EventType, alert_data: Dict[str, Any]):
    """Publish alert-related events"""
    await event_bus.publish_event(event_type, alert_data, "alert-engine")