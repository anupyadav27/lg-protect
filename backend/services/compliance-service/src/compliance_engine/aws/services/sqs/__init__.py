"""
AWS Sqs Service Module

Centralized imports for AWS Sqs compliance checks.
"""

# Import the service class
from .sqs_service import SQSService

# Import individual checks
from .sqs_queues_not_publicly_accessible.sqs_queues_not_publicly_accessible import sqs_queues_not_publicly_accessible
from .sqs_queues_server_side_encryption_enabled.sqs_queues_server_side_encryption_enabled import sqs_queues_server_side_encryption_enabled

__all__ = [
    'SQSService',
    'sqs_queues_not_publicly_accessible',
    'sqs_queues_server_side_encryption_enabled',
]
