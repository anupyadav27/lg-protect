"""
AWS Firehose Service Module

Centralized imports for AWS Firehose compliance checks.
"""

# Import the service class
from .firehose_service import FirehoseService

# Import individual checks
from .firehose_stream_encrypted_at_rest.firehose_stream_encrypted_at_rest import firehose_stream_encrypted_at_rest

__all__ = [
    'FirehoseService',
    'firehose_stream_encrypted_at_rest',
]
