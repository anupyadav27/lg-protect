"""
AWS Kinesis Service Module

Centralized imports for AWS Kinesis compliance checks.
"""

# Import the service class
from .kinesis_service import KinesisService

# Import individual checks
from .kinesis_stream_data_retention_period.kinesis_stream_data_retention_period import kinesis_stream_data_retention_period
from .kinesis_stream_encrypted_at_rest.kinesis_stream_encrypted_at_rest import kinesis_stream_encrypted_at_rest

__all__ = [
    'KinesisService',
    'kinesis_stream_data_retention_period',
    'kinesis_stream_encrypted_at_rest',
]
