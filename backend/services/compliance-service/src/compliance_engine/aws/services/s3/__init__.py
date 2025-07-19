"""
AWS S3 Service Module

Centralized imports for AWS S3 compliance checks.
"""

# Import the service class
from .s3_service import S3Service

# Import individual checks
from .s3_access_point_public_access_block.s3_access_point_public_access_block import s3_access_point_public_access_block
from .s3_account_level_public_access_blocks.s3_account_level_public_access_blocks import s3_account_level_public_access_blocks
from .s3_bucket_acl_prohibited.s3_bucket_acl_prohibited import s3_bucket_acl_prohibited
from .s3_bucket_cross_account_access.s3_bucket_cross_account_access import s3_bucket_cross_account_access
from .s3_bucket_cross_region_replication.s3_bucket_cross_region_replication import s3_bucket_cross_region_replication
from .s3_bucket_default_encryption.s3_bucket_default_encryption import s3_bucket_default_encryption
from .s3_bucket_event_notifications_enabled.s3_bucket_event_notifications_enabled import s3_bucket_event_notifications_enabled
from .s3_bucket_kms_encryption.s3_bucket_kms_encryption import s3_bucket_kms_encryption
from .s3_bucket_level_public_access_block.s3_bucket_level_public_access_block import s3_bucket_level_public_access_block
from .s3_bucket_lifecycle_enabled.s3_bucket_lifecycle_enabled import s3_bucket_lifecycle_enabled
from .s3_bucket_no_mfa_delete.s3_bucket_no_mfa_delete import s3_bucket_no_mfa_delete
from .s3_bucket_object_lock.s3_bucket_object_lock import s3_bucket_object_lock
from .s3_bucket_object_versioning.s3_bucket_object_versioning import s3_bucket_object_versioning
from .s3_bucket_policy_public_write_access.s3_bucket_policy_public_write_access import s3_bucket_policy_public_write_access
from .s3_bucket_public_access.s3_bucket_public_access import s3_bucket_public_access
from .s3_bucket_public_list_acl.s3_bucket_public_list_acl import s3_bucket_public_list_acl
from .s3_bucket_public_write_acl.s3_bucket_public_write_acl import s3_bucket_public_write_acl
from .s3_bucket_secure_transport_policy.s3_bucket_secure_transport_policy import s3_bucket_secure_transport_policy
from .s3_bucket_server_access_logging_enabled.s3_bucket_server_access_logging_enabled import s3_bucket_server_access_logging_enabled
from .s3_multi_region_access_point_public_access_block.s3_multi_region_access_point_public_access_block import s3_multi_region_access_point_public_access_block

__all__ = [
    'S3Service',
    's3_access_point_public_access_block',
    's3_account_level_public_access_blocks',
    's3_bucket_acl_prohibited',
    's3_bucket_cross_account_access',
    's3_bucket_cross_region_replication',
    's3_bucket_default_encryption',
    's3_bucket_event_notifications_enabled',
    's3_bucket_kms_encryption',
    's3_bucket_level_public_access_block',
    's3_bucket_lifecycle_enabled',
    's3_bucket_no_mfa_delete',
    's3_bucket_object_lock',
    's3_bucket_object_versioning',
    's3_bucket_policy_public_write_access',
    's3_bucket_public_access',
    's3_bucket_public_list_acl',
    's3_bucket_public_write_acl',
    's3_bucket_secure_transport_policy',
    's3_bucket_server_access_logging_enabled',
    's3_multi_region_access_point_public_access_block',
]
