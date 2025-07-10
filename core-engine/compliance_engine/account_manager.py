#!/usr/bin/env python3
"""
Enterprise Account Management Module

Handles multi-account AWS management with credential validation and role assumption.
Separated from compliance_utils for better maintainability.
"""

import boto3
import logging
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import botocore.exceptions


class EnterpriseAccountManager:
    """Advanced multi-account AWS management with credential validation"""
    
    def __init__(self):
        self.accounts = []
        self.account_cache = {}
        
    def add_account(self, name: str, access_key: str = None, secret_key: str = None, 
                   session_token: str = None, profile: str = None, role_arn: str = None, 
                   external_id: str = None) -> bool:
        """Add an AWS account with multiple authentication methods"""
        try:
            # Create session based on authentication method
            if profile:
                session = boto3.Session(profile_name=profile)
            elif role_arn:
                session = self._assume_role_session(role_arn, external_id, access_key, secret_key)
            elif access_key and secret_key:
                session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    aws_session_token=session_token
                )
            else:
                session = boto3.Session()

            # Validate credentials and get account info
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            account_id = identity['Account']
            user_arn = identity.get('Arn', 'Unknown')
            
            # Get enabled regions with caching
            if account_id not in self.account_cache:
                enabled_regions = self._get_enabled_regions(session)
                self.account_cache[account_id] = enabled_regions
            else:
                enabled_regions = self.account_cache[account_id]
            
            account_info = {
                'name': name,
                'account_id': account_id,
                'user_arn': user_arn,
                'session': session,
                'enabled_regions': enabled_regions,
                'auth_method': 'profile' if profile else 'role' if role_arn else 'keys' if access_key else 'default',
                'added_at': datetime.now(timezone.utc).isoformat()
            }
            
            self.accounts.append(account_info)
            return True
            
        except Exception as e:
            logging.error(f"Failed to add account {name}: {str(e)}")
            return False
    
    def _assume_role_session(self, role_arn: str, external_id: str = None, 
                           access_key: str = None, secret_key: str = None) -> boto3.Session:
        """Create session by assuming IAM role"""
        if access_key and secret_key:
            base_session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
        else:
            base_session = boto3.Session()
        
        sts = base_session.client('sts')
        assume_role_kwargs = {
            'RoleArn': role_arn,
            'RoleSessionName': f'ComplianceCheck-{int(time.time())}'
        }
        
        if external_id:
            assume_role_kwargs['ExternalId'] = external_id
        
        response = sts.assume_role(**assume_role_kwargs)
        credentials = response['Credentials']
        
        return boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
    
    def _get_enabled_regions(self, session: boto3.Session) -> List[str]:
        """Get enabled regions with enhanced error handling"""
        try:
            ec2 = session.client('ec2', region_name='us-east-1')
            regions_response = ec2.describe_regions(AllRegions=True)
            enabled_regions = [
                r['RegionName'] for r in regions_response['Regions'] 
                if r['OptInStatus'] in ('opt-in-not-required', 'opted-in')
            ]
            return sorted(enabled_regions)
        except Exception as e:
            logging.warning(f"Could not fetch enabled regions: {str(e)}")
            # Return comprehensive fallback list
            return [
                'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
                'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
                'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
                'ap-south-1', 'ca-central-1', 'sa-east-1'
            ]


def get_account_manager_from_profiles(profiles: List[str] = None) -> EnterpriseAccountManager:
    """
    Create an EnterpriseAccountManager from AWS profiles.
    
    Args:
        profiles (List[str]): List of AWS profile names
        
    Returns:
        EnterpriseAccountManager: Configured account manager
    """
    from .aws_session_manager import get_aws_profiles
    
    account_manager = EnterpriseAccountManager()
    
    if not profiles:
        profiles = get_aws_profiles()
    
    for profile in profiles:
        success = account_manager.add_account(profile, profile=profile)
        if success:
            logging.info(f"Added account for profile: {profile}")
        else:
            logging.warning(f"Failed to add account for profile: {profile}")
    
    return account_manager