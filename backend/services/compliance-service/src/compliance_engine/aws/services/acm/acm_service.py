"""
ACM Service

Service abstraction for ACM compliance checks.
"""

from datetime import datetime
from typing import Optional, Dict, List, Any
from pydantic import BaseModel
import boto3
import logging

# Import the base service class
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from base import BaseService, ComplianceResult

logger = logging.getLogger(__name__)


class Certificate(BaseModel):
    """ACM certificate model"""
    arn: str
    name: str
    id: str
    type: str
    key_algorithm: str
    tags: Optional[List[Dict[str, str]]] = []
    expiration_days: int
    in_use: bool
    transparency_logging: Optional[bool]
    region: str
    
    # Computed properties
    @property
    def is_expired(self) -> bool:
        """Check if certificate is expired"""
        return self.expiration_days < 0
    
    @property
    def is_expiring_soon(self) -> bool:
        """Check if certificate is expiring within 30 days"""
        return 0 <= self.expiration_days <= 30


class ACMService(BaseService):
    """ACM service that collects certificate data for compliance checks"""
    
    def __init__(self, session: boto3.Session = None, region: str = None):
        super().__init__(session, region)
        self.certificates = {}
    
    def _get_service_name(self) -> str:
        """Get the AWS service name"""
        return 'acm'
    
    def get_all_certificates(self, region: str = None) -> List[Certificate]:
        """
        Get all ACM certificates for the specified region
        
        Args:
            region: AWS region to scan (defaults to service region)
            
        Returns:
            List of Certificate objects
        """
        if not region:
            region = self.region or 'us-east-1'
        
        # Clear existing certificates for this region
        self.certificates = {k: v for k, v in self.certificates.items() if v.region != region}
        
        # Load certificates for this region
        self._load_certificates_for_region(region)
        
        return [cert for cert in self.certificates.values() if cert.region == region]
    
    def _load_certificates_for_region(self, region: str):
        """Load all ACM certificates from AWS for a specific region"""
        try:
            client = self.get_client(region)
            self._list_certificates(client, region)
        except Exception as error:
            logger.error(f"ACM - Error getting certificates from {region}: {error}")
    
    def _list_certificates(self, client, region: str):
        """Get list of certificates from AWS"""
        logger.info(f"ACM - Getting certificates from {region}")
        
        try:
            # Define what key types to include
            includes = {
                "keyTypes": [
                    "RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096",
                    "EC_prime256v1", "EC_secp384r1", "EC_secp521r1",
                ]
            }
            
            # Use pagination to get all certificates
            paginator = client.get_paginator("list_certificates")
            for page in paginator.paginate(Includes=includes):
                for cert_data in page["CertificateSummaryList"]:
                    self._create_certificate(cert_data, region)
                    
        except Exception as error:
            logger.error(f"ACM - Error getting certificates from {region}: {error}")
    
    def _create_certificate(self, cert_data, region: str):
        """Create certificate object from AWS data"""
        # Calculate days until expiration
        expiration_days = self._calculate_expiration_days(cert_data)
        
        # Create certificate object
        certificate = Certificate(
            arn=cert_data["CertificateArn"],
            name=cert_data.get("DomainName", ""),
            id=cert_data["CertificateArn"].split("/")[-1],
            type=cert_data["Type"],
            key_algorithm=cert_data["KeyAlgorithm"],
            expiration_days=expiration_days,
            in_use=cert_data.get("InUse", False),
            transparency_logging=False,  # Will be updated later
            region=region,
        )
        
        # Store in our collection
        self.certificates[certificate.arn] = certificate
        
        # Get additional details
        self._get_certificate_details(certificate)
    
    def _calculate_expiration_days(self, cert_data) -> int:
        """Calculate days until certificate expires"""
        if "NotAfter" not in cert_data:
            return 0
        
        not_after = cert_data["NotAfter"]
        now = datetime.now(not_after.tzinfo if hasattr(not_after, 'tzinfo') else None)
        return (not_after - now).days
    
    def _get_certificate_details(self, certificate):
        """Get detailed information about certificate"""
        try:
            client = self.get_client(certificate.region)
            response = client.describe_certificate(CertificateArn=certificate.arn)
            
            cert_data = response["Certificate"]
            # Update transparency logging status
            certificate.transparency_logging = (
                cert_data["Options"]["CertificateTransparencyLoggingPreference"] == "ENABLED"
            )
            
            # Get tags
            try:
                tags_response = client.list_tags_for_certificate(CertificateArn=certificate.arn)
                certificate.tags = tags_response.get("Tags", [])
            except Exception as error:
                logger.error(f"ACM - Error getting tags for {certificate.arn}: {error}")
            
        except Exception as error:
            logger.error(f"ACM - Error getting details for {certificate.arn}: {error}")
    
    # Utility methods for individual rules (these are NOT compliance checks, just data filters)
    def get_expiring_certificates(self, days: int = 30, region: str = None) -> List[Certificate]:
        """Get certificates expiring within specified days"""
        certificates = self.get_all_certificates(region)
        return [cert for cert in certificates if 0 <= cert.expiration_days <= days]
    
    def get_insecure_certificates(self, insecure_algorithms: List[str], region: str = None) -> List[Certificate]:
        """Get certificates using insecure algorithms"""
        certificates = self.get_all_certificates(region)
        return [cert for cert in certificates if cert.key_algorithm in insecure_algorithms]
    
    def get_certificates_without_transparency(self, region: str = None) -> List[Certificate]:
        """Get certificates without transparency logging enabled"""
        certificates = self.get_all_certificates(region)
        return [cert for cert in certificates if not cert.transparency_logging]