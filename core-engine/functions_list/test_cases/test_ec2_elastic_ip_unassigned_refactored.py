#!/usr/bin/env python3
"""
Test Cases for AWS Compliance Check: ec2_elastic_ip_unassigned (Refactored)

This file contains test cases for the refactored compliance function using centralized utilities.
"""

import unittest
import sys
import os
from unittest.mock import patch, Mock

# Add paths for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services_functions.ec2_elastic_ip_unassigned import ec2_elastic_ip_unassigned, check_unassigned_elastic_ips

class TestEc2ElasticIpUnassignedRefactored(unittest.TestCase):
    """Test cases for the refactored compliance function."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_unassigned_response = {
            'Addresses': [
                {
                    'AllocationId': 'eipalloc-12345678',
                    'PublicIp': '203.0.113.1',
                    'Domain': 'vpc',
                    'Tags': []
                }
            ]
        }
        
        self.mock_assigned_response = {
            'Addresses': [
                {
                    'AllocationId': 'eipalloc-87654321',
                    'PublicIp': '203.0.113.2',
                    'Domain': 'vpc',
                    'InstanceId': 'i-1234567890abcdef0',
                    'AssociationId': 'eipassoc-12345678',
                    'Tags': []
                }
            ]
        }
    
    def test_check_unassigned_elastic_ips_function(self):
        """Test the core compliance check function."""
        mock_client = Mock()
        mock_client.describe_addresses.return_value = self.mock_unassigned_response
        mock_logger = Mock()
        
        findings = check_unassigned_elastic_ips(mock_client, 'us-east-1', 'default', mock_logger)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['status'], 'NON_COMPLIANT')
        self.assertEqual(findings[0]['risk_level'], 'MEDIUM')
        self.assertTrue(findings[0]['details']['is_unassigned'])
    
    def test_check_assigned_elastic_ips_function(self):
        """Test with assigned Elastic IPs."""
        mock_client = Mock()
        mock_client.describe_addresses.return_value = self.mock_assigned_response
        mock_logger = Mock()
        
        findings = check_unassigned_elastic_ips(mock_client, 'us-east-1', 'default', mock_logger)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['status'], 'COMPLIANT')
        self.assertEqual(findings[0]['risk_level'], 'LOW')
        self.assertFalse(findings[0]['details']['is_unassigned'])
    
    @patch('compliance_utils.load_service_regions')
    @patch('compliance_utils.get_aws_profiles')
    @patch('compliance_utils.create_aws_session')
    def test_main_function(self, mock_session, mock_profiles, mock_regions):
        """Test the main compliance function."""
        # Setup mocks
        mock_regions.return_value = {'ec2': ['us-east-1']}
        mock_profiles.return_value = ['default']
        
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        
        mock_client = Mock()
        mock_client.describe_addresses.return_value = self.mock_unassigned_response
        mock_session_instance.client.return_value = mock_client
        
        # Run test
        result = ec2_elastic_ip_unassigned(region_name='us-east-1')
        
        # Assertions
        self.assertIsInstance(result, dict)
        self.assertIn('status', result)
        self.assertIn('findings', result)
        self.assertEqual(result['function_name'], 'ec2_elastic_ip_unassigned')

if __name__ == '__main__':
    unittest.main()