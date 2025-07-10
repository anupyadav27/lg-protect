#!/usr/bin/env python3
"""
Test Cases for iso27001_2022_aws - ec2_instance_port_telnet_exposed_to_internet

Comprehensive test coverage for ec2_instance_port_telnet_exposed_to_internet compliance function.
Tests multiple scenarios including compliant, non-compliant, mixed, empty responses, and error conditions.
"""

import unittest
import sys
import os
from unittest.mock import patch, Mock, MagicMock

# Add paths for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '..', '..'))

from services_functions.ec2_instance_port_telnet_exposed_to_internet import (
    ec2_instance_port_telnet_exposed_to_internet,
    ec2_instance_port_telnet_exposed_to_internet_check,
    check_telnet_port_exposure
)

class TestEc2InstancePortTelnetExposedToInternet(unittest.TestCase):
    """Test cases for ec2_instance_port_telnet_exposed_to_internet compliance function."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        
        # Mock security group with telnet exposed to internet
        self.mock_non_compliant_sg = {
            'GroupId': 'sg-12345678',
            'GroupName': 'telnet-exposed-sg',
            'Description': 'Security group with telnet exposed',
            'VpcId': 'vpc-12345678',
            'OwnerId': '123456789012',
            'IpPermissions': [
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 23,
                    'ToPort': 23,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'Open to internet'}],
                    'Ipv6Ranges': [],
                    'UserIdGroupPairs': []
                }
            ]
        }
        
        # Mock security group without telnet exposed
        self.mock_compliant_sg = {
            'GroupId': 'sg-87654321',
            'GroupName': 'secure-sg',
            'Description': 'Secure security group',
            'VpcId': 'vpc-87654321',
            'OwnerId': '123456789012',
            'IpPermissions': [
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
                    'Ipv6Ranges': [],
                    'UserIdGroupPairs': []
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 23,
                    'ToPort': 23,
                    'IpRanges': [{'CidrIp': '10.0.0.0/8'}],  # Private range only
                    'Ipv6Ranges': [],
                    'UserIdGroupPairs': []
                }
            ]
        }
        
        # Mock security group with IPv6 telnet exposure
        self.mock_ipv6_exposed_sg = {
            'GroupId': 'sg-ipv6-123',
            'GroupName': 'ipv6-telnet-sg',
            'Description': 'IPv6 telnet exposed',
            'VpcId': 'vpc-ipv6-123',
            'OwnerId': '123456789012',
            'IpPermissions': [
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 23,
                    'ToPort': 23,
                    'IpRanges': [],
                    'Ipv6Ranges': [{'CidrIpv6': '::/0', 'Description': 'IPv6 open to internet'}],
                    'UserIdGroupPairs': []
                }
            ]
        }
        
        # Mock security group with port range covering telnet
        self.mock_range_exposed_sg = {
            'GroupId': 'sg-range-123',
            'GroupName': 'range-exposed-sg',
            'Description': 'Port range covering telnet',
            'VpcId': 'vpc-range-123',
            'OwnerId': '123456789012',
            'IpPermissions': [
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 20,
                    'ToPort': 25,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
                    'Ipv6Ranges': [],
                    'UserIdGroupPairs': []
                }
            ]
        }

    def test_check_telnet_port_exposure_function(self):
        """Test the helper function for detecting telnet exposure."""
        # Test exposed telnet port
        self.assertTrue(check_telnet_port_exposure(self.mock_non_compliant_sg))
        
        # Test non-exposed telnet port
        self.assertFalse(check_telnet_port_exposure(self.mock_compliant_sg))
        
        # Test IPv6 exposure
        self.assertTrue(check_telnet_port_exposure(self.mock_ipv6_exposed_sg))
        
        # Test port range exposure
        self.assertTrue(check_telnet_port_exposure(self.mock_range_exposed_sg))

    def test_compliant_security_groups(self):
        """Test compliant scenario - no telnet exposure."""
        mock_client = Mock()
        mock_client.describe_security_groups.return_value = {
            'SecurityGroups': [self.mock_compliant_sg]
        }
        
        findings = ec2_instance_port_telnet_exposed_to_internet_check(
            mock_client, 'us-east-1', 'default', self.mock_logger
        )
        
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['status'], 'COMPLIANT')
        self.assertEqual(finding['compliance_status'], 'PASS')
        self.assertEqual(finding['resource_id'], 'sg-87654321')
        self.assertFalse(finding['details']['telnet_exposed_to_internet'])

    def test_non_compliant_security_groups(self):
        """Test non-compliant scenario - telnet exposed to internet."""
        mock_client = Mock()
        mock_client.describe_security_groups.return_value = {
            'SecurityGroups': [self.mock_non_compliant_sg]
        }
        
        findings = ec2_instance_port_telnet_exposed_to_internet_check(
            mock_client, 'us-east-1', 'default', self.mock_logger
        )
        
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['status'], 'NON_COMPLIANT')
        self.assertEqual(finding['compliance_status'], 'FAIL')
        self.assertEqual(finding['resource_id'], 'sg-12345678')
        self.assertTrue(finding['details']['telnet_exposed_to_internet'])
        self.assertEqual(finding['risk_level'], 'HIGH')

    def test_mixed_scenario(self):
        """Test mixed scenario - some compliant, some non-compliant."""
        mock_client = Mock()
        mock_client.describe_security_groups.return_value = {
            'SecurityGroups': [
                self.mock_compliant_sg,
                self.mock_non_compliant_sg,
                self.mock_ipv6_exposed_sg
            ]
        }
        
        findings = ec2_instance_port_telnet_exposed_to_internet_check(
            mock_client, 'us-east-1', 'default', self.mock_logger
        )
        
        self.assertEqual(len(findings), 3)
        
        # Check compliant finding
        compliant_finding = next(f for f in findings if f['resource_id'] == 'sg-87654321')
        self.assertEqual(compliant_finding['status'], 'COMPLIANT')
        
        # Check non-compliant findings
        non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
        self.assertEqual(len(non_compliant_findings), 2)

    def test_empty_response(self):
        """Test empty response - no security groups found."""
        mock_client = Mock()
        mock_client.describe_security_groups.return_value = {
            'SecurityGroups': []
        }
        
        findings = ec2_instance_port_telnet_exposed_to_internet_check(
            mock_client, 'us-east-1', 'default', self.mock_logger
        )
        
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['status'], 'COMPLIANT')
        self.assertEqual(finding['compliance_status'], 'PASS')
        self.assertIn('no-security-groups', finding['resource_id'])
        self.assertEqual(finding['details']['security_groups_count'], 0)

    def test_api_error_handling(self):
        """Test API error handling."""
        mock_client = Mock()
        mock_client.describe_security_groups.side_effect = Exception("API Error: Access Denied")
        
        findings = ec2_instance_port_telnet_exposed_to_internet_check(
            mock_client, 'us-east-1', 'default', self.mock_logger
        )
        
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['status'], 'ERROR')
        self.assertEqual(finding['compliance_status'], 'ERROR')
        self.assertIn('error', finding)
        self.assertIn("API Error: Access Denied", finding['error'])

    def test_edge_cases(self):
        """Test edge cases and malformed data."""
        # Test security group with missing fields
        malformed_sg = {
            'GroupId': 'sg-malformed',
            'IpPermissions': [
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 23,
                    'ToPort': 23,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    # Missing other fields
                }
            ]
        }
        
        mock_client = Mock()
        mock_client.describe_security_groups.return_value = {
            'SecurityGroups': [malformed_sg]
        }
        
        findings = ec2_instance_port_telnet_exposed_to_internet_check(
            mock_client, 'us-east-1', 'default', self.mock_logger
        )
        
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['resource_id'], 'sg-malformed')
        # Should still detect the exposure despite missing fields
        self.assertTrue(finding['details']['telnet_exposed_to_internet'])

    def test_ipv6_exposure_detection(self):
        """Test IPv6 telnet exposure detection."""
        mock_client = Mock()
        mock_client.describe_security_groups.return_value = {
            'SecurityGroups': [self.mock_ipv6_exposed_sg]
        }
        
        findings = ec2_instance_port_telnet_exposed_to_internet_check(
            mock_client, 'us-east-1', 'default', self.mock_logger
        )
        
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['status'], 'NON_COMPLIANT')
        self.assertTrue(finding['details']['telnet_exposed_to_internet'])

    def test_port_range_exposure_detection(self):
        """Test port range covering telnet detection."""
        mock_client = Mock()
        mock_client.describe_security_groups.return_value = {
            'SecurityGroups': [self.mock_range_exposed_sg]
        }
        
        findings = ec2_instance_port_telnet_exposed_to_internet_check(
            mock_client, 'us-east-1', 'default', self.mock_logger
        )
        
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['status'], 'NON_COMPLIANT')
        self.assertTrue(finding['details']['telnet_exposed_to_internet'])

    def test_finding_structure_validation(self):
        """Validate the structure of compliance findings."""
        mock_client = Mock()
        mock_client.describe_security_groups.return_value = {
            'SecurityGroups': [self.mock_compliant_sg]
        }
        
        findings = ec2_instance_port_telnet_exposed_to_internet_check(
            mock_client, 'us-east-1', 'default', self.mock_logger
        )
        
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        
        # Validate required fields
        required_fields = [
            'region', 'profile', 'resource_type', 'resource_id', 
            'status', 'compliance_status', 'risk_level', 'recommendation', 'details'
        ]
        for field in required_fields:
            self.assertIn(field, finding, f"Missing required field: {field}")
        
        # Validate details structure
        details = finding['details']
        self.assertIsInstance(details, dict)
        self.assertIn('security_group_id', details)
        self.assertIn('telnet_exposed_to_internet', details)
        self.assertIn('telnet_port', details)
        self.assertEqual(details['telnet_port'], 23)

    @patch('compliance_engine.ComplianceEngine')
    def test_main_function_integration(self, mock_engine_class):
        """Test main function integration."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine
        mock_engine.run_compliance_check.return_value = {
            'status': 'COMPLETED',
            'findings': [{'status': 'COMPLIANT'}],
            'function_name': 'ec2_instance_port_telnet_exposed_to_internet'
        }
        
        result = ec2_instance_port_telnet_exposed_to_internet(region_name='us-east-1')
        
        self.assertIsInstance(result, dict)
        self.assertEqual(result['function_name'], 'ec2_instance_port_telnet_exposed_to_internet')
        mock_engine.run_compliance_check.assert_called_once()

    def test_logger_usage(self):
        """Test that logger is used appropriately."""
        mock_client = Mock()
        mock_client.describe_security_groups.return_value = {
            'SecurityGroups': [self.mock_compliant_sg, self.mock_non_compliant_sg]
        }
        
        mock_logger = Mock()
        findings = ec2_instance_port_telnet_exposed_to_internet_check(
            mock_client, 'us-east-1', 'default', mock_logger
        )
        
        # Verify logger.info was called with summary information
        mock_logger.info.assert_called()
        info_call_args = mock_logger.info.call_args[0][0]
        self.assertIn("Checked 2 security groups", info_call_args)
        self.assertIn("found 1 with telnet exposed", info_call_args)

if __name__ == '__main__':
    unittest.main(verbosity=2)
