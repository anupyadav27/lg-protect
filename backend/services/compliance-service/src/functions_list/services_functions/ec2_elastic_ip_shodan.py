#!/usr/bin/env python3
"""
iso27001_2022_aws - ec2_elastic_ip_shodan

Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.
"""

import sys
import os
import json
import requests
from typing import Dict, List, Any

# Add the core-engine path to sys.path to import compliance_engine
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from compliance_engine import (
    ComplianceEngine,
    setup_command_line_interface,
    save_results,
    exit_with_status
)

def load_compliance_metadata(function_name: str) -> dict:
    """Load compliance metadata including risk level and recommendation from JSON."""
    try:
        # Path to compliance_checks.json relative to functions_list directory
        compliance_json_path = os.path.join(
            os.path.dirname(__file__), 
            '..', '..', 
            'compliance_checks.json'
        )
        
        with open(compliance_json_path, 'r') as f:
            compliance_data = json.load(f)
        
        # Find the specific compliance entry for this function
        for entry in compliance_data:
            if entry.get('Function Name') == function_name:
                return {
                    'compliance_name': entry.get('Compliance Name', ''),
                    'function_name': entry.get('Function Name', ''),
                    'id': entry.get('ID', ''),
                    'name': entry.get('Name', ''),
                    'description': entry.get('Description', ''),
                    'api_function': entry.get('API function', ''),
                    'user_function': entry.get('user function', ''),
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Monitor and secure Elastic IPs that appear in public internet scanning databases')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'ec2_elastic_ip_shodan',
        'id': 'ISO-27001-2022-A.13.1',
        'name': 'Network Security Management',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client=boto3.client(\'ec2\')',
        'user_function': 'describe_addresses()',
        'risk_level': 'HIGH',
        'recommendation': 'Monitor and secure Elastic IPs that appear in public internet scanning databases'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ec2_elastic_ip_shodan')

def check_ip_exposure_risk(public_ip: str, logger) -> Dict[str, Any]:
    """
    Check if a public IP has potential exposure risks.
    
    Note: This is a simplified implementation that checks basic IP characteristics.
    In a production environment, you would integrate with threat intelligence APIs
    or security scanning services with proper API keys and rate limiting.
    
    Args:
        public_ip: Public IP address to check
        logger: Logger instance
        
    Returns:
        Risk assessment results
    """
    risk_assessment = {
        'ip_address': public_ip,
        'is_routable': True,
        'is_private': False,
        'risk_indicators': [],
        'security_recommendations': []
    }
    
    try:
        # Basic IP validation and classification
        octets = public_ip.split('.')
        if len(octets) != 4:
            risk_assessment['is_routable'] = False
            return risk_assessment
        
        first_octet = int(octets[0])
        second_octet = int(octets[1])
        
        # Check for private IP ranges
        if (first_octet == 10 or 
            (first_octet == 172 and 16 <= second_octet <= 31) or
            (first_octet == 192 and second_octet == 168)):
            risk_assessment['is_private'] = True
            risk_assessment['is_routable'] = False
            return risk_assessment
        
        # Check for other non-routable ranges
        if (first_octet == 127 or  # Loopback
            first_octet == 169 or  # Link-local
            first_octet >= 224):   # Multicast/Reserved
            risk_assessment['is_routable'] = False
            return risk_assessment
        
        # For production use, you would integrate with services like:
        # - Shodan API
        # - VirusTotal API  
        # - IPinfo.io
        # - Threat intelligence feeds
        
        # Simulate basic risk assessment based on IP characteristics
        if first_octet in [104, 185, 188]:  # Common hosting provider ranges
            risk_assessment['risk_indicators'].append('IP in common hosting provider range')
        
        # Add general security recommendations
        risk_assessment['security_recommendations'].extend([
            'Ensure proper security groups are configured',
            'Monitor for unusual traffic patterns',
            'Implement intrusion detection',
            'Regular security scanning of exposed services'
        ])
        
    except ValueError:
        logger.warning(f"Invalid IP address format: {public_ip}")
        risk_assessment['is_routable'] = False
    except Exception as e:
        logger.warning(f"Error assessing IP {public_ip}: {e}")
    
    return risk_assessment

def ec2_elastic_ip_shodan_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_elastic_ip_shodan.
    
    Args:
        ec2_client: Boto3 EC2 client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all Elastic IP addresses
        response = ec2_client.describe_addresses()
        addresses = response.get('Addresses', [])
        
        if not addresses:
            # No Elastic IP addresses found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'ElasticIP',
                'resource_id': f'no-elastic-ips-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No Elastic IP addresses found in this region',
                'details': {
                    'elastic_ips_count': 0,
                    'message': 'No Elastic IP addresses found to check for exposure risks'
                }
            }
            findings.append(finding)
            return findings
        
        # Check each Elastic IP for exposure risks
        high_risk_count = 0
        
        for address in addresses:
            allocation_id = address.get('AllocationId', 'unknown')
            public_ip = address.get('PublicIp', 'unknown')
            instance_id = address.get('InstanceId')
            network_interface_id = address.get('NetworkInterfaceId')
            
            # Perform risk assessment on the public IP
            risk_assessment = check_ip_exposure_risk(public_ip, logger)
            
            # Determine compliance status based on exposure and usage
            is_attached = bool(instance_id or network_interface_id)
            is_routable = risk_assessment['is_routable']
            risk_indicators = risk_assessment['risk_indicators']
            
            # Risk factors:
            # 1. Unattached Elastic IPs are still charged and potentially exposed
            # 2. Public IPs with known risk indicators
            # 3. IPs that might appear in scanning databases
            
            if not is_attached:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = 'MEDIUM'
                recommendation = 'Unattached Elastic IP should be released or attached to a resource'
            elif risk_indicators:
                high_risk_count += 1
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                recommendation = f"Elastic IP has potential exposure risks: {', '.join(risk_indicators)}"
            elif is_routable and is_attached:
                status = 'REVIEW_REQUIRED'
                compliance_status = 'WARN'
                risk_level = 'MEDIUM'
                recommendation = 'Public Elastic IP requires security monitoring and proper access controls'
            else:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                risk_level = 'LOW'
                recommendation = 'Elastic IP appears to have appropriate configuration'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'ElasticIP',
                'resource_id': allocation_id,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': risk_level,
                'recommendation': recommendation,
                'details': {
                    'allocation_id': allocation_id,
                    'public_ip': public_ip,
                    'instance_id': instance_id,
                    'network_interface_id': network_interface_id,
                    'is_attached': is_attached,
                    'is_routable': is_routable,
                    'is_private_ip': risk_assessment['is_private'],
                    'risk_indicators': risk_indicators,
                    'security_recommendations': risk_assessment['security_recommendations'],
                    'domain': address.get('Domain', 'unknown'),
                    'network_border_group': address.get('NetworkBorderGroup', 'unknown'),
                    'public_ipv4_pool': address.get('PublicIpv4Pool', 'unknown'),
                    'tags': address.get('Tags', []),
                    'security_note': 'Public IPs should be monitored for exposure in internet scanning databases and threat intelligence feeds',
                    'monitoring_note': 'Consider implementing continuous monitoring for this public IP address'
                }
            }
            
            findings.append(finding)
        
        logger.info(f"Checked {len(addresses)} Elastic IP addresses, found {high_risk_count} with potential exposure risks")
        
    except Exception as e:
        logger.error(f"Error in ec2_elastic_ip_shodan check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'ElasticIP',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Monitor Elastic IPs for exposure risks'),
            'error': str(e)
        })
        
    return findings

def ec2_elastic_ip_shodan(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_elastic_ip_shodan_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ec2_elastic_ip_shodan(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)
