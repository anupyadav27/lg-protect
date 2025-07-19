#!/usr/bin/env python3
"""
Multi-Client AWS Compliance Scanner

Scans multiple AWS accounts using configuration-based credentials.
Supports shared credentials, access keys, and role assumption.
"""

import sys
import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any

# Add current directory to path
sys.path.insert(0, os.getcwd())

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def scan_single_account(session, account_name: str, regions: List[str], services: List[str]) -> Dict[str, Any]:
    """Scan a single AWS account"""
    print(f"\n🔍 Scanning Account: {account_name}")
    print("=" * 50)
    
    all_findings = []
    
    for region in regions:
        print(f"  🌍 Region: {region}")
        
        for service in services:
            try:
                service_findings = scan_service(session, service, region, account_name)
                all_findings.extend(service_findings)
                
                if service_findings:
                    print(f"    ✅ {service}: {len(service_findings)} findings")
                else:
                    print(f"    ⚪ {service}: No findings")
                    
            except Exception as e:
                print(f"    ❌ {service}: Error - {str(e)[:50]}...")
    
    return all_findings

def scan_service(session, service: str, region: str, account_name: str) -> List[Dict[str, Any]]:
    """Scan a specific AWS service"""
    findings = []
    
    try:
        if service == 'acm':
            findings = scan_acm_service(session, region, account_name)
        elif service == 'accessanalyzer':
            findings = scan_accessanalyzer_service(session, region, account_name)
        elif service == 'account':
            findings = scan_account_service(session, region, account_name)
        elif service == 'iam':
            findings = scan_iam_service(session, region, account_name)
        elif service == 's3':
            findings = scan_s3_service(session, region, account_name)
        elif service == 'ec2':
            findings = scan_ec2_service(session, region, account_name)
        else:
            logger.warning(f"Service {service} not implemented yet")
    
    except Exception as e:
        logger.error(f"Error scanning {service} in {region}: {e}")
    
    return findings

def scan_acm_service(session, region: str, account_name: str) -> List[Dict[str, Any]]:
    """Scan ACM service"""
    findings = []
    
    try:
        acm_client = session.client('acm', region_name=region)
        response = acm_client.list_certificates()
        certificates = response.get('CertificateSummaryList', [])
        
        for cert in certificates:
            # Get certificate details
            cert_response = acm_client.describe_certificate(CertificateArn=cert['CertificateArn'])
            cert_details = cert_response['Certificate']
            
            # Check expiration
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            expiration = cert_details['NotAfter'].replace(tzinfo=timezone.utc)
            days_until_expiration = (expiration - now).days
            
            if days_until_expiration <= 30:
                status = "FAIL"
                status_extended = f"Certificate expires in {days_until_expiration} days"
            else:
                status = "PASS"
                status_extended = f"Certificate expires in {days_until_expiration} days"
            
            finding = {
                'check_name': 'acm_certificates_expiration_check',
                'status': status,
                'status_extended': status_extended,
                'resource': {
                    'certificate_arn': cert['CertificateArn'],
                    'domain_name': cert['DomainName'],
                    'expiration_date': cert_details['NotAfter'].isoformat(),
                    'days_until_expiration': days_until_expiration
                },
                'evidence': {
                    'certificate_id': cert['CertificateArn'].split('/')[-1],
                    'key_algorithm': cert_details.get('KeyAlgorithm', 'Unknown')
                },
                'account_name': account_name,
                'region': region,
                'service': 'acm'
            }
            findings.append(finding)
    
    except Exception as e:
        logger.error(f"Error scanning ACM in {region}: {e}")
    
    return findings

def scan_accessanalyzer_service(session, region: str, account_name: str) -> List[Dict[str, Any]]:
    """Scan Access Analyzer service"""
    findings = []
    
    try:
        accessanalyzer_client = session.client('accessanalyzer', region_name=region)
        response = accessanalyzer_client.list_analyzers()
        analyzers = response.get('analyzers', [])
        
        if not analyzers:
            finding = {
                'check_name': 'accessanalyzer_enabled',
                'status': 'FAIL',
                'status_extended': f'No Access Analyzers found in {region}',
                'resource': {
                    'region': region,
                    'analyzer_status': 'DISABLED'
                },
                'evidence': {
                    'analyzers_found': 0
                },
                'account_name': account_name,
                'region': region,
                'service': 'accessanalyzer'
            }
            findings.append(finding)
        else:
            for analyzer in analyzers:
                finding = {
                    'check_name': 'accessanalyzer_enabled',
                    'status': 'PASS',
                    'status_extended': f"Access Analyzer '{analyzer['name']}' is enabled",
                    'resource': {
                        'analyzer_arn': analyzer['arn'],
                        'analyzer_name': analyzer['name'],
                        'status': analyzer['status']
                    },
                    'evidence': {
                        'analyzer_type': analyzer.get('type', 'Unknown'),
                        'created_at': analyzer.get('createdAt', 'Unknown')
                    },
                    'account_name': account_name,
                    'region': region,
                    'service': 'accessanalyzer'
                }
                findings.append(finding)
    
    except Exception as e:
        logger.error(f"Error scanning Access Analyzer in {region}: {e}")
    
    return findings

def scan_account_service(session, region: str, account_name: str) -> List[Dict[str, Any]]:
    """Scan Account service"""
    findings = []
    
    try:
        # Get account information
        sts_client = session.client('sts')
        identity = sts_client.get_caller_identity()
        
        # Try to get account alternate contacts
        try:
            account_client = session.client('account', region_name=region)
            contacts_response = account_client.get_alternate_contact(AlternateContactType='SECURITY')
            
            finding = {
                'check_name': 'account_security_contact_information_is_registered',
                'status': 'PASS',
                'status_extended': 'Security contact information is registered',
                'resource': {
                    'account_id': identity['Account'],
                    'security_contact_email': contacts_response['AlternateContact'].get('EmailAddress', 'N/A'),
                    'security_contact_phone': contacts_response['AlternateContact'].get('PhoneNumber', 'N/A')
                },
                'evidence': {
                    'contact_info_verified': True
                },
                'account_name': account_name,
                'region': region,
                'service': 'account'
            }
            
        except Exception as e:
            finding = {
                'check_name': 'account_security_contact_information_is_registered',
                'status': 'WARNING',
                'status_extended': f'Could not verify security contact information: {str(e)[:50]}',
                'resource': {
                    'account_id': identity['Account']
                },
                'evidence': {
                    'contact_info_verified': False,
                    'error': str(e)
                },
                'account_name': account_name,
                'region': region,
                'service': 'account'
            }
        
        findings.append(finding)
    
    except Exception as e:
        logger.error(f"Error scanning Account service in {region}: {e}")
    
    return findings

def scan_iam_service(session, region: str, account_name: str) -> List[Dict[str, Any]]:
    """Scan IAM service"""
    findings = []
    
    try:
        iam_client = session.client('iam')
        
        # Check for users without MFA
        response = iam_client.list_users()
        users = response.get('Users', [])
        
        for user in users:
            # Check if user has MFA devices
            mfa_response = iam_client.list_mfa_devices(UserName=user['UserName'])
            mfa_devices = mfa_response.get('MFADevices', [])
            
            if not mfa_devices:
                finding = {
                    'check_name': 'iam_user_mfa_enabled',
                    'status': 'FAIL',
                    'status_extended': f"User {user['UserName']} does not have MFA enabled",
                    'resource': {
                        'user_name': user['UserName'],
                        'user_arn': user['Arn'],
                        'create_date': user['CreateDate'].isoformat()
                    },
                    'evidence': {
                        'mfa_devices_count': 0
                    },
                    'account_name': account_name,
                    'region': region,
                    'service': 'iam'
                }
                findings.append(finding)
    
    except Exception as e:
        logger.error(f"Error scanning IAM service: {e}")
    
    return findings

def scan_s3_service(session, region: str, account_name: str) -> List[Dict[str, Any]]:
    """Scan S3 service"""
    findings = []
    
    try:
        s3_client = session.client('s3')
        
        # List buckets
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        for bucket in buckets:
            try:
                # Check bucket encryption
                encryption_response = s3_client.get_bucket_encryption(Bucket=bucket['Name'])
                finding = {
                    'check_name': 's3_bucket_encryption_enabled',
                    'status': 'PASS',
                    'status_extended': f"Bucket {bucket['Name']} has encryption enabled",
                    'resource': {
                        'bucket_name': bucket['Name'],
                        'creation_date': bucket['CreationDate'].isoformat()
                    },
                    'evidence': {
                        'encryption_enabled': True
                    },
                    'account_name': account_name,
                    'region': region,
                    'service': 's3'
                }
            except Exception:
                finding = {
                    'check_name': 's3_bucket_encryption_enabled',
                    'status': 'FAIL',
                    'status_extended': f"Bucket {bucket['Name']} does not have encryption enabled",
                    'resource': {
                        'bucket_name': bucket['Name'],
                        'creation_date': bucket['CreationDate'].isoformat()
                    },
                    'evidence': {
                        'encryption_enabled': False
                    },
                    'account_name': account_name,
                    'region': region,
                    'service': 's3'
                }
            
            findings.append(finding)
    
    except Exception as e:
        logger.error(f"Error scanning S3 service: {e}")
    
    return findings

def scan_ec2_service(session, region: str, account_name: str) -> List[Dict[str, Any]]:
    """Scan EC2 service"""
    findings = []
    
    try:
        ec2_client = session.client('ec2', region_name=region)
        
        # List instances
        response = ec2_client.describe_instances()
        
        for reservation in response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                # Check if instance has public IP
                if instance.get('PublicIpAddress'):
                    finding = {
                        'check_name': 'ec2_instance_public_ip',
                        'status': 'WARNING',
                        'status_extended': f"Instance {instance['InstanceId']} has public IP {instance['PublicIpAddress']}",
                        'resource': {
                            'instance_id': instance['InstanceId'],
                            'instance_type': instance['InstanceType'],
                            'public_ip': instance['PublicIpAddress'],
                            'state': instance['State']['Name']
                        },
                        'evidence': {
                            'has_public_ip': True
                        },
                        'account_name': account_name,
                        'region': region,
                        'service': 'ec2'
                    }
                    findings.append(finding)
    
    except Exception as e:
        logger.error(f"Error scanning EC2 service in {region}: {e}")
    
    return findings

def main():
    """Main function for multi-client scanning"""
    print("🔍 Multi-Client AWS Compliance Scanner")
    print("=" * 60)
    print("🏗️ Using configuration-based credentials")
    print("🎯 Scanning multiple AWS accounts")
    print("=" * 60)
    
    try:
        # Import configuration manager
        from utils.secret_manager import get_secret_manager
        
        # Initialize configuration manager
        secret_manager = get_secret_manager()
        
        # Validate configuration
        if not secret_manager.validate_configuration():
            print("❌ Configuration validation failed")
            return 1
        
        # Get all profiles
        profiles = secret_manager.get_all_profiles()
        print(f"\n📋 Found {len(profiles)} AWS profiles:")
        for profile in profiles:
            print(f"  • {profile.name} ({profile.type}) - {profile.account_name or 'Unknown'}")
        
        # Get scan configuration
        scan_config = secret_manager.scan_config
        print(f"\n🔧 Scan Configuration:")
        print(f"  • Regions: {', '.join(scan_config.default_regions)}")
        print(f"  • Services: {', '.join(scan_config.services_to_scan)}")
        print(f"  • Max Workers: {scan_config.max_workers}")
        
        # Scan each profile
        all_results = {}
        total_findings = []
        
        for profile in profiles:
            print(f"\n🚀 Scanning Profile: {profile.name}")
            print("-" * 40)
            
            # Create session for this profile
            session = secret_manager.create_boto3_session(profile.name)
            if not session:
                print(f"❌ Failed to create session for profile {profile.name}")
                continue
            
            # Test session
            try:
                sts_client = session.client('sts')
                identity = sts_client.get_caller_identity()
                print(f"✅ Connected to account: {identity['Account']}")
            except Exception as e:
                print(f"❌ Failed to connect to account: {e}")
                continue
            
            # Scan this account
            account_findings = scan_single_account(
                session, 
                profile.account_name or profile.name,
                scan_config.default_regions,
                scan_config.services_to_scan
            )
            
            all_results[profile.name] = {
                'profile': profile,
                'findings': account_findings,
                'account_id': identity['Account']
            }
            
            total_findings.extend(account_findings)
        
        # Generate summary
        print(f"\n📊 Multi-Client Scan Summary")
        print("=" * 60)
        print(f"Accounts Scanned: {len(all_results)}")
        print(f"Total Findings: {len(total_findings)}")
        
        passed = sum(1 for f in total_findings if f['status'] == 'PASS')
        failed = sum(1 for f in total_findings if f['status'] == 'FAIL')
        warnings = sum(1 for f in total_findings if f['status'] == 'WARNING')
        
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"⚠️  Warnings: {warnings}")
        
        if total_findings:
            compliance_score = (passed / len(total_findings)) * 100
            print(f"🎯 Overall Compliance Score: {compliance_score:.1f}%")
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"output/multi_client_scan_{timestamp}.json"
        
        results = {
            'scan_id': f'multi_client_scan_{timestamp}',
            'scan_timestamp': datetime.now().isoformat(),
            'accounts_scanned': len(all_results),
            'total_findings': len(total_findings),
            'summary': {
                'passed': passed,
                'failed': failed,
                'warnings': warnings,
                'compliance_score': compliance_score if total_findings else 0
            },
            'account_results': {
                profile_name: {
                    'account_id': result['account_id'],
                    'account_name': result['profile'].account_name,
                    'findings_count': len(result['findings'])
                }
                for profile_name, result in all_results.items()
            },
            'findings': total_findings
        }
        
        # Ensure output directory exists
        os.makedirs('output', exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n💾 Results saved to: {output_file}")
        
        # Show file content
        print(f"\n📄 Generated File Content:")
        print("-" * 50)
        with open(output_file, 'r') as f:
            print(f.read())
        
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("Make sure all required modules are available")
        return 1
    except Exception as e:
        print(f"❌ Error: {e}")
        logger.error(f"Multi-client scan failed: {e}", exc_info=True)
        return 1
    
    print(f"\n🎉 Multi-client AWS compliance scanning completed successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(main()) 