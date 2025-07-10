#!/usr/bin/env python3
"""
AWS Compliance Engine Generator
Reads compliance_checks.csv and generates individual compliance check files
"""

import csv
import json
import os
from pathlib import Path
from collections import defaultdict

# Global services mapping
GLOBAL_SERVICES = {
    'iam': 'us-east-1',
    'organizations': 'us-east-1',
    'route53': 'us-east-1',
    's3': 'us-east-1',
    'cloudfront': 'us-east-1',
    'waf': 'us-east-1',
    'wafv2': 'us-east-1',
    'shield': 'us-east-1',
    'support': 'us-east-1',
    'budgets': 'us-east-1',
    'ce': 'us-east-1',
    'artifact': 'us-east-1',
    'account': 'us-east-1'
}

def create_service_regions_file():
    """Create the service-regions.json file with AWS regions mapping"""
    service_regions = {
        "ec2": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-south-1", "ca-central-1", "sa-east-1"],
        "rds": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "lambda": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "cloudtrail": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "cloudwatch": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "logs": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "ssm": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "apigateway": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "dynamodb": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "efs": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "elb": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "elbv2": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "emr": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "opensearch": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "es": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "guardduty": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "kms": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "redshift": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "sagemaker": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "secretsmanager": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "securityhub": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "sns": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "config": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "codebuild": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "dax": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1"],
        "backup": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        "acm": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1", "sa-east-1"],
        
        # Global services (single region)
        "iam": ["us-east-1"],
        "s3": ["us-east-1"], 
        "cloudfront": ["us-east-1"],
        "waf": ["us-east-1"],
        "wafv2": ["us-east-1"],
        "organizations": ["us-east-1"],
        "route53": ["us-east-1"],
        "shield": ["us-east-1"],
        "support": ["us-east-1"],
        "budgets": ["us-east-1"],
        "ce": ["us-east-1"],
        "artifact": ["us-east-1"],
        "account": ["us-east-1"]
    }
    
    functions_list_dir = Path("functions_list")
    functions_list_dir.mkdir(exist_ok=True)
    
    service_regions_file = functions_list_dir / "service-regions.json"
    with open(service_regions_file, 'w') as f:
        json.dump(service_regions, f, indent=2)
    
    print(f"✅ Created {service_regions_file}")
    return service_regions

def extract_service_from_function_name(function_name):
    """Extract AWS service from function name"""
    # Common patterns in function names
    if function_name.startswith('ec2_'):
        return 'ec2'
    elif function_name.startswith('rds_'):
        return 'rds'
    elif function_name.startswith('s3_'):
        return 's3'
    elif function_name.startswith('iam_'):
        return 'iam'
    elif function_name.startswith('cloudtrail_'):
        return 'cloudtrail'
    elif function_name.startswith('cloudwatch_'):
        return 'cloudwatch'
    elif function_name.startswith('lambda_') or function_name.startswith('awslambda_'):
        return 'lambda'
    elif function_name.startswith('apigateway_'):
        return 'apigateway'
    elif function_name.startswith('dynamodb_'):
        return 'dynamodb'
    elif function_name.startswith('efs_'):
        return 'efs'
    elif function_name.startswith('elb_') and not function_name.startswith('elbv2_'):
        return 'elb'
    elif function_name.startswith('elbv2_'):
        return 'elbv2'
    elif function_name.startswith('emr_'):
        return 'emr'
    elif function_name.startswith('opensearch_'):
        return 'opensearch'
    elif function_name.startswith('guardduty_'):
        return 'guardduty'
    elif function_name.startswith('kms_'):
        return 'kms'
    elif function_name.startswith('redshift_'):
        return 'redshift'
    elif function_name.startswith('sagemaker_'):
        return 'sagemaker'
    elif function_name.startswith('secretsmanager_'):
        return 'secretsmanager'
    elif function_name.startswith('securityhub_'):
        return 'securityhub'
    elif function_name.startswith('sns_'):
        return 'sns'
    elif function_name.startswith('ssm_'):
        return 'ssm'
    elif function_name.startswith('config_'):
        return 'config'
    elif function_name.startswith('codebuild_'):
        return 'codebuild'
    elif function_name.startswith('dax_'):
        return 'dax'
    elif function_name.startswith('vpc_'):
        return 'ec2'  # VPC functions use EC2 client
    elif 'log_' in function_name or 'logs_' in function_name:
        return 'logs'
    elif 'backup' in function_name:
        return 'backup'
    elif function_name.startswith('acm_'):
        return 'acm'
    else:
        # Default to the first part of the function name
        return function_name.split('_')[0]

def get_regions_for_service(service_name, service_regions):
    """Get regions for a specific service"""
    if service_name in GLOBAL_SERVICES:
        return [GLOBAL_SERVICES[service_name]]
    
    return service_regions.get(service_name, [
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
        "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1",
        "ca-central-1", "sa-east-1"
    ])

def clean_api_function(api_function):
    """Clean and format API function string"""
    # Remove quotes and extra spaces
    cleaned = api_function.strip().strip('"').strip("'")
    # Handle multiple clients
    if ',' in cleaned and 'client' in cleaned:
        clients = []
        for part in cleaned.split(','):
            part = part.strip()
            if 'client' in part:
                clients.append(part)
        return ', '.join(clients)
    return cleaned

def clean_user_function(user_function):
    """Clean and format user function string"""
    # Remove quotes and extra spaces
    cleaned = user_function.strip().strip('"').strip("'")
    # Remove trailing commas
    cleaned = cleaned.rstrip(',')
    return cleaned

def generate_compliance_template(compliance_data, service_regions):
    """Generate compliance check template for a specific function"""
    
    # Extract service from function name
    service_name = extract_service_from_function_name(compliance_data['Function Name'])
    regions = get_regions_for_service(service_name, service_regions)
    
    # Clean API and user functions
    api_function = clean_api_function(compliance_data['API function'])
    user_function = clean_user_function(compliance_data['user function'])
    
    template = f'''#!/usr/bin/env python3
"""
AWS Compliance Engine - {compliance_data['Function Name']}

Compliance Name: {compliance_data['Compliance Name']}
ID: {compliance_data['ID']}
Name: {compliance_data['Name']}
Description: {compliance_data['Description']}
Function Name: {compliance_data['Function Name']}
API function: {api_function}
User function: {user_function}
"""

import boto3
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

# Global services configuration
GLOBAL_SERVICES = {{
    'iam': 'us-east-1',
    'organizations': 'us-east-1',
    'route53': 'us-east-1',
    's3': 'us-east-1',
    'cloudfront': 'us-east-1',
    'waf': 'us-east-1',
    'wafv2': 'us-east-1',
    'shield': 'us-east-1',
    'support': 'us-east-1',
    'budgets': 'us-east-1',
    'ce': 'us-east-1',
    'artifact': 'us-east-1',
    'account': 'us-east-1'
}}

class {compliance_data['Function Name'].title().replace('_', '')}Checker:
    """
    AWS Compliance Checker for {compliance_data['Function Name']}
    
    Compliance Details:
    - Compliance Name: {compliance_data['Compliance Name']}
    - ID: {compliance_data['ID']}
    - Name: {compliance_data['Name']}
    - Description: {compliance_data['Description']}
    - Function Name: {compliance_data['Function Name']}
    - API function: {api_function}
    - User function: {user_function}
    """
    
    def __init__(self, session: Optional[boto3.Session] = None):
        """Initialize the compliance checker"""
        self.session = session or boto3.Session()
        self.service_name = "{service_name}"
        self.function_name = "{compliance_data['Function Name']}"
        self.compliance_name = "{compliance_data['Compliance Name']}"
        self.compliance_id = "{compliance_data['ID']}"
        self.regions = {regions}
        
    def get_client(self, region: str = None):
        """Get AWS client for the service"""
        if self.service_name in GLOBAL_SERVICES:
            region = GLOBAL_SERVICES[self.service_name]
        elif region is None:
            region = 'us-east-1'
            
        return self.session.client(self.service_name, region_name=region)
    
    def check_compliance_single_region(self, region: str) -> Dict[str, Any]:
        """
        Check compliance for a single region
        
        Args:
            region: AWS region to check
            
        Returns:
            Dictionary containing compliance check results
        """
        try:
            # {api_function}
            client = self.get_client(region)
            
            # TODO: Implement the specific compliance check logic here
            # This is a template - you need to implement the actual check logic
            # based on the user function: {user_function}
            
            result = {{
                'region': region,
                'service': self.service_name,
                'function': self.function_name,
                'compliance_name': self.compliance_name,
                'compliance_id': self.compliance_id,
                'compliant': False,  # TODO: Set based on actual check
                'findings': [],      # TODO: Add specific findings
                'resources': [],     # TODO: Add affected resources
                'timestamp': datetime.utcnow().isoformat(),
                'error': None
            }}
            
            # Example implementation (replace with actual logic):
            # response = client.{user_function.split('(')[0] if '(' in user_function else user_function}()
            # Process response and set compliance status
            
            return result
            
        except Exception as e:
            return {{
                'region': region,
                'service': self.service_name,
                'function': self.function_name,
                'compliance_name': self.compliance_name,
                'compliance_id': self.compliance_id,
                'compliant': False,
                'findings': [],
                'resources': [],
                'timestamp': datetime.utcnow().isoformat(),
                'error': str(e)
            }}
    
    def check_compliance_all_regions(self) -> List[Dict[str, Any]]:
        """
        Check compliance across all applicable regions
        
        Returns:
            List of compliance check results for each region
        """
        results = []
        
        for region in self.regions:
            result = self.check_compliance_single_region(region)
            results.append(result)
            
        return results
    
    def generate_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive compliance report
        
        Returns:
            Dictionary containing complete compliance report
        """
        results = self.check_compliance_all_regions()
        
        # Aggregate results
        total_regions = len(results)
        compliant_regions = len([r for r in results if r['compliant']])
        non_compliant_regions = total_regions - compliant_regions
        errors = [r for r in results if r['error']]
        
        report = {{
            'compliance_check': {{
                'name': self.compliance_name,
                'id': self.compliance_id,
                'function': self.function_name,
                'service': self.service_name,
                'description': "{compliance_data['Description']}"
            }},
            'summary': {{
                'total_regions_checked': total_regions,
                'compliant_regions': compliant_regions,
                'non_compliant_regions': non_compliant_regions,
                'compliance_percentage': (compliant_regions / total_regions * 100) if total_regions > 0 else 0,
                'errors_encountered': len(errors)
            }},
            'detailed_results': results,
            'recommendations': self._get_recommendations(results),
            'generated_at': datetime.utcnow().isoformat()
        }}
        
        return report
    
    def _get_recommendations(self, results: List[Dict[str, Any]]) -> List[str]:
        """
        Generate recommendations based on compliance check results
        
        Args:
            results: List of compliance check results
            
        Returns:
            List of recommendation strings
        """
        recommendations = []
        
        non_compliant = [r for r in results if not r['compliant'] and not r['error']]
        errors = [r for r in results if r['error']]
        
        if non_compliant:
            recommendations.append(
                f"Address compliance issues in {{len(non_compliant)}} regions: "
                f"{{', '.join([r['region'] for r in non_compliant])}}"
            )
        
        if errors:
            recommendations.append(
                f"Investigate errors in {{len(errors)}} regions: "
                f"{{', '.join([r['region'] for r in errors])}}"
            )
        
        # Add specific recommendations based on the compliance check type
        recommendations.extend(self._get_specific_recommendations())
        
        return recommendations
    
    def _get_specific_recommendations(self) -> List[str]:
        """
        Get specific recommendations for this compliance check
        
        Returns:
            List of specific recommendation strings
        """
        # TODO: Add specific recommendations based on the compliance check
        # This depends on the specific compliance rule being checked
        return [
            f"Review {self.service_name} configuration in all regions",
            f"Ensure {self.function_name} compliance requirements are met",
            "Implement automated remediation where possible"
        ]

def main():
    """Main execution function"""
    print(f"🔍 AWS Compliance Check: {{'{compliance_data['Function Name']}'}}")
    print(f"📋 Compliance: {{'{compliance_data['Compliance Name']}'}} - {{'{compliance_data['ID']}'}}")
    print(f"📝 Description: {{'{compliance_data['Description']}'}}")
    print(f"🔧 Service: {service_name}")
    print(f"🌍 Regions: {len(regions)} regions")
    print()
    
    # Initialize checker
    checker = {compliance_data['Function Name'].title().replace('_', '')}Checker()
    
    # Generate report
    print("⏳ Running compliance checks...")
    report = checker.generate_report()
    
    # Display summary
    print(f"\\n📊 COMPLIANCE SUMMARY:")
    print(f"   Total Regions: {{report['summary']['total_regions_checked']}}")
    print(f"   Compliant: {{report['summary']['compliant_regions']}}")
    print(f"   Non-Compliant: {{report['summary']['non_compliant_regions']}}")
    print(f"   Compliance Rate: {{report['summary']['compliance_percentage']:.1f}}%")
    print(f"   Errors: {{report['summary']['errors_encountered']}}")
    
    # Save report
    output_file = f"compliance_report_{{'{compliance_data['Function Name']}'}}_{{{datetime.now().strftime('%Y%m%d_%H%M%S')}}}.json"
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\\n💾 Report saved to: {{output_file}}")
    
    # Display recommendations
    if report['recommendations']:
        print(f"\\n💡 RECOMMENDATIONS:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"   {{i}}. {{rec}}")

if __name__ == "__main__":
    main()
'''
    
    return template

def read_compliance_csv(csv_file_path):
    """Read and parse the compliance CSV file"""
    compliance_data = []
    
    try:
        with open(csv_file_path, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if row['Function Name'].strip():  # Skip empty rows
                    compliance_data.append(row)
        
        print(f"✅ Successfully read {len(compliance_data)} compliance checks from CSV")
        return compliance_data
        
    except FileNotFoundError:
        print(f"❌ CSV file not found: {csv_file_path}")
        return []
    except Exception as e:
        print(f"❌ Error reading CSV file: {e}")
        return []

def main():
    """Main execution function"""
    print("🚀 AWS Compliance Engine Generator")
    print("📋 Creating compliance check files from CSV data")
    print()
    
    # Define paths
    current_dir = Path.cwd()
    csv_file = current_dir / "compliance_checks.csv"
    output_dir = current_dir / "generated_compliance_checks"
    
    # Create output directory
    output_dir.mkdir(exist_ok=True)
    
    # Create service-regions.json file
    print("📂 Creating service-regions.json file...")
    service_regions = create_service_regions_file()
    
    # Read CSV data
    print(f"📖 Reading compliance data from {csv_file}...")
    compliance_data = read_compliance_csv(csv_file)
    
    if not compliance_data:
        print("❌ No compliance data found. Exiting.")
        return
    
    # Group by function name and take top 5 rows for now
    function_groups = defaultdict(list)
    for row in compliance_data:
        function_name = row['Function Name'].strip()
        if function_name:
            function_groups[function_name].append(row)
    
    print(f"📊 Found {len(function_groups)} unique function names")
    print(f"🔢 Processing top 5 function groups (as requested)")
    
    # Process top 5 function names
    processed_count = 0
    for function_name, rows in list(function_groups.items())[:5]:
        print(f"\\n🔧 Processing: {function_name}")
        
        # Use the first row for the function (they should have same function details)
        primary_row = rows[0]
        
        # Generate compliance template
        template = generate_compliance_template(primary_row, service_regions)
        
        # Write to file
        output_file = output_dir / f"{function_name}.py"
        with open(output_file, 'w') as f:
            f.write(template)
        
        print(f"   ✅ Created: {output_file}")
        print(f"   📋 Compliance: {primary_row['Compliance Name']} - {primary_row['ID']}")
        print(f"   📝 Description: {primary_row['Description'][:80]}...")
        
        processed_count += 1
    
    print(f"\\n🎉 Successfully generated {processed_count} compliance check files!")
    print(f"📂 Output directory: {output_dir}")
    print(f"📋 Service regions file: functions_list/service-regions.json")
    
    # Display summary of created files
    print(f"\\n📁 GENERATED FILES:")
    for file_path in sorted(output_dir.glob("*.py")):
        print(f"   📄 {file_path.name}")

if __name__ == "__main__":
    main()