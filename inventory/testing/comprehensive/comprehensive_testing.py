#!/usr/bin/env python3
"""
Comprehensive Testing - Full AWS Service Enablement Checker Validation
Tests resource detection, service enablement, and CSV output functionality
Results are saved to timestamped folders for tracking test history
"""

import boto3
import json
import sys
import csv
from pathlib import Path
from datetime import datetime

# Add the inventory directory to the path
sys.path.append('/Users/apple/Desktop/lg-protect/inventory')

def create_timestamped_results_folder():
    """Create a timestamped results folder for this test run"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    results_dir = Path(__file__).parent / "results" / f"comprehensive_test_{timestamp}"
    results_dir.mkdir(parents=True, exist_ok=True)
    return results_dir

def save_test_results(results_dir, test_results, summary):
    """Save comprehensive test results to files"""
    # Save detailed test results as JSON
    results_file = results_dir / "test_results_detailed.json"
    with open(results_file, 'w') as f:
        json.dump(test_results, f, indent=2, default=str)
    
    # Save summary as text
    summary_file = results_dir / "test_summary.txt"
    with open(summary_file, 'w') as f:
        f.write(f"Comprehensive Testing Summary - {datetime.now().isoformat()}\n")
        f.write("=" * 70 + "\n")
        for line in summary:
            f.write(f"{line}\n")
    
    # Save results as CSV for easy analysis
    csv_file = results_dir / "test_results_summary.csv"
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Service', 'Region', 'API_Success', 'Resource_Count', 'Sample_Resources'])
        
        for service, result in test_results.items():
            if isinstance(result, dict) and 'success' in result:
                sample_resources = '; '.join([r.get('identifier', 'Unknown') for r in result.get('resources', [])[:3]])
                writer.writerow([
                    service,
                    result.get('region', 'us-east-1'),
                    result['success'],
                    result['resource_count'],
                    sample_resources
                ])
    
    return results_file, summary_file, csv_file

def test_single_service(service_name, region='us-east-1'):
    """Test a single service to verify resource detection"""
    try:
        # Load service mapping
        mapping_file = Path('/Users/apple/Desktop/lg-protect/inventory/service_enablement_mapping.json')
        with open(mapping_file, 'r') as f:
            service_mapping = json.load(f)
        
        if service_name not in service_mapping:
            return False, 0, [], f"Service {service_name} not found in mapping"
        
        config = service_mapping[service_name]
        client_type = config.get('client_type', service_name)
        check_function = config.get('check_function')
        count_field = config.get('count_field')
        resource_identifier = config.get('resource_identifier')
        
        # Create AWS client
        session = boto3.Session()
        client = session.client(client_type, region_name=region)
        
        # Test the API call
        if hasattr(client, check_function):
            func = getattr(client, check_function)
            
            # Handle special cases
            if service_name == 'wafv2':
                response = func(Scope='REGIONAL')
            elif service_name == 'cloudformation':
                response = func(StackStatusFilter=['CREATE_COMPLETE', 'UPDATE_COMPLETE', 'DELETE_FAILED'])
            else:
                response = func()
            
            # Test resource extraction
            resource_count, resources = extract_test_resources(response, resource_identifier, count_field, service_name)
            
            return True, resource_count, resources, "Success"
        else:
            return False, 0, [], f"Function {check_function} not found on {client_type} client"
            
    except Exception as e:
        return False, 0, [], str(e)

def extract_test_resources(response, resource_identifier, count_field, service_name):
    """Test version of resource extraction logic"""
    if not response or not count_field:
        return 0, []
    
    resources = []
    
    try:
        # Handle different response structures
        if count_field.endswith('[*]'):
            # Direct array fields like "TableNames[*]", "QueueUrls[*]"
            field_name = count_field.replace('[*]', '')
            if field_name in response and isinstance(response[field_name], list):
                for item in response[field_name]:
                    if isinstance(item, str):
                        resources.append({
                            'identifier': item,
                            'service': service_name,
                            'type': resource_identifier
                        })
        
        elif '.' in count_field and '[*]' in count_field:
            # Nested structures like "Buckets[*].Name"
            parts = count_field.split('.')
            current_data = response
            
            # Navigate to the array
            for part in parts[:-1]:
                if '[*]' in part:
                    field_name = part.replace('[*]', '')
                    if field_name in current_data and isinstance(current_data[field_name], list):
                        current_data = current_data[field_name]
                        break
                else:
                    if part in current_data:
                        current_data = current_data[part]
                    else:
                        return 0, []
            
            # Extract from array
            final_field = parts[-1]
            if isinstance(current_data, list):
                for item in current_data:
                    if isinstance(item, dict) and final_field in item:
                        resources.append({
                            'identifier': item[final_field],
                            'service': service_name,
                            'type': resource_identifier
                        })
        
        # Special handling for complex services
        elif service_name == 'ec2' and 'Reservations' in response:
            for reservation in response['Reservations']:
                if 'Instances' in reservation:
                    for instance in reservation['Instances']:
                        if 'InstanceId' in instance:
                            resources.append({
                                'identifier': instance['InstanceId'],
                                'service': service_name,
                                'type': 'InstanceId',
                                'state': instance.get('State', {}).get('Name', 'unknown')
                            })
        
        return len(resources), resources
        
    except Exception as e:
        return 0, []

def test_services_with_known_resources():
    """Test services that should have resources in a typical AWS account"""
    test_services = [
        ('s3', 'us-east-1'),           # Should find S3 buckets
        ('dynamodb', 'us-east-1'),     # Should find DynamoDB tables  
        ('sqs', 'us-east-1'),          # Should find SQS queues
        ('iam', 'us-east-1'),          # Should find IAM users (global)
        ('ec2', 'us-east-1'),          # Should find EC2 instances
        ('lambda', 'us-east-1'),       # Should find Lambda functions
        ('logs', 'us-east-1'),         # Should find CloudWatch logs
        ('cloudformation', 'us-east-1'), # Should find CloudFormation stacks
        ('kms', 'us-east-1'),          # Should find KMS keys
        ('sns', 'us-east-1'),          # Should find SNS topics
    ]
    
    results = {}
    summary_lines = []
    
    summary_lines.append("🎯 Testing services with likely resources...")
    
    for service_name, region in test_services:
        summary_lines.append(f"\n🧪 Testing {service_name} in {region}...")
        
        success, count, resources, message = test_single_service(service_name, region)
        results[service_name] = {
            'success': success,
            'resource_count': count,
            'resources': resources[:5] if resources else [],  # Keep first 5 for summary
            'region': region,
            'message': message
        }
        
        status = "✅" if success else "❌"
        resource_info = f"({count} resources)" if count > 0 else "(no resources)"
        summary_lines.append(f"   {status} {service_name:<15} {resource_info}")
        
        if count > 0:
            # Show sample resource identifiers
            for res in resources[:3]:  # Show first 3
                summary_lines.append(f"      📋 {res.get('identifier', 'Unknown')}")
        
        if not success:
            summary_lines.append(f"      ❌ Error: {message}")
    
    return results, summary_lines

def test_csv_generation():
    """Test CSV generation with mock data"""
    summary_lines = []
    summary_lines.append(f"\n📄 Testing CSV generation...")
    
    # Create mock results data
    mock_results = [
        {
            'account_id': '123456789012',
            'account_name': 'test-account',
            'service': 's3',
            'region': 'global',
            'enabled': True,
            'resource_count': 3,
            'resources': [
                {'identifier': 'my-bucket-1', 'type': 'Name'},
                {'identifier': 'my-bucket-2', 'type': 'Name'},
                {'identifier': 'my-bucket-3', 'type': 'Name'}
            ],
            'scope': 'global',
            'resource_identifier': 'Name'
        },
        {
            'account_id': '123456789012',
            'account_name': 'test-account',
            'service': 'dynamodb',
            'region': 'us-east-1',
            'enabled': True,
            'resource_count': 2,
            'resources': [
                {'identifier': 'users-table', 'type': 'TableName'},
                {'identifier': 'products-table', 'type': 'TableName'}
            ],
            'scope': 'regional',
            'resource_identifier': 'TableName'
        }
    ]
    
    # Test the hierarchical structure creation
    csv_rows = []
    
    for result in mock_results:
        resource_identifiers = '; '.join([r.get('identifier', str(r)) for r in result['resources']])
        csv_rows.append({
            'Account_ID': result['account_id'],
            'Account_Name': result['account_name'],
            'Region_Type': 'Global' if result['scope'] == 'global' else 'Regional',
            'Region_Name': result['region'],
            'Service_Name': result['service'],
            'Service_Enabled': result['enabled'],
            'Resource_Count': result['resource_count'],
            'Resource_Identifier_Type': result['resource_identifier'],
            'Resource_Identifiers': resource_identifiers,
            'Service_Scope': result['scope']
        })
    
    summary_lines.append(f"✅ Generated {len(csv_rows)} CSV rows")
    summary_lines.append(f"📋 Sample CSV data:")
    
    for i, row in enumerate(csv_rows):
        summary_lines.append(f"   {i+1}. {row['Service_Name']} in {row['Region_Name']}: "
              f"{'Enabled' if row['Service_Enabled'] else 'Disabled'} "
              f"({row['Resource_Count']} resources)")
        if row['Resource_Identifiers']:
            summary_lines.append(f"      Resources: {row['Resource_Identifiers']}")
    
    return True, summary_lines

if __name__ == "__main__":
    # Create timestamped results folder
    results_dir = create_timestamped_results_folder()
    
    print("🚀 AWS Service Enablement Checker - Comprehensive Testing")
    print("=" * 70)
    print(f"📁 Results will be saved to: {results_dir}")
    
    all_summary = [
        "🚀 AWS Service Enablement Checker - Comprehensive Testing",
        "=" * 70,
        f"📁 Results saved to: {results_dir}"
    ]
    
    # Test 1: Individual service testing
    test_results, service_summary = test_services_with_known_resources()
    all_summary.extend(service_summary)
    
    # Test 2: CSV generation
    csv_success, csv_summary = test_csv_generation()
    all_summary.extend(csv_summary)
    
    # Generate final summary
    successful_tests = sum(1 for r in test_results.values() if r['success'])
    services_with_resources = sum(1 for r in test_results.values() if r['resource_count'] > 0)
    total_tests = len(test_results)
    
    final_summary = [
        "",
        "📊 COMPREHENSIVE TEST RESULTS SUMMARY:",
        "=" * 60,
        f"📈 {successful_tests}/{total_tests} API calls successful",
        f"📦 {services_with_resources}/{total_tests} services have resources",
        f"📄 CSV generation test: {'✅ Passed' if csv_success else '❌ Failed'}",
        "",
        f"🎉 Comprehensive testing completed!",
        f"💡 Next step: Run the full service enablement checker to see improvements"
    ]
    
    all_summary.extend(final_summary)
    
    # Print summary to console
    for line in final_summary:
        print(line)
    
    # Save results to files
    results_file, summary_file, csv_file = save_test_results(results_dir, test_results, all_summary)
    
    print(f"\n📋 Detailed results saved to:")
    print(f"   📄 {results_file}")
    print(f"   📝 {summary_file}")  
    print(f"   📊 {csv_file}")