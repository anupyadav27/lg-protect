#!/usr/bin/env python3
"""
Quick Validation Test - Fast AWS Resource Detection Verification
Tests basic resource detection for key services (S3, DynamoDB, SQS)
Results are saved to timestamped folders for tracking validation history
"""

import boto3
import json
import csv
from pathlib import Path
from datetime import datetime

def create_timestamped_results_folder():
    """Create a timestamped results folder for this test run"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    results_dir = Path(__file__).parent / "results" / f"quick_validation_{timestamp}"
    results_dir.mkdir(parents=True, exist_ok=True)
    return results_dir

def save_validation_results(results_dir, test_results, summary):
    """Save quick validation results to files"""
    # Save test results as JSON
    results_file = results_dir / "validation_results.json"
    with open(results_file, 'w') as f:
        json.dump(test_results, f, indent=2, default=str)
    
    # Save summary as text
    summary_file = results_dir / "validation_summary.txt"
    with open(summary_file, 'w') as f:
        f.write(f"Quick Validation Test Summary - {datetime.now().isoformat()}\n")
        f.write("=" * 50 + "\n")
        for line in summary:
            f.write(f"{line}\n")
    
    # Save results as CSV
    csv_file = results_dir / "validation_results.csv"
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Service', 'Success', 'Resource_Count', 'Sample_Resources', 'Error_Message'])
        
        for service, result in test_results.items():
            sample_resources = '; '.join([str(r) for r in result.get('sample_resources', [])[:3]])
            writer.writerow([
                service,
                result['success'],
                result['resource_count'],
                sample_resources,
                result.get('error', '')
            ])
    
    return results_file, summary_file, csv_file

def quick_test_s3():
    """Quick test for S3 bucket detection"""
    try:
        client = boto3.client('s3', region_name='us-east-1')
        response = client.list_buckets()
        
        if 'Buckets' in response and response['Buckets']:
            buckets = response['Buckets']
            bucket_names = [bucket['Name'] for bucket in buckets]
            return True, len(buckets), bucket_names, None
        else:
            return True, 0, [], None
            
    except Exception as e:
        return False, 0, [], str(e)

def quick_test_dynamodb():
    """Quick test for DynamoDB table detection"""
    try:
        client = boto3.client('dynamodb', region_name='us-east-1')
        response = client.list_tables()
        
        if 'TableNames' in response and response['TableNames']:
            tables = response['TableNames']
            return True, len(tables), tables, None
        else:
            return True, 0, [], None
            
    except Exception as e:
        return False, 0, [], str(e)

def quick_test_sqs():
    """Quick test for SQS queue detection"""
    try:
        client = boto3.client('sqs', region_name='us-east-1')
        response = client.list_queues()
        
        if 'QueueUrls' in response and response['QueueUrls']:
            queues = response['QueueUrls']
            queue_names = [url.split('/')[-1] for url in queues]
            return True, len(queues), queue_names, None
        else:
            return True, 0, [], None
            
    except Exception as e:
        return False, 0, [], str(e)

def quick_test_iam():
    """Quick test for IAM user detection"""
    try:
        client = boto3.client('iam', region_name='us-east-1')
        response = client.list_users()
        
        if 'Users' in response and response['Users']:
            users = response['Users']
            user_names = [user['UserName'] for user in users]
            return True, len(users), user_names, None
        else:
            return True, 0, [], None
            
    except Exception as e:
        return False, 0, [], str(e)

def quick_test_lambda():
    """Quick test for Lambda function detection"""
    try:
        client = boto3.client('lambda', region_name='us-east-1')
        response = client.list_functions()
        
        if 'Functions' in response and response['Functions']:
            functions = response['Functions']
            function_names = [func['FunctionName'] for func in functions]
            return True, len(functions), function_names, None
        else:
            return True, 0, [], None
            
    except Exception as e:
        return False, 0, [], str(e)

def run_quick_validation():
    """Run quick validation tests on key AWS services"""
    test_services = {
        's3': quick_test_s3,
        'dynamodb': quick_test_dynamodb,
        'sqs': quick_test_sqs,
        'iam': quick_test_iam,
        'lambda': quick_test_lambda
    }
    
    results = {}
    summary_lines = []
    
    summary_lines.append("⚡ Quick AWS Resource Detection Validation")
    summary_lines.append("Testing key services for resource detection...")
    
    for service_name, test_func in test_services.items():
        summary_lines.append(f"\n🧪 Testing {service_name.upper()}...")
        
        success, count, resources, error = test_func()
        
        results[service_name] = {
            'success': success,
            'resource_count': count,
            'sample_resources': resources[:5] if resources else [],  # Keep first 5
            'error': error
        }
        
        status = "✅" if success else "❌"
        resource_info = f"({count} resources)" if count > 0 else "(no resources)"
        summary_lines.append(f"   {status} {service_name.upper():<10} {resource_info}")
        
        if success and count > 0:
            # Show sample resources
            for i, resource in enumerate(resources[:3]):  # Show first 3
                summary_lines.append(f"      📋 {i+1}. {resource}")
        elif not success:
            summary_lines.append(f"      ❌ Error: {error}")
    
    return results, summary_lines

if __name__ == "__main__":
    # Create timestamped results folder
    results_dir = create_timestamped_results_folder()
    
    print("⚡ Quick AWS Resource Detection Validation")
    print("=" * 50)
    print(f"📁 Results will be saved to: {results_dir}")
    
    # Run validation tests
    test_results, summary_lines = run_quick_validation()
    
    # Calculate summary statistics
    successful_tests = sum(1 for r in test_results.values() if r['success'])
    services_with_resources = sum(1 for r in test_results.values() if r['resource_count'] > 0)
    total_resources = sum(r['resource_count'] for r in test_results.values())
    total_tests = len(test_results)
    
    # Add final summary
    final_summary = [
        "",
        "📊 QUICK VALIDATION SUMMARY:",
        "=" * 40,
        f"✅ {successful_tests}/{total_tests} API calls successful",
        f"📦 {services_with_resources}/{total_tests} services have resources", 
        f"🔢 {total_resources} total resources found",
        "",
        "🎯 Validation Result:",
    ]
    
    if total_resources > 0:
        final_summary.extend([
            "✅ SUCCESS: Resource detection is working!",
            "💡 The service enablement checker should detect real resources."
        ])
    else:
        final_summary.extend([
            "⚠️  WARNING: No resources found.",
            "   This could mean:",
            "   - Your AWS account has no resources in these services",
            "   - There may be permission issues",
            "   - Resources exist in different regions"
        ])
    
    final_summary.append(f"\n⚡ Quick validation completed!")
    
    # Combine all summary lines
    all_summary = summary_lines + final_summary
    
    # Print final summary to console
    for line in final_summary:
        print(line)
    
    # Save results to files
    results_file, summary_file, csv_file = save_validation_results(results_dir, test_results, all_summary)
    
    print(f"\n📋 Results saved to:")
    print(f"   📄 {results_file}")
    print(f"   📝 {summary_file}")
    print(f"   📊 {csv_file}")