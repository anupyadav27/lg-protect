#!/usr/bin/env python3
"""
Script to extract unique AWS service names from check functions and populate the applied_services column
in the compliance CSV file. Ensures no duplicate services per unique_id and marks manual checks as "manual".
"""

import csv
import json
import re
from collections import defaultdict

def extract_service_from_check(check_function):
    """
    Extract the AWS service name from a check function name.
    
    Args:
        check_function (str): The check function name
        
    Returns:
        str: The AWS service name or None if not found
    """
    if not check_function:
        return None
    
    # Handle special cases first
    special_mappings = {
        'awslambda': 'lambda',
        'opensearch_service': 'opensearch',
        'account_': 'account',
        'accessanalyzer': 'accessanalyzer'
    }
    
    for prefix, service in special_mappings.items():
        if check_function.startswith(prefix):
            return service
    
    # Extract the first part of the function name (service prefix)
    parts = check_function.split('_')
    if len(parts) > 0:
        potential_service = parts[0]
        
        # Handle compound service names like 'elbv2', 'apigateway', etc.
        compound_services = {
            'elbv2', 'apigateway', 'apigatewayv2', 'cloudtrail', 
            'cloudwatch', 'cloudfront', 'codebuild', 'dynamodb',
            'guardduty', 'securityhub', 'secretsmanager', 'sagemaker',
            'stepfunctions', 'datasync', 'elasticache', 'elasticsearch',
            'elasticbeanstalk', 'networkfirewall', 'wafv2'
        }
        
        if potential_service in compound_services:
            return potential_service
        
        return potential_service
    
    return None

def parse_checks_column(checks_str):
    """
    Parse the Checks column which contains a JSON array of check functions.
    
    Args:
        checks_str (str): The checks column value
        
    Returns:
        list: List of check function names
    """
    if not checks_str or checks_str.strip() == '':
        return []
    
    try:
        # Parse JSON array
        checks = json.loads(checks_str)
        return checks if isinstance(checks, list) else []
    except json.JSONDecodeError:
        return []

def extract_unique_services_from_row(row):
    """
    Extract all unique services from a row's check functions.
    If no checks exist, return ["manual"].
    
    Args:
        row (dict): CSV row as dictionary
        
    Returns:
        list: Sorted list of unique service names or ["manual"] if no checks
    """
    checks = parse_checks_column(row.get('Checks', ''))
    
    # If no checks exist, mark as manual
    if not checks:
        return ["manual"]
    
    services = set()  # Using set to automatically handle uniqueness
    
    for check in checks:
        service = extract_service_from_check(check)
        if service:
            services.add(service)
    
    # If checks exist but no services were extracted, still mark as manual
    if not services:
        return ["manual"]
    
    return sorted(list(services))

def main():
    input_file = '/Users/apple/Desktop/lg-protect/backend/services/compliance-service/config/compliance_checks_from_json.csv'
    output_file = '/Users/apple/Desktop/lg-protect/backend/services/compliance-service/config/compliance_checks_updated.csv'
    
    # Statistics
    stats = {
        'total_rows': 0,
        'rows_updated': 0,
        'rows_already_populated': 0,
        'rows_marked_manual': 0,
        'service_counts': defaultdict(int),
        'unique_services': set()
    }
    
    # Read and process the CSV
    with open(input_file, 'r', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        rows = []
        
        for row in reader:
            stats['total_rows'] += 1
            
            # Check if applied_services is already populated - handle None values
            existing_services = row.get('applied_services')
            if existing_services is not None:
                existing_services = existing_services.strip()
            else:
                existing_services = ''
            
            if existing_services and existing_services != '':
                stats['rows_already_populated'] += 1
                # Parse existing services to count them
                try:
                    existing_service_list = json.loads(existing_services)
                    if isinstance(existing_service_list, list):
                        for service in existing_service_list:
                            stats['service_counts'][service] += 1
                            stats['unique_services'].add(service)
                except json.JSONDecodeError:
                    pass
                rows.append(row)
                continue
            
            # Extract unique services from check functions
            services = extract_unique_services_from_row(row)
            
            if services == ["manual"]:
                stats['rows_marked_manual'] += 1
                stats['service_counts']['manual'] += 1
                stats['unique_services'].add('manual')
            else:
                stats['rows_updated'] += 1
                # Count unique services
                for service in services:
                    stats['service_counts'][service] += 1
                    stats['unique_services'].add(service)
            
            row['applied_services'] = json.dumps(services)
            rows.append(row)
    
    # Write the updated CSV
    with open(output_file, 'w', encoding='utf-8', newline='') as outfile:
        if rows:
            writer = csv.DictWriter(outfile, fieldnames=reader.fieldnames)
            writer.writeheader()
            writer.writerows(rows)
    
    # Print statistics
    print(f"Processing completed!")
    print(f"Total rows processed: {stats['total_rows']}")
    print(f"Rows already populated: {stats['rows_already_populated']}")
    print(f"Rows updated with services: {stats['rows_updated']}")
    print(f"Rows marked as manual: {stats['rows_marked_manual']}")
    print(f"Total unique services found: {len(stats['unique_services'])}")
    print(f"\nTop 15 most common services:")
    
    sorted_services = sorted(stats['service_counts'].items(), key=lambda x: x[1], reverse=True)
    for service, count in sorted_services[:15]:
        print(f"  {service}: {count}")
    
    print(f"\nAll unique services identified:")
    for service in sorted(stats['unique_services']):
        print(f"  - {service}")
    
    print(f"\nUpdated file saved as: {output_file}")
    
    # Also create a summary of unique services per compliance row
    print(f"\nSample of extracted unique services:")
    sample_count = 0
    with open(output_file, 'r', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            applied_services = row.get('applied_services')
            if applied_services and applied_services.strip() and sample_count < 10:
                unique_key = row.get('unique_key', 'N/A')
                print(f"  {unique_key}: {applied_services}")
                sample_count += 1

    # Count validation summary
    print(f"\nValidation Summary:")
    manual_count = stats['service_counts'].get('manual', 0)
    automated_count = stats['total_rows'] - stats['rows_already_populated'] - manual_count
    print(f"  Total entries with automated checks: {automated_count}")
    print(f"  Total entries marked as manual: {manual_count}")
    print(f"  Total entries already populated: {stats['rows_already_populated']}")
    print(f"  Grand total: {stats['total_rows']}")

if __name__ == "__main__":
    main()