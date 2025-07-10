#!/usr/bin/env python3
"""
Compliance Checks vs Inventory Mapping Analysis
This script analyzes the compliance_checks.csv file and compares it with the inventory_functions_mapping.json
to ensure all services, functions, and API calls are properly covered for comprehensive inventory collection.
"""

import csv
import json
import os
import re
from collections import defaultdict, Counter
from typing import Dict, List, Set, Tuple

def parse_api_functions(api_function_str: str) -> List[str]:
    """Extract individual API function calls from the API function string."""
    if not api_function_str:
        return []
    
    # Handle cases like "client = boto3.client('ec2'), client = boto3.client('ssm')"
    services = []
    
    # Extract service names from boto3.client() calls
    service_pattern = r"boto3\.client\(['\"]([^'\"]+)['\"]\)"
    matches = re.findall(service_pattern, api_function_str)
    services.extend(matches)
    
    return services

def parse_user_functions(user_function_str: str) -> List[str]:
    """Extract individual user function calls from the user function string."""
    if not user_function_str:
        return []
    
    # Split by comma and clean up
    functions = []
    parts = user_function_str.split(',')
    
    for part in parts:
        part = part.strip()
        # Remove parentheses and parameters
        if '(' in part:
            func_name = part.split('(')[0].strip()
            functions.append(func_name)
        elif part:
            functions.append(part)
    
    return functions

def analyze_compliance_checks(csv_file_path: str) -> Dict:
    """Analyze the compliance checks CSV file and extract all services and functions."""
    
    compliance_data = {
        'services': defaultdict(list),  # service -> list of functions
        'function_names': [],       # all compliance function names
        'api_functions': defaultdict(list),  # service -> list of API functions
        'frameworks': [],           # compliance frameworks
        'missing_services': [],     # services not in inventory mapping
        'statistics': {}
    }
    
    # Use sets for processing, convert to lists later
    services_set = defaultdict(set)
    function_names_set = set()
    api_functions_set = defaultdict(set)
    frameworks_set = set()
    
    total_rows = 0
    processed_rows = 0
    
    try:
        with open(csv_file_path, 'r', encoding='utf-8') as file:
            # Skip the first few rows that might be headers or empty
            lines = file.readlines()
            
            # Find the actual header row
            header_row_idx = 0
            for i, line in enumerate(lines):
                if 'Compliance Name' in line or 'Function Name' in line:
                    header_row_idx = i
                    break
            
            # Reset file pointer and skip to header
            file.seek(0)
            for _ in range(header_row_idx):
                next(file)
            
            reader = csv.DictReader(file)
            
            for row in reader:
                total_rows += 1
                
                # Extract data from row
                framework = row.get('Compliance Name', '').strip()
                function_name = row.get('Function Name', '').strip()
                api_function = row.get('API function', '').strip()
                user_function = row.get('user function', '').strip()
                
                # Skip empty rows
                if not function_name and not api_function:
                    continue
                
                processed_rows += 1
                
                # Add framework
                if framework:
                    frameworks_set.add(framework)
                
                # Add function name
                if function_name:
                    function_names_set.add(function_name)
                
                # Parse services from API functions
                services = parse_api_functions(api_function)
                for service in services:
                    services_set[service].add(function_name)
                
                # Parse user functions (AWS API calls)
                user_funcs = parse_user_functions(user_function)
                for service in services:
                    for func in user_funcs:
                        api_functions_set[service].add(func)
    
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return compliance_data
    
    # Convert sets to lists for JSON serialization
    compliance_data['services'] = {k: list(v) for k, v in services_set.items()}
    compliance_data['api_functions'] = {k: list(v) for k, v in api_functions_set.items()}
    compliance_data['function_names'] = list(function_names_set)
    compliance_data['frameworks'] = list(frameworks_set)
    
    # Add statistics
    compliance_data['statistics'] = {
        'total_rows': total_rows,
        'processed_rows': processed_rows,
        'unique_services': len(compliance_data['services']),
        'unique_functions': len(compliance_data['function_names']),
        'unique_frameworks': len(compliance_data['frameworks'])
    }
    
    return compliance_data

def load_inventory_mapping(json_file_path: str) -> Dict:
    """Load the existing inventory mapping file."""
    try:
        with open(json_file_path, 'r') as file:
            return json.load(file)
    except Exception as e:
        print(f"Error loading inventory mapping: {e}")
        return {}

def compare_mappings(compliance_data: Dict, inventory_mapping: Dict) -> Dict:
    """Compare compliance data with inventory mapping to find gaps."""
    
    comparison = {
        'missing_services': [],
        'missing_functions': defaultdict(list),
        'coverage_analysis': {},
        'recommendations': []
    }
    
    # Check for missing services
    compliance_services = set(compliance_data['services'].keys())
    inventory_services = set(inventory_mapping.keys())
    
    comparison['missing_services'] = list(compliance_services - inventory_services)
    
    # Check for missing functions in existing services
    for service in compliance_services:
        if service in inventory_mapping:
            # Get all functions from inventory mapping
            inventory_funcs = set()
            if 'list_functions' in inventory_mapping[service]:
                inventory_funcs.update(inventory_mapping[service]['list_functions'])
            if 'describe_functions' in inventory_mapping[service]:
                for funcs in inventory_mapping[service]['describe_functions'].values():
                    inventory_funcs.update(funcs)
            
            # Get compliance functions for this service
            compliance_funcs = set(compliance_data['api_functions'].get(service, []))
            
            # Find missing functions
            missing_funcs = compliance_funcs - inventory_funcs
            if missing_funcs:
                comparison['missing_functions'][service] = list(missing_funcs)
    
    # Calculate coverage percentage
    total_services = len(compliance_services)
    covered_services = len(compliance_services & inventory_services)
    coverage_percentage = (covered_services / total_services * 100) if total_services > 0 else 0
    
    comparison['coverage_analysis'] = {
        'total_compliance_services': total_services,
        'covered_services': covered_services,
        'coverage_percentage': round(coverage_percentage, 2),
        'service_coverage_details': {}
    }
    
    # Detailed coverage analysis per service
    for service in compliance_services:
        if service in inventory_mapping:
            inventory_funcs = set()
            if 'list_functions' in inventory_mapping[service]:
                inventory_funcs.update(inventory_mapping[service]['list_functions'])
            if 'describe_functions' in inventory_mapping[service]:
                for funcs in inventory_mapping[service]['describe_functions'].values():
                    inventory_funcs.update(funcs)
            
            compliance_funcs = set(compliance_data['api_functions'].get(service, []))
            
            if compliance_funcs:
                covered_funcs = len(compliance_funcs & inventory_funcs)
                total_funcs = len(compliance_funcs)
                func_coverage = (covered_funcs / total_funcs * 100) if total_funcs > 0 else 0
                
                comparison['coverage_analysis']['service_coverage_details'][service] = {
                    'total_functions': total_funcs,
                    'covered_functions': covered_funcs,
                    'coverage_percentage': round(func_coverage, 2),
                    'missing_functions': list(compliance_funcs - inventory_funcs)
                }
    
    # Generate recommendations
    if comparison['missing_services']:
        comparison['recommendations'].append(
            f"Add {len(comparison['missing_services'])} missing services to inventory mapping: {comparison['missing_services'][:5]}{'...' if len(comparison['missing_services']) > 5 else ''}"
        )
    
    missing_func_count = sum(len(funcs) for funcs in comparison['missing_functions'].values())
    if missing_func_count > 0:
        comparison['recommendations'].append(
            f"Add {missing_func_count} missing API functions across {len(comparison['missing_functions'])} services"
        )
    
    if coverage_percentage < 90:
        comparison['recommendations'].append(
            f"Current coverage is {coverage_percentage:.1f}%. Aim for 95%+ coverage for comprehensive inventory collection."
        )
    
    return comparison

def generate_updated_mapping(compliance_data: Dict, inventory_mapping: Dict) -> Dict:
    """Generate an updated inventory mapping that includes all compliance requirements."""
    
    updated_mapping = inventory_mapping.copy()
    
    # Add missing services
    for service in compliance_data['services']:
        if service not in updated_mapping:
            # Create a basic structure for new services
            api_functions = compliance_data['api_functions'].get(service, [])
            
            # Try to identify list vs describe functions based on naming patterns
            list_functions = [f for f in api_functions if any(pattern in f for pattern in ['list_', 'describe_', 'get_'])]
            
            updated_mapping[service] = {
                "list_functions": list_functions,
                "describe_functions": {},
                "resource_identifiers": {}
            }
            
            # Basic describe functions mapping
            for func in list_functions:
                updated_mapping[service]["describe_functions"][func] = api_functions
                # Basic identifier patterns
                if 'list_' in func:
                    identifier = func.replace('list_', '').rstrip('s') + 'Id'
                elif 'describe_' in func:
                    identifier = func.replace('describe_', '').rstrip('s') + 'Id'
                else:
                    identifier = service + 'Id'
                updated_mapping[service]["resource_identifiers"][func] = [identifier]
    
    # Add missing functions to existing services
    for service, missing_funcs in compliance_data['api_functions'].items():
        if service in updated_mapping:
            existing_funcs = set()
            if 'list_functions' in updated_mapping[service]:
                existing_funcs.update(updated_mapping[service]['list_functions'])
            if 'describe_functions' in updated_mapping[service]:
                for funcs in updated_mapping[service]['describe_functions'].values():
                    existing_funcs.update(funcs)
            
            new_funcs = set(missing_funcs) - existing_funcs
            if new_funcs:
                # Add to list_functions if they look like list functions
                for func in new_funcs:
                    if any(pattern in func for pattern in ['list_', 'describe_', 'get_']):
                        if func not in updated_mapping[service]['list_functions']:
                            updated_mapping[service]['list_functions'].append(func)
                        
                        # Add basic describe functions mapping
                        if func not in updated_mapping[service]['describe_functions']:
                            updated_mapping[service]['describe_functions'][func] = list(new_funcs)
                        
                        # Add basic resource identifier
                        if func not in updated_mapping[service]['resource_identifiers']:
                            if 'list_' in func:
                                identifier = func.replace('list_', '').rstrip('s') + 'Id'
                            elif 'describe_' in func:
                                identifier = func.replace('describe_', '').rstrip('s') + 'Id'
                            else:
                                identifier = service + 'Id'
                            updated_mapping[service]['resource_identifiers'][func] = [identifier]
    
    return updated_mapping

def main():
    """Main function to run the compliance analysis."""
    
    # File paths
    csv_file = "/Users/apple/Desktop/lg-protect/core-engine/compliance_checks.csv"
    inventory_file = "/Users/apple/Desktop/lg-protect/inventory/inventory_functions_mapping.json"
    output_dir = "/Users/apple/Desktop/lg-protect/core-engine/analysis_output"
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    print("🔍 Starting Compliance Checks vs Inventory Mapping Analysis...")
    print("=" * 60)
    
    # Step 1: Analyze compliance checks
    print("📊 Analyzing compliance checks CSV...")
    compliance_data = analyze_compliance_checks(csv_file)
    
    # Save compliance analysis
    with open(f"{output_dir}/compliance_analysis.json", 'w') as f:
        json.dump(compliance_data, f, indent=2)
    
    print(f"✅ Processed {compliance_data['statistics']['processed_rows']} compliance checks")
    print(f"📋 Found {compliance_data['statistics']['unique_services']} unique services")
    print(f"🔧 Found {compliance_data['statistics']['unique_functions']} unique functions")
    print(f"📚 Found {compliance_data['statistics']['unique_frameworks']} compliance frameworks")
    
    # Step 2: Load inventory mapping
    print("\n📁 Loading inventory mapping...")
    inventory_mapping = load_inventory_mapping(inventory_file)
    print(f"✅ Loaded inventory mapping with {len(inventory_mapping)} services")
    
    # Step 3: Compare mappings
    print("\n🔄 Comparing compliance requirements with inventory mapping...")
    comparison = compare_mappings(compliance_data, inventory_mapping)
    
    # Save comparison analysis
    with open(f"{output_dir}/gap_analysis.json", 'w') as f:
        json.dump(comparison, f, indent=2)
    
    # Step 4: Generate updated mapping
    print("\n🛠️  Generating updated inventory mapping...")
    updated_mapping = generate_updated_mapping(compliance_data, inventory_mapping)
    
    # Save updated mapping
    with open(f"{output_dir}/updated_inventory_mapping.json", 'w') as f:
        json.dump(updated_mapping, f, indent=2)
    
    # Step 5: Print summary
    print("\n" + "=" * 60)
    print("📈 ANALYSIS SUMMARY")
    print("=" * 60)
    
    print(f"🎯 Coverage: {comparison['coverage_analysis']['coverage_percentage']:.1f}%")
    print(f"❌ Missing Services: {len(comparison['missing_services'])}")
    print(f"⚠️  Services with Missing Functions: {len(comparison['missing_functions'])}")
    
    if comparison['missing_services']:
        print(f"\n🚨 Missing Services ({len(comparison['missing_services'])}):")
        for service in sorted(comparison['missing_services'])[:10]:
            print(f"   • {service}")
        if len(comparison['missing_services']) > 10:
            print(f"   ... and {len(comparison['missing_services']) - 10} more")
    
    if comparison['missing_functions']:
        print(f"\n⚠️  Services with Missing Functions:")
        for service, funcs in list(comparison['missing_functions'].items())[:5]:
            print(f"   • {service}: {len(funcs)} missing functions")
        if len(comparison['missing_functions']) > 5:
            print(f"   ... and {len(comparison['missing_functions']) - 5} more services")
    
    print(f"\n📝 Recommendations:")
    for rec in comparison['recommendations']:
        print(f"   • {rec}")
    
    print(f"\n📁 Analysis files saved to: {output_dir}/")
    print("   • compliance_analysis.json - Full compliance data analysis")
    print("   • gap_analysis.json - Detailed gap analysis")
    print("   • updated_inventory_mapping.json - Enhanced mapping file")
    
    print(f"\n✅ Analysis complete! Use the updated mapping to ensure comprehensive inventory collection.")

if __name__ == "__main__":
    main()