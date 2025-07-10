#!/usr/bin/env python3
"""
Simplify Inventory Mapping Structure
This script modifies the inventory_functions_mapping.json to simplify the describe_functions
structure by keeping only the main function names without the sub-function arrays.
"""

import json
import os
from datetime import datetime

def simplify_describe_functions(mapping_data):
    """
    Simplify the describe_functions structure by keeping only main function names.
    
    Before:
    "describe_functions": {
        "list_buckets": ["get_bucket_policy", "get_bucket_encryption", ...],
        "list_distributions": ["list_distributions", "get_distribution_config", ...]
    }
    
    After:
    "describe_functions": ["list_buckets", "list_distributions"]
    """
    
    simplified_mapping = {}
    
    for service_name, service_config in mapping_data.items():
        simplified_service = {}
        
        # Copy list_functions as is
        if 'list_functions' in service_config:
            simplified_service['list_functions'] = service_config['list_functions']
        
        # Simplify describe_functions - keep only the keys, not the values
        if 'describe_functions' in service_config:
            if isinstance(service_config['describe_functions'], dict):
                # Extract only the main function names (keys)
                simplified_service['describe_functions'] = list(service_config['describe_functions'].keys())
            else:
                # Keep as is if it's already a list
                simplified_service['describe_functions'] = service_config['describe_functions']
        
        # Copy resource_identifiers as is
        if 'resource_identifiers' in service_config:
            simplified_service['resource_identifiers'] = service_config['resource_identifiers']
        
        simplified_mapping[service_name] = simplified_service
    
    return simplified_mapping

def main():
    """Main function to simplify the inventory mapping structure."""
    
    # File paths
    input_file = "/Users/apple/Desktop/lg-protect/inventory/inventory_functions_mapping.json"
    backup_file = "/Users/apple/Desktop/lg-protect/inventory/inventory_functions_mapping_backup.json"
    output_file = "/Users/apple/Desktop/lg-protect/inventory/inventory_functions_mapping_simplified.json"
    
    print("🔧 Starting Inventory Mapping Simplification...")
    print("=" * 60)
    
    # Step 1: Load the current mapping
    print("📁 Loading current inventory mapping...")
    try:
        with open(input_file, 'r') as f:
            mapping_data = json.load(f)
        print(f"✅ Loaded mapping with {len(mapping_data)} services")
    except Exception as e:
        print(f"❌ Error loading file: {e}")
        return
    
    # Step 2: Create backup if it doesn't exist
    if not os.path.exists(backup_file):
        print("💾 Creating backup of original file...")
        try:
            with open(backup_file, 'w') as f:
                json.dump(mapping_data, f, indent=2)
            print("✅ Backup created successfully")
        except Exception as e:
            print(f"❌ Error creating backup: {e}")
            return
    else:
        print("📋 Backup already exists, skipping backup creation")
    
    # Step 3: Simplify the structure
    print("🔄 Simplifying describe_functions structure...")
    simplified_mapping = simplify_describe_functions(mapping_data)
    
    # Step 4: Show example of changes
    print("\n📊 Example of structural changes:")
    example_service = next(iter(simplified_mapping.keys()))
    print(f"\nService: {example_service}")
    
    # Show original structure
    if 'describe_functions' in mapping_data[example_service]:
        original_desc = mapping_data[example_service]['describe_functions']
        if isinstance(original_desc, dict) and original_desc:
            sample_key = next(iter(original_desc.keys()))
            print(f"  Before: '{sample_key}': {original_desc[sample_key][:3]}{'...' if len(original_desc[sample_key]) > 3 else ''}")
    
    # Show simplified structure
    if 'describe_functions' in simplified_mapping[example_service]:
        simplified_desc = simplified_mapping[example_service]['describe_functions']
        print(f"  After:  {simplified_desc[:3]}{'...' if len(simplified_desc) > 3 else ''}")
    
    # Step 5: Save simplified mapping
    print(f"\n💾 Saving simplified mapping...")
    try:
        with open(output_file, 'w') as f:
            json.dump(simplified_mapping, f, indent=2)
        print(f"✅ Simplified mapping saved to: {output_file}")
    except Exception as e:
        print(f"❌ Error saving simplified mapping: {e}")
        return
    
    # Step 6: Statistics
    print("\n📈 Simplification Statistics:")
    total_functions_before = 0
    total_functions_after = 0
    
    for service_name in mapping_data:
        if 'describe_functions' in mapping_data[service_name]:
            if isinstance(mapping_data[service_name]['describe_functions'], dict):
                total_functions_before += sum(len(funcs) for funcs in mapping_data[service_name]['describe_functions'].values())
        
        if 'describe_functions' in simplified_mapping[service_name]:
            total_functions_after += len(simplified_mapping[service_name]['describe_functions'])
    
    print(f"  Services processed: {len(simplified_mapping)}")
    print(f"  Functions before: {total_functions_before} (including sub-functions)")
    print(f"  Functions after: {total_functions_after} (main functions only)")
    print(f"  Reduction: {total_functions_before - total_functions_after} functions removed")
    
    print("\n✅ Simplification complete!")
    print(f"📁 Files:")
    print(f"  • Original: {input_file}")
    print(f"  • Backup: {backup_file}")
    print(f"  • Simplified: {output_file}")
    
    # Ask user if they want to replace the original
    print(f"\n🔄 To replace the original file with the simplified version, run:")
    print(f"   cp {output_file} {input_file}")

if __name__ == "__main__":
    main()