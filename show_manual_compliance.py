#!/usr/bin/env python3
"""
Script to extract and display compliance entries marked as "manual" from the CSV file.
"""

import csv
import json

def main():
    input_file = '/Users/apple/Desktop/lg-protect/backend/services/compliance-service/config/compliance_checks_updated.csv'
    
    manual_entries = []
    
    # Read the CSV and find manual entries
    with open(input_file, 'r', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        
        for row in reader:
            applied_services = row.get('applied_services', '')
            if applied_services and 'manual' in applied_services:
                manual_entries.append(row)
    
    print(f"Found {len(manual_entries)} compliance entries marked as 'manual':\n")
    print("=" * 80)
    
    # Group by compliance framework
    frameworks = {}
    for entry in manual_entries:
        framework = entry.get('Compliance Name', 'Unknown')
        if framework not in frameworks:
            frameworks[framework] = []
        frameworks[framework].append(entry)
    
    # Display by framework
    for framework, entries in frameworks.items():
        print(f"\n📋 FRAMEWORK: {framework}")
        print(f"   Manual entries: {len(entries)}")
        print("-" * 80)
        
        for i, entry in enumerate(entries, 1):
            unique_key = entry.get('unique_key', 'N/A')
            control_id = entry.get('ID', 'N/A')
            name = entry.get('Name', 'N/A')
            description = entry.get('Description', 'N/A')
            
            print(f"\n{i}. Control ID: {control_id}")
            print(f"   Unique Key: {unique_key}")
            print(f"   Name: {name}")
            print(f"   Description: {description[:200]}{'...' if len(description) > 200 else ''}")
            
            # Check if there are any attributes that might give more context
            attributes = entry.get('Attributes', '')
            if attributes:
                try:
                    attr_data = json.loads(attributes)
                    if isinstance(attr_data, list) and len(attr_data) > 0:
                        first_attr = attr_data[0]
                        if 'AssessmentStatus' in first_attr:
                            print(f"   Assessment Status: {first_attr.get('AssessmentStatus', 'N/A')}")
                        if 'Profile' in first_attr:
                            print(f"   Profile Level: {first_attr.get('Profile', 'N/A')}")
                        if 'Section' in first_attr:
                            print(f"   Section: {first_attr.get('Section', 'N/A')}")
                except json.JSONDecodeError:
                    pass
            
            print(f"   Applied Services: {entry.get('applied_services', 'N/A')}")
    
    print("\n" + "=" * 80)
    print("📊 SUMMARY BY FRAMEWORK:")
    for framework, entries in frameworks.items():
        print(f"  • {framework}: {len(entries)} manual entries")
    
    print(f"\n🔍 TOTAL MANUAL COMPLIANCE ENTRIES: {len(manual_entries)}")
    
    # Show some common patterns in manual entries
    print("\n📝 COMMON MANUAL COMPLIANCE CATEGORIES:")
    categories = {}
    for entry in manual_entries:
        attributes = entry.get('Attributes', '')
        try:
            attr_data = json.loads(attributes)
            if isinstance(attr_data, list) and len(attr_data) > 0:
                section = attr_data[0].get('Section', 'Unknown')
                if section not in categories:
                    categories[section] = 0
                categories[section] += 1
        except (json.JSONDecodeError, KeyError, IndexError):
            categories['Unknown'] = categories.get('Unknown', 0) + 1
    
    for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
        print(f"  • {category}: {count} entries")

if __name__ == "__main__":
    main()