#!/usr/bin/env python3
"""
Utility Testing - Service Mapping Region Updater
Updates service_enablement_mapping.json with region information
Results are saved to timestamped folders for tracking changes
"""

import json
import os
from datetime import datetime
from pathlib import Path

def create_timestamped_results_folder():
    """Create a timestamped results folder for this test run"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    results_dir = Path(__file__).parent / "results" / f"utility_test_{timestamp}"
    results_dir.mkdir(parents=True, exist_ok=True)
    return results_dir

def save_test_log(results_dir, log_messages):
    """Save test execution log to results folder"""
    log_file = results_dir / "utility_test_log.txt"
    with open(log_file, 'w') as f:
        f.write(f"Utility Testing Log - {datetime.now().isoformat()}\n")
        f.write("=" * 60 + "\n")
        for message in log_messages:
            f.write(f"{message}\n")
    return log_file

def load_json_file(file_path):
    """Load JSON data from a file"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File {file_path} not found")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {file_path}: {e}")
        return None

def save_json_file(data, file_path):
    """Save JSON data to a file with pretty formatting"""
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2, sort_keys=True)
        print(f"Successfully saved updated data to {file_path}")
        return True
    except Exception as e:
        print(f"Error saving file {file_path}: {e}")
        return False

def create_service_region_mapping(aws_services_by_region):
    """Create a mapping of service to list of regions where it's available"""
    service_regions = {}
    
    for region, services in aws_services_by_region.items():
        for service in services:
            if service not in service_regions:
                service_regions[service] = []
            service_regions[service].append(region)
    
    # Sort regions for each service for consistency
    for service in service_regions:
        service_regions[service].sort()
    
    return service_regions

def update_service_enablement_mapping(service_mapping, service_regions):
    """Add region information to service enablement mapping, excluding global services"""
    updated_mapping = {}
    
    for service, config in service_mapping.items():
        # Create a copy of the existing configuration
        updated_config = config.copy()
        
        # Check if service scope is global
        scope = config.get('scope', 'regional')
        
        if scope == 'global':
            # For global services, don't add regions array
            # Remove regions if it exists (cleanup)
            if 'regions' in updated_config:
                del updated_config['regions']
            print(f"Service '{service}' is global - no regions specified")
        else:
            # For regional services, add regions information
            if service in service_regions:
                updated_config['regions'] = service_regions[service]
                print(f"Added {len(service_regions[service])} regions for regional service: {service}")
            else:
                # If service not found, add empty regions list and warn
                updated_config['regions'] = []
                print(f"Warning: Regional service '{service}' not found in AWS services by region data")
        
        updated_mapping[service] = updated_config
    
    return updated_mapping

def main():
    # Create timestamped results folder
    results_dir = create_timestamped_results_folder()
    log_messages = []
    
    def log(message):
        print(message)
        log_messages.append(message)
    
    # File paths
    aws_services_file = "/Users/apple/Desktop/lg-protect/aws_services_by_region.json"
    service_mapping_file = "/Users/apple/Desktop/lg-protect/inventory/service_enablement_mapping.json"
    
    # Save backup and updated files in results folder
    backup_file = results_dir / "service_enablement_mapping_backup.json"
    updated_file = results_dir / "service_enablement_mapping_updated.json"
    
    log("🔧 UTILITY TESTING - Service Mapping Region Updater")
    log(f"📁 Results will be saved to: {results_dir}")
    log("Note: Global services will not include regions array")
    
    # Load AWS services by region data
    log(f"Loading AWS services by region from: {aws_services_file}")
    aws_services_by_region = load_json_file(aws_services_file)
    if not aws_services_by_region:
        save_test_log(results_dir, log_messages)
        return
    
    # Load current service enablement mapping
    log(f"Loading service enablement mapping from: {service_mapping_file}")
    service_mapping = load_json_file(service_mapping_file)
    if not service_mapping:
        save_test_log(results_dir, log_messages)
        return
    
    # Create backup of original file in results folder
    log("Creating backup of original service enablement mapping...")
    if save_json_file(service_mapping, str(backup_file)):
        log(f"Backup saved to: {backup_file}")
    
    # Create service to regions mapping
    log("Creating service to regions mapping...")
    service_regions = create_service_region_mapping(aws_services_by_region)
    log(f"Processed {len(service_regions)} unique AWS services across {len(aws_services_by_region)} regions")
    
    # Update service enablement mapping with region information
    log("Updating service enablement mapping with region information...")
    updated_mapping = update_service_enablement_mapping(service_mapping, service_regions)
    
    # Save updated mapping to both results folder and original location
    log("Saving updated service enablement mapping...")
    if save_json_file(updated_mapping, str(updated_file)):
        log(f"Updated mapping saved to results: {updated_file}")
    
    if save_json_file(updated_mapping, service_mapping_file):
        log("✅ Successfully updated original service_enablement_mapping.json")
    
    # Generate summary report
    log("\n" + "="*60)
    log("UTILITY TEST SUMMARY")
    log("="*60)
    log(f"Total services in enablement mapping: {len(updated_mapping)}")
    log(f"Total AWS regions processed: {len(aws_services_by_region)}")
    log(f"Total unique AWS services found: {len(service_regions)}")
    
    # Categorize services by scope
    global_services = [s for s, c in updated_mapping.items() if c.get('scope') == 'global']
    regional_services = [s for s, c in updated_mapping.items() if c.get('scope') == 'regional']
    
    log(f"Global services (no regions specified): {len(global_services)}")
    log(f"Regional services (with regions): {len(regional_services)}")
    
    # Show examples of each type
    log("\nExamples of global services:")
    for service in global_services[:3]:
        log(f"  - {service}: global scope")
    
    log("\nExamples of regional services with region information:")
    count = 0
    for service, config in updated_mapping.items():
        if count < 3 and config.get('scope') == 'regional' and config.get('regions'):
            region_count = len(config['regions'])
            log(f"  - {service}: {region_count} regions")
            count += 1
    
    # Show services not found in AWS data
    not_found_services = [s for s, c in updated_mapping.items() 
                         if c.get('scope') == 'regional' and not c.get('regions')]
    if not_found_services:
        log(f"\nRegional services not found in AWS regions data ({len(not_found_services)}):")
        for service in not_found_services:
            log(f"  - {service}")
    
    # Save test log
    log_file = save_test_log(results_dir, log_messages)
    log(f"\n📋 Test log saved to: {log_file}")
    log(f"🎉 Utility testing completed successfully!")

if __name__ == "__main__":
    main()