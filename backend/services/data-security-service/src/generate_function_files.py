#!/usr/bin/env python3
"""
YAML Rule File Processor - Data Security Function Generator

This script processes all YAML files in the rules folder and generates 
individual Python function files for each rule defined in the YAML files.
"""

import yaml
import os
import sys
from pathlib import Path

def load_yaml_file(filepath):
    """Load and parse a YAML file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            return yaml.safe_load(file)
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return None

def generate_function_template(rule_data):
    """Generate the Python function template for a rule."""
    
    function_name = rule_data.get('function_name', 'unknown_function')
    title = rule_data.get('title', 'No title provided')
    description = rule_data.get('description', 'No description provided')
    capability = rule_data.get('capability', 'unknown_capability')
    service = rule_data.get('service', 'unknown_service')
    subservice = rule_data.get('subservice', 'unknown_subservice')
    risk = rule_data.get('risk', 'UNKNOWN')
    existing = rule_data.get('existing', False)
    
    # If function already exists (existing: true), skip generation
    if existing:
        return None  # Return None to indicate skip
    
    # Generate the complete function template only for existing: false
    template = f'''#!/usr/bin/env python3
"""
data_security_aws - {function_name}

{description}
"""

# Rule Metadata from YAML:
# Function Name: {function_name}
# Capability: {capability.upper()}
# Service: {service.upper()}
# Subservice: {subservice.upper() if subservice else 'N/A'}
# Description: {description}
# Risk Level: {risk}
# Recommendation: {title}
# API Function: client = boto3.client('{service}')
# User Function: {function_name}()

# Import required modules
import boto3
import json
import sys
from typing import Dict, List, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_rule_metadata(function_name: str) -> Dict[str, Any]:
    """Load rule metadata from YAML configuration."""
    return {{
        "function_name": "{function_name}",
        "title": "{title}",
        "description": "{description}",
        "capability": "{capability}",
        "service": "{service}",
        "subservice": "{subservice}",
        "risk": "{risk}",
        "existing": {existing}
    }}

def {function_name}_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check {service} resources for {capability} compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    try:
        # Initialize boto3 client
        session = boto3.Session(profile_name=profile_name)
        {service}_client = session.client('{service}', region_name=region_name)
        
        logger.info(f"Checking {{service}} resources for {capability} compliance in region {{region_name}}")
        
        # TODO: Implement specific logic for {function_name}
        # Example structure:
        # paginator = {service}_client.get_paginator('list_resources')  # Replace with actual API call
        # for page in paginator.paginate():
        #     for resource in page['Resources']:
        #         resource_id = resource.get('ResourceId')
        #         resource_arn = resource.get('ResourceArn')
        #         
        #         if not_compliant_condition:
        #             findings.append({{
        #                 "region": region_name,
        #                 "profile": profile_name or "default",
        #                 "resource_type": "{service}_{subservice}",
        #                 "resource_id": resource_arn,
        #                 "status": "NON_COMPLIANT",
        #                 "risk_level": "{risk}",
        #                 "recommendation": "{title}",
        #                 "details": {{
        #                     "{service}_id": resource_arn,
        #                     "violation": "Specific violation details"
        #                 }}
        #             }})
        #         else:
        #             findings.append({{
        #                 "region": region_name,
        #                 "profile": profile_name or "default",
        #                 "resource_type": "{service}_{subservice}",
        #                 "resource_id": resource_arn,
        #                 "status": "COMPLIANT",
        #                 "risk_level": "{risk}",
        #                 "recommendation": "Resource is compliant",
        #                 "details": {{
        #                     "{service}_id": resource_arn
        #                 }}
        #             }})
        
        logger.info(f"Completed checking {function_name}. Found {{len(findings)}} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check {function_name}: {{e}}")
        findings.append({{
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "{service}_{subservice}",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "{risk}",
            "recommendation": "Fix API access issues",
            "details": {{
                "error": str(e)
            }}
        }})
    
    return findings

def {function_name}(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for {function_name}.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("{function_name}")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, {function_name}_check)
    
    # Current implementation
    findings = {function_name}_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {{
        "function_name": "{function_name}",
        "region": region_name,
        "profile": profile_name or "default",
        "total_findings": total_findings,
        "compliant_count": compliant_findings,
        "non_compliant_count": non_compliant_findings,
        "error_count": error_findings,
        "compliance_rate": (compliant_findings / total_findings * 100) if total_findings > 0 else 0,
        "findings": findings
    }}

def main():
    """CLI entry point for {function_name}."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = {function_name}(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="{description}"
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = {function_name}(args.region, args.profile)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"Results saved to {{args.output}}")
        else:
            print(json.dumps(results, indent=2))
            
        # Exit with appropriate code
        if results['error_count'] > 0:
            sys.exit(2)  # Errors encountered
        elif results['non_compliant_count'] > 0:
            sys.exit(1)  # Non-compliant resources found
        else:
            sys.exit(0)  # All compliant
            
    except Exception as e:
        logger.error(f"Execution failed: {{e}}")
        sys.exit(3)

if __name__ == "__main__":
    main()
'''
    
    return template

def process_rules_directory(rules_dir, output_dir):
    """Process all YAML files in the rules directory."""
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Get all YAML files
    yaml_files = [f for f in os.listdir(rules_dir) if f.endswith('.yaml')]
    
    total_functions = 0
    generated_functions = 0
    skipped_functions = 0
    
    for yaml_file in yaml_files:
        if yaml_file == 'promt.txt':  # Skip non-YAML files
            continue
            
        yaml_path = os.path.join(rules_dir, yaml_file)
        print(f"Processing {yaml_file}...")
        
        # Load YAML data
        yaml_data = load_yaml_file(yaml_path)
        if not yaml_data:
            continue
            
        # Process each rule in the YAML file
        for rule in yaml_data:
            if not isinstance(rule, dict) or 'function_name' not in rule:
                continue
                
            function_name = rule['function_name']
            existing = rule.get('existing', False)
            total_functions += 1
            
            # Generate function file
            function_content = generate_function_template(rule)
            
            # Skip if function already exists (existing: true)
            if function_content is None:
                print(f"  ⏭️  Skipped: {function_name}.py (existing: true)")
                skipped_functions += 1
                continue
            
            # Write to output file
            output_file = os.path.join(output_dir, f"{function_name}.py")
            
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(function_content)
                
                print(f"  ✓ Generated: {function_name}.py (existing: false)")
                generated_functions += 1
                
            except Exception as e:
                print(f"  ✗ Failed to generate {function_name}.py: {e}")
    
    print(f"\n📊 Summary:")
    print(f"Total functions processed: {total_functions}")
    print(f"Successfully generated: {generated_functions}")
    print(f"Skipped (existing: true): {skipped_functions}")
    print(f"Output directory: {output_dir}")
    print(f"\n🎯 Only functions with 'existing: false' were generated.")

def main():
    """Main function to run the generator."""
    
    # Set up paths
    current_dir = os.path.dirname(os.path.abspath(__file__))
    rules_dir = os.path.join(current_dir, "rules")
    output_dir = os.path.join(current_dir, "data_function_list")
    
    # Validate rules directory exists
    if not os.path.exists(rules_dir):
        print(f"Error: Rules directory not found at {rules_dir}")
        sys.exit(1)
    
    print("🚀 Starting Data Security Function Generator")
    print(f"Rules directory: {rules_dir}")
    print(f"Output directory: {output_dir}")
    print("-" * 60)
    
    # Process all rules
    process_rules_directory(rules_dir, output_dir)
    
    print("\n✅ Function generation completed!")

if __name__ == "__main__":
    main()