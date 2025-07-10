#!/usr/bin/env python3
"""
AWS Service and Function Inventory Builder

This module builds comprehensive inventories of AWS services and their corresponding
boto3 functions based on compliance rule mappings. It processes compliance data
to generate service catalogs, function mappings, and service-specific inventories.

Author: Compliance Team
Date: 2025-01-02
"""

import json
import csv
import pandas as pd
from typing import Dict, List, Set, Tuple
from collections import defaultdict, Counter
import re
import os
from pathlib import Path

class AWSServiceInventoryBuilder:
    """
    Builds comprehensive AWS service and function inventories from compliance data.
    """
    
    def __init__(self, base_path: str = "/Users/apple/Desktop/lg-protect"):
        """
        Initialize the inventory builder.
        
        Args:
            base_path: Base path to the project directory
        """
        self.base_path = Path(base_path)
        self.core_engine_path = self.base_path / "core-engine"
        self.inventory_path = self.base_path / "inventory"
        self.dump_path = self.inventory_path / "dump"
        
        # Ensure output directories exist
        self.dump_path.mkdir(parents=True, exist_ok=True)
        
        # Data storage
        self.compliance_data = []
        self.service_function_mapping = defaultdict(set)
        self.function_service_mapping = {}
        self.service_compliance_mapping = defaultdict(list)
        self.compliance_categories = defaultdict(list)
        
    def load_compliance_data(self) -> List[Dict]:
        """
        Load compliance data from CSV and JSON files.
        
        Returns:
            List of compliance check dictionaries
        """
        compliance_files = [
            self.core_engine_path / "compliance_checks.csv",
            self.inventory_path / "dump" / "compliance_checks.json"
        ]
        
        all_data = []
        
        for file_path in compliance_files:
            if file_path.exists():
                try:
                    if file_path.suffix == '.csv':
                        df = pd.read_csv(file_path)
                        all_data.extend(df.to_dict('records'))
                    elif file_path.suffix == '.json':
                        with open(file_path, 'r') as f:
                            data = json.load(f)
                            if isinstance(data, dict) and 'compliance_checks' in data:
                                all_data.extend(data['compliance_checks'])
                            elif isinstance(data, list):
                                all_data.extend(data)
                    print(f"✓ Loaded {len(all_data)} compliance checks from {file_path.name}")
                except Exception as e:
                    print(f"✗ Error loading {file_path.name}: {e}")
        
        self.compliance_data = all_data
        return all_data
    
    def extract_service_from_client(self, api_function: str) -> str:
        """
        Extract AWS service name from boto3 client string.
        
        Args:
            api_function: String like "client = boto3.client('ec2')"
            
        Returns:
            Extracted service name
        """
        if not api_function or pd.isna(api_function):
            return "unknown"
        
        # Extract service from boto3.client('service') pattern
        pattern = r"boto3\.client\(['\"]([^'\"]+)['\"]\)"
        matches = re.findall(pattern, str(api_function))
        
        if matches:
            return matches[0]
        
        # Fallback: try to extract from variable assignments
        if "client" in str(api_function).lower():
            # Look for common service patterns
            services = [
                'ec2', 'iam', 's3', 'rds', 'lambda', 'cloudtrail', 'cloudwatch',
                'dynamodb', 'efs', 'elb', 'elbv2', 'kms', 'sns', 'sqs',
                'apigateway', 'apigatewayv2', 'backup', 'redshift', 'opensearch',
                'guardduty', 'securityhub', 'dax', 'wafv2', 'acm', 'ssm',
                'emr', 'codebuild', 'sagemaker', 'athena', 'logs'
            ]
            
            for service in services:
                if service in str(api_function).lower():
                    return service
        
        return "unknown"
    
    def extract_functions_from_user_function(self, user_function: str) -> List[str]:
        """
        Extract function names from user function string.
        
        Args:
            user_function: String like "describe_instances(), get_bucket_policy()"
            
        Returns:
            List of function names
        """
        if not user_function or pd.isna(user_function):
            return []
        
        # Extract functions with parentheses
        pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        functions = re.findall(pattern, str(user_function))
        
        # Clean and deduplicate
        functions = list(set([f.strip() for f in functions if f.strip()]))
        
        return functions
    
    def build_service_function_mapping(self) -> Dict[str, Set[str]]:
        """
        Build mapping of AWS services to their boto3 functions.
        
        Returns:
            Dictionary mapping service names to sets of function names
        """
        print("\n🔍 Building service-function mapping...")
        
        for record in self.compliance_data:
            # Extract service name
            api_function = record.get('API function', '')
            service = self.extract_service_from_client(api_function)
            
            # Extract functions
            user_function = record.get('user function', '')
            functions = self.extract_functions_from_user_function(user_function)
            
            # Add to mapping
            for func in functions:
                self.service_function_mapping[service].add(func)
                self.function_service_mapping[func] = service
            
            # Add compliance mapping
            compliance_name = record.get('Compliance Name', 'unknown')
            compliance_id = record.get('ID', 'unknown')
            function_name = record.get('Function Name', 'unknown')
            
            self.service_compliance_mapping[service].append({
                'compliance_name': compliance_name,
                'compliance_id': compliance_id,
                'function_name': function_name,
                'description': record.get('Description', ''),
                'boto3_functions': functions
            })
        
        # Convert sets to lists for JSON serialization
        result = {service: list(functions) for service, functions in self.service_function_mapping.items()}
        
        print(f"✓ Mapped {len(result)} services with {sum(len(funcs) for funcs in result.values())} unique functions")
        return result
    
    def build_compliance_categories(self) -> Dict[str, List[Dict]]:
        """
        Build compliance categories and their associated checks.
        
        Returns:
            Dictionary of compliance categories
        """
        print("\n📋 Building compliance categories...")
        
        for record in self.compliance_data:
            compliance_name = record.get('Compliance Name', 'unknown')
            compliance_id = record.get('ID', 'unknown')
            
            # Extract category from ID (e.g., "your-systems-1" -> "your-systems")
            category = compliance_id.split('-')[0:-1] if compliance_id != 'unknown' else ['uncategorized']
            category_name = '-'.join(category) if category else 'uncategorized'
            
            self.compliance_categories[category_name].append({
                'compliance_name': compliance_name,
                'compliance_id': compliance_id,
                'name': record.get('Name', ''),
                'description': record.get('Description', ''),
                'function_name': record.get('Function Name', ''),
                'service': self.extract_service_from_client(record.get('API function', '')),
                'boto3_functions': self.extract_functions_from_user_function(record.get('user function', ''))
            })
        
        print(f"✓ Organized {len(self.compliance_categories)} compliance categories")
        return dict(self.compliance_categories)
    
    def generate_service_statistics(self) -> Dict:
        """
        Generate statistics about services and functions.
        
        Returns:
            Dictionary containing various statistics
        """
        stats = {
            'total_services': len(self.service_function_mapping),
            'total_functions': len(self.function_service_mapping),
            'total_compliance_checks': len(self.compliance_data),
            'services_by_function_count': {},
            'top_services_by_usage': {},
            'function_distribution': {},
            'compliance_coverage': {}
        }
        
        # Services by function count
        for service, functions in self.service_function_mapping.items():
            count = len(functions)
            stats['services_by_function_count'][service] = count
        
        # Top services by usage (number of compliance checks)
        service_usage = Counter()
        for record in self.compliance_data:
            service = self.extract_service_from_client(record.get('API function', ''))
            service_usage[service] += 1
        
        stats['top_services_by_usage'] = dict(service_usage.most_common(10))
        
        # Function distribution
        func_counts = [len(functions) for functions in self.service_function_mapping.values()]
        if func_counts:
            stats['function_distribution'] = {
                'min_functions': min(func_counts),
                'max_functions': max(func_counts),
                'avg_functions': sum(func_counts) / len(func_counts)
            }
        
        # Compliance coverage by service
        for service, compliance_list in self.service_compliance_mapping.items():
            stats['compliance_coverage'][service] = len(compliance_list)
        
        return stats
    
    def save_inventories(self) -> None:
        """
        Save all generated inventories to files.
        """
        print("\n💾 Saving inventories...")
        
        # Service-function mapping
        service_functions = self.build_service_function_mapping()
        with open(self.dump_path / "aws_services_function_mapping.json", 'w') as f:
            json.dump(service_functions, f, indent=2, sort_keys=True)
        print(f"✓ Saved service-function mapping to aws_services_function_mapping.json")
        
        # Function-service reverse mapping
        with open(self.dump_path / "function_to_service_mapping.json", 'w') as f:
            json.dump(self.function_service_mapping, f, indent=2, sort_keys=True)
        print(f"✓ Saved function-service mapping to function_to_service_mapping.json")
        
        # Service compliance mapping
        service_compliance = {service: compliance_list for service, compliance_list in self.service_compliance_mapping.items()}
        with open(self.dump_path / "service_compliance_mapping.json", 'w') as f:
            json.dump(service_compliance, f, indent=2, sort_keys=True)
        print(f"✓ Saved service-compliance mapping to service_compliance_mapping.json")
        
        # Compliance categories
        categories = self.build_compliance_categories()
        with open(self.dump_path / "compliance_categories.json", 'w') as f:
            json.dump(categories, f, indent=2, sort_keys=True)
        print(f"✓ Saved compliance categories to compliance_categories.json")
        
        # Statistics
        stats = self.generate_service_statistics()
        with open(self.dump_path / "aws_inventory_statistics.json", 'w') as f:
            json.dump(stats, f, indent=2, sort_keys=True)
        print(f"✓ Saved statistics to aws_inventory_statistics.json")
        
        # Service list (simple list of all services)
        services_list = sorted(list(self.service_function_mapping.keys()))
        with open(self.dump_path / "aws_services_list.json", 'w') as f:
            json.dump(services_list, f, indent=2)
        print(f"✓ Saved services list to aws_services_list.json")
        
        # Function list (simple list of all functions)
        functions_list = sorted(list(self.function_service_mapping.keys()))
        with open(self.dump_path / "aws_functions_list.json", 'w') as f:
            json.dump(functions_list, f, indent=2)
        print(f"✓ Saved functions list to aws_functions_list.json")
    
    def generate_service_specific_inventory(self, service_name: str) -> Dict:
        """
        Generate inventory for a specific AWS service.
        
        Args:
            service_name: Name of the AWS service
            
        Returns:
            Service-specific inventory dictionary
        """
        if service_name not in self.service_function_mapping:
            return {}
        
        inventory = {
            'service_name': service_name,
            'functions': list(self.service_function_mapping[service_name]),
            'compliance_checks': self.service_compliance_mapping.get(service_name, []),
            'function_count': len(self.service_function_mapping[service_name]),
            'compliance_count': len(self.service_compliance_mapping.get(service_name, [])),
            'compliance_categories': set()
        }
        
        # Extract compliance categories for this service
        for check in inventory['compliance_checks']:
            comp_id = check.get('compliance_id', '')
            if comp_id and comp_id != 'unknown':
                category = '-'.join(comp_id.split('-')[0:-1])
                inventory['compliance_categories'].add(category)
        
        inventory['compliance_categories'] = list(inventory['compliance_categories'])
        
        return inventory
    
    def save_service_specific_inventories(self) -> None:
        """
        Save individual inventory files for each AWS service.
        """
        print("\n📂 Generating service-specific inventories...")
        
        service_inventories_path = self.dump_path / "service_inventories"
        service_inventories_path.mkdir(exist_ok=True)
        
        for service_name in self.service_function_mapping.keys():
            if service_name == 'unknown':
                continue
                
            inventory = self.generate_service_specific_inventory(service_name)
            
            filename = f"{service_name}_inventory.json"
            filepath = service_inventories_path / filename
            
            with open(filepath, 'w') as f:
                json.dump(inventory, f, indent=2, sort_keys=True)
        
        print(f"✓ Generated {len(self.service_function_mapping) - 1} service-specific inventories")
    
    def create_summary_report(self) -> str:
        """
        Create a summary report of the inventory.
        
        Returns:
            Formatted summary report as string
        """
        stats = self.generate_service_statistics()
        
        report = f"""
AWS Service and Function Inventory Summary
==========================================

📊 Overall Statistics:
• Total AWS Services: {stats['total_services']}
• Total Boto3 Functions: {stats['total_functions']}
• Total Compliance Checks: {stats['total_compliance_checks']}

🔝 Top 10 Services by Usage:
"""
        
        for service, count in stats['top_services_by_usage'].items():
            report += f"   • {service}: {count} compliance checks\n"
        
        report += f"""
📈 Function Distribution:
• Service with most functions: {max(stats['services_by_function_count'], key=stats['services_by_function_count'].get)} ({max(stats['services_by_function_count'].values())} functions)
• Service with least functions: {min(stats['services_by_function_count'], key=stats['services_by_function_count'].get)} ({min(stats['services_by_function_count'].values())} functions)
• Average functions per service: {stats['function_distribution']['avg_functions']:.1f}

📋 Compliance Categories:
"""
        
        for category, checks in self.compliance_categories.items():
            report += f"   • {category}: {len(checks)} checks\n"
        
        report += f"""
💾 Generated Files:
• aws_services_function_mapping.json - Service to functions mapping
• function_to_service_mapping.json - Function to service mapping
• service_compliance_mapping.json - Service to compliance checks mapping
• compliance_categories.json - Organized compliance categories
• aws_inventory_statistics.json - Detailed statistics
• aws_services_list.json - Simple list of all services
• aws_functions_list.json - Simple list of all functions
• service_inventories/ - Individual service inventories

🎯 Usage Examples:
1. Get all functions for EC2: service_functions['ec2']
2. Find service for a function: function_service_mapping['describe_instances']
3. Get compliance checks for RDS: service_compliance_mapping['rds']
"""
        
        return report
    
    def run_full_inventory_build(self) -> None:
        """
        Run the complete inventory building process.
        """
        print("🚀 Starting AWS Service Inventory Build...")
        print("=" * 50)
        
        # Load data
        self.load_compliance_data()
        
        if not self.compliance_data:
            print("❌ No compliance data found. Please check your data files.")
            return
        
        # Build mappings
        self.build_service_function_mapping()
        self.build_compliance_categories()
        
        # Save inventories
        self.save_inventories()
        self.save_service_specific_inventories()
        
        # Generate and save summary report
        report = self.create_summary_report()
        with open(self.dump_path / "inventory_summary_report.txt", 'w') as f:
            f.write(report)
        
        print("\n" + "=" * 50)
        print("✅ Inventory build completed successfully!")
        print(f"📁 All files saved to: {self.dump_path}")
        print("\n" + report)

def main():
    """
    Main function to run the inventory builder.
    """
    builder = AWSServiceInventoryBuilder()
    builder.run_full_inventory_build()

if __name__ == "__main__":
    main()