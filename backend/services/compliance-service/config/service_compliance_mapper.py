#!/usr/bin/env python3
"""
Service-Based Compliance Check Generator

This script analyzes the compliance CSV file and generates a JSON output containing:
- Compliance checks that can be run based on available services
- Detailed mapping of unique_ids to their required checks
- Service availability analysis and recommendations

Usage:
    python service_compliance_mapper.py --services "ec2,s3,iam,rds" --output compliance_analysis.json
"""

import pandas as pd
import json
import argparse
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

class ServiceComplianceMapper:
    def __init__(self, csv_file_path):
        """
        Initialize the mapper with the compliance CSV file
        
        Args:
            csv_file_path (str): Path to the compliance CSV file
        """
        self.csv_file_path = csv_file_path
        self.df = None
        self.load_data()
    
    def load_data(self):
        """Load and validate the compliance CSV data"""
        try:
            self.df = pd.read_csv(self.csv_file_path)
            print(f"✅ Loaded {len(self.df)} compliance entries from {self.csv_file_path}")
        except FileNotFoundError:
            print(f"❌ Error: CSV file not found at {self.csv_file_path}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error loading CSV file: {str(e)}")
            sys.exit(1)
    
    def parse_json_field(self, field_value):
        """Safely parse JSON fields from CSV"""
        if pd.isna(field_value) or field_value == '':
            return []
        try:
            parsed = json.loads(field_value)
            return parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, TypeError):
            return []
    
    def generate_unique_key(self, row):
        """
        Generate a unique key for compliance entries that don't have one
        
        Args:
            row: DataFrame row containing compliance entry data
            
        Returns:
            str: Generated unique key
        """
        compliance_name = str(row.get('Compliance Name', '')).lower().replace(' ', '_')
        control_id = str(row.get('ID', '')).replace(' ', '_').replace('.', '_')
        
        # Clean up compliance name
        compliance_name = compliance_name.replace('_aws', '').replace('-', '_')
        
        # Generate key pattern: compliance_framework_control_id
        if compliance_name and control_id:
            return f"{compliance_name}_{control_id}".lower()
        elif compliance_name:
            return f"{compliance_name}_unknown".lower()
        else:
            return f"unknown_{control_id}".lower() if control_id else "unknown_control"
    
    def clean_field_value(self, value):
        """
        Clean field values to handle NaN, None, and empty strings
        
        Args:
            value: Raw field value
            
        Returns:
            str or None: Cleaned value
        """
        if pd.isna(value) or value == '' or str(value).lower() in ['nan', 'none']:
            return None
        return str(value).strip()

    def map_function_to_service(self, function_name):
        """
        Map a function name to its actual AWS service based on function prefix
        
        Args:
            function_name (str): The function name to map
            
        Returns:
            str or None: The AWS service name or None if not mappable
        """
        if not function_name:
            return None
            
        # Extract service prefix from function name
        if '_' in function_name:
            service_prefix = function_name.split('_')[0]
            
            # Handle special cases
            if service_prefix == 'awslambda':
                return 'lambda'
            elif service_prefix == 'opensearch':
                return 'opensearch'
            elif service_prefix == 'apigateway':
                return 'apigateway'
            elif service_prefix == 'apigatewayv2':
                return 'apigatewayv2'
            elif service_prefix == 'elasticbeanstalk':
                return 'elasticbeanstalk'
            elif service_prefix == 'elasticache':
                return 'elasticache'
            elif service_prefix == 'networkfirewall':
                return 'networkfirewall'
            elif service_prefix == 'stepfunctions':
                return 'stepfunctions'
            elif service_prefix == 'secretsmanager':
                return 'secretsmanager'
            elif service_prefix == 'account':
                return 'account'
            elif service_prefix == 'accessanalyzer':
                return 'accessanalyzer'
            else:
                return service_prefix
        
        return None

    def analyze_service_availability(self, available_services):
        """
        Analyze compliance checks based on service availability
        
        Args:
            available_services (list): List of available AWS services
            
        Returns:
            dict: Comprehensive analysis results
        """
        available_services_lower = [service.lower().strip() for service in available_services]
        
        analysis_results = {
            "metadata": {
                "analysis_timestamp": datetime.now().isoformat(),
                "available_services": available_services,
                "total_compliance_entries": len(self.df),
                "csv_source": self.csv_file_path
            },
            "summary": {
                "runnable_checks": 0,
                "not_applicable_checks": 0,
                "manual_checks": 0,
                "total_unique_functions": 0,
                "missing_services_impact": {}
            },
            "runnable_compliance_checks": [],
            "not_applicable_checks": [],
            "manual_verification_required": [],
            "service_to_functions_mapping": {},
            "unique_functions_to_execute": [],
            "recommendations": {
                "immediate_actions": [],
                "service_additions": [],
                "manual_priorities": []
            }
        }
        
        # Track unique functions and service mappings
        all_runnable_functions = set()
        service_function_map = defaultdict(set)
        missing_services_count = defaultdict(int)
        
        for _, row in self.df.iterrows():
            applied_services = self.parse_json_field(row.get('applied_services', ''))
            checks = self.parse_json_field(row.get('Checks', ''))
            
            # Handle unique_key generation
            unique_key = self.clean_field_value(row.get('unique_key', ''))
            if not unique_key:
                unique_key = self.generate_unique_key(row)
            
            # Handle name field
            name = self.clean_field_value(row.get('Name', ''))
            
            # Handle description
            description = self.clean_field_value(row.get('Description', ''))
            if description and len(description) > 200:
                description = description[:200] + '...'
            
            compliance_entry = {
                "unique_key": unique_key,
                "compliance_name": self.clean_field_value(row.get('Compliance Name', '')),
                "control_id": self.clean_field_value(row.get('ID', '')),
                "name": name,
                "description": description,
                "required_services": applied_services,
                "functions_to_execute": checks,
                "total_functions": len(checks),
                "data_security_tags": self.clean_field_value(row.get('data_security', ''))
            }
            
            # Handle manual checks
            if not applied_services or applied_services == ['manual']:
                compliance_entry["status"] = "manual_verification_required"
                compliance_entry["reason"] = "Manual verification or organizational control required"
                analysis_results["manual_verification_required"].append(compliance_entry)
                analysis_results["summary"]["manual_checks"] += 1
                continue
            
            # Check service availability
            required_services_lower = [svc.lower().strip() for svc in applied_services]
            available_required = [svc for svc in required_services_lower if svc in available_services_lower]
            missing_services = [svc for svc in required_services_lower if svc not in available_services_lower]
            
            compliance_entry["available_services"] = available_required
            compliance_entry["missing_services"] = missing_services
            
            if not missing_services:
                # All services available - can execute
                compliance_entry["status"] = "ready_to_execute"
                compliance_entry["reason"] = "All required services are available"
                analysis_results["runnable_compliance_checks"].append(compliance_entry)
                analysis_results["summary"]["runnable_checks"] += 1
                
                # Track functions to execute
                all_runnable_functions.update(checks)
                
                # Map functions to their actual services based on function names
                for function_name in checks:
                    actual_service = self.map_function_to_service(function_name)
                    if actual_service and actual_service.lower() in available_services_lower:
                        service_function_map[actual_service.lower()].add(function_name)
                
            else:
                # Missing services - not applicable
                compliance_entry["status"] = "not_applicable"
                compliance_entry["reason"] = f"Missing required services: {', '.join(missing_services)}"
                analysis_results["not_applicable_checks"].append(compliance_entry)
                analysis_results["summary"]["not_applicable_checks"] += 1
                
                # Track missing services impact
                for missing_svc in missing_services:
                    missing_services_count[missing_svc] += 1
        
        # Convert service mappings to lists and create final mappings
        for service, functions in service_function_map.items():
            analysis_results["service_to_functions_mapping"][service] = {
                "total_functions": len(functions),
                "functions": sorted(list(functions))
            }
        
        # Create final list of unique functions to execute
        analysis_results["unique_functions_to_execute"] = sorted(list(all_runnable_functions))
        analysis_results["summary"]["total_unique_functions"] = len(all_runnable_functions)
        
        # Missing services impact
        analysis_results["summary"]["missing_services_impact"] = dict(missing_services_count)
        
        # Generate recommendations
        self._generate_recommendations(analysis_results, missing_services_count)
        
        return analysis_results
    
    def _generate_recommendations(self, analysis_results, missing_services_count):
        """Generate actionable recommendations based on analysis"""
        
        # Immediate actions
        if analysis_results["summary"]["runnable_checks"] > 0:
            analysis_results["recommendations"]["immediate_actions"].append({
                "action": "execute_compliance_checks",
                "description": f"Execute {analysis_results['summary']['total_unique_functions']} unique compliance functions across {analysis_results['summary']['runnable_checks']} compliance controls",
                "priority": "high"
            })
        
        if analysis_results["summary"]["manual_checks"] > 0:
            analysis_results["recommendations"]["immediate_actions"].append({
                "action": "manual_verification_planning",
                "description": f"Plan manual verification for {analysis_results['summary']['manual_checks']} compliance controls that require organizational processes",
                "priority": "medium"
            })
        
        # Service addition recommendations
        top_missing_services = sorted(missing_services_count.items(), key=lambda x: x[1], reverse=True)[:5]
        for service, impact_count in top_missing_services:
            analysis_results["recommendations"]["service_additions"].append({
                "service": service,
                "impact": f"Would enable {impact_count} additional compliance checks",
                "priority": "high" if impact_count > 50 else "medium" if impact_count > 20 else "low"
            })
        
        # Manual verification priorities
        manual_frameworks = defaultdict(int)
        for manual_check in analysis_results["manual_verification_required"]:
            manual_frameworks[manual_check["compliance_name"]] += 1
        
        for framework, count in sorted(manual_frameworks.items(), key=lambda x: x[1], reverse=True)[:3]:
            analysis_results["recommendations"]["manual_priorities"].append({
                "framework": framework,
                "manual_checks_count": count,
                "recommendation": f"Prioritize manual verification for {framework} framework ({count} checks)"
            })
    
    def generate_execution_checklist(self, analysis_results):
        """Generate a practical execution checklist"""
        
        checklist = {
            "execution_summary": {
                "total_functions_to_run": analysis_results["summary"]["total_unique_functions"],
                "total_compliance_checks": analysis_results["summary"]["runnable_checks"],
                "estimated_execution_time": f"{analysis_results['summary']['total_unique_functions'] * 2} minutes (estimated)",
                "services_involved": list(analysis_results["service_to_functions_mapping"].keys())
            },
            "execution_plan": [],
            "validation_steps": [
                "Verify all required AWS services are accessible",
                "Ensure proper IAM permissions for compliance scanning",
                "Test connectivity to AWS APIs",
                "Prepare logging and monitoring for compliance execution"
            ]
        }
        
        # Group functions by service for organized execution
        for service, mapping in analysis_results["service_to_functions_mapping"].items():
            if mapping["functions"]:
                checklist["execution_plan"].append({
                    "service": service,
                    "functions_count": mapping["total_functions"],
                    "functions": mapping["functions"],
                    "execution_order": len(checklist["execution_plan"]) + 1
                })
        
        return checklist
    
    def save_results(self, analysis_results, output_file, include_checklist=True):
        """Save analysis results to JSON file"""
        
        final_output = {
            "service_compliance_analysis": analysis_results
        }
        
        if include_checklist:
            final_output["execution_checklist"] = self.generate_execution_checklist(analysis_results)
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(final_output, f, indent=2, ensure_ascii=False)
            
            print(f"✅ Analysis results saved to: {output_file}")
            return True
            
        except Exception as e:
            print(f"❌ Error saving results: {str(e)}")
            return False
    
    def print_summary(self, analysis_results):
        """Print a summary of the analysis results"""
        
        print("\n" + "="*80)
        print("🔍 SERVICE-BASED COMPLIANCE ANALYSIS SUMMARY")
        print("="*80)
        
        metadata = analysis_results["metadata"]
        summary = analysis_results["summary"]
        
        print(f"📊 Analysis Details:")
        print(f"   • Available Services: {', '.join(metadata['available_services'])}")
        print(f"   • Total Compliance Entries: {metadata['total_compliance_entries']}")
        print(f"   • Analysis Timestamp: {metadata['analysis_timestamp']}")
        
        print(f"\n📈 Execution Summary:")
        print(f"   ✅ Ready to Execute: {summary['runnable_checks']} compliance checks")
        print(f"   🎯 Unique Functions to Run: {summary['total_unique_functions']}")
        print(f"   ❌ Not Applicable: {summary['not_applicable_checks']} (missing services)")
        print(f"   📝 Manual Verification: {summary['manual_checks']} (organizational controls)")
        
        if summary.get('missing_services_impact'):
            print(f"\n🚫 Top Missing Services (Impact):")
            sorted_missing = sorted(summary['missing_services_impact'].items(), key=lambda x: x[1], reverse=True)
            for service, count in sorted_missing[:5]:
                print(f"   • {service}: affects {count} compliance checks")
        
        if analysis_results.get('service_to_functions_mapping'):
            print(f"\n📦 Service Function Distribution:")
            for service, mapping in list(analysis_results['service_to_functions_mapping'].items())[:5]:
                print(f"   • {service}: {mapping['total_functions']} functions")
        
        print(f"\n🎯 Next Steps:")
        for i, action in enumerate(analysis_results['recommendations']['immediate_actions'], 1):
            print(f"   {i}. {action['description']} (Priority: {action['priority']})")

def main():
    parser = argparse.ArgumentParser(description='Generate compliance checks based on available AWS services')
    parser.add_argument('--services', required=True, 
                       help='Comma-separated list of available AWS services (e.g., "ec2,s3,iam,rds")')
    parser.add_argument('--output', default='service_compliance_analysis.json',
                       help='Output JSON file path (default: service_compliance_analysis.json)')
    parser.add_argument('--csv', 
                       default='compliance_checks_updated.csv',
                       help='Input CSV file path (default: compliance_checks_updated.csv)')
    parser.add_argument('--no-checklist', action='store_true',
                       help='Exclude execution checklist from output')
    parser.add_argument('--quiet', action='store_true',
                       help='Suppress summary output')
    
    args = parser.parse_args()
    
    # Parse services
    available_services = [service.strip() for service in args.services.split(',') if service.strip()]
    
    if not available_services:
        print("❌ Error: No services provided. Use --services to specify available AWS services.")
        sys.exit(1)
    
    # Resolve file paths
    script_dir = Path(__file__).parent
    csv_file = script_dir / args.csv
    output_file = script_dir / args.output
    
    if not csv_file.exists():
        print(f"❌ Error: CSV file not found at {csv_file}")
        print("   Available files in directory:")
        for file in script_dir.glob("*.csv"):
            print(f"   - {file.name}")
        sys.exit(1)
    
    # Initialize mapper and run analysis
    mapper = ServiceComplianceMapper(str(csv_file))
    
    print(f"🔍 Analyzing compliance requirements for services: {', '.join(available_services)}")
    analysis_results = mapper.analyze_service_availability(available_services)
    
    # Save results
    success = mapper.save_results(
        analysis_results, 
        str(output_file), 
        include_checklist=not args.no_checklist
    )
    
    if success and not args.quiet:
        mapper.print_summary(analysis_results)
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())