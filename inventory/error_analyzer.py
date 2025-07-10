#!/usr/bin/env python3
"""
Advanced AWS Inventory Error Analyzer
Analyzes error patterns from inventory scans and provides actionable insights
Can be run standalone or integrated with service enablement checker
"""
import pandas as pd
import json
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime
import csv
import sys
import os

class InventoryErrorAnalyzer:
    """Advanced error analysis for AWS inventory scans"""
    
    def __init__(self, error_csv_path=None, scan_output_dir=None):
        self.error_csv_path = error_csv_path
        self.scan_output_dir = scan_output_dir
        self.df = None
        self.analysis_results = {}
        self.scan_metadata = {}
        
    def auto_discover_latest_scan(self):
        """Auto-discover the latest scan results directory"""
        inventory_dir = Path(__file__).parent
        
        # Look for service_enablement_results directory
        results_dir = inventory_dir / "service_enablement_results"
        if not results_dir.exists():
            return None
            
        # Find latest scan directory
        scan_dirs = [d for d in results_dir.iterdir() if d.is_dir() and d.name.startswith('scan_')]
        if not scan_dirs:
            return None
            
        # Check for latest_scan symlink first
        latest_link = results_dir / "latest_scan"
        if latest_link.exists() and latest_link.is_symlink():
            latest_scan_dir = latest_link.resolve()
            if latest_scan_dir.exists():
                return latest_scan_dir
        
        # Fall back to most recent directory
        latest_scan_dir = max(scan_dirs, key=lambda x: x.stat().st_mtime)
        return latest_scan_dir
    
    def load_error_data(self, csv_path=None, scan_dir=None):
        """Load error data from CSV file with auto-discovery"""
        if csv_path:
            self.error_csv_path = csv_path
        elif scan_dir:
            self.scan_output_dir = scan_dir
            # Look for error CSV in the scan directory
            error_logs_dir = scan_dir / "error_logs"
            if error_logs_dir.exists():
                error_files = list(error_logs_dir.glob("errors_summary*.csv"))
                if error_files:
                    self.error_csv_path = max(error_files, key=lambda x: x.stat().st_mtime)
        
        # Auto-discover if no path provided
        if not self.error_csv_path and not self.scan_output_dir:
            auto_scan_dir = self.auto_discover_latest_scan()
            if auto_scan_dir:
                self.scan_output_dir = auto_scan_dir
                error_logs_dir = auto_scan_dir / "error_logs"
                if error_logs_dir.exists():
                    error_files = list(error_logs_dir.glob("errors_summary*.csv"))
                    if error_files:
                        self.error_csv_path = max(error_files, key=lambda x: x.stat().st_mtime)
                        print(f"📊 Auto-discovered scan directory: {auto_scan_dir}")
                        print(f"📊 Auto-discovered error file: {self.error_csv_path}")
        
        # Load scan metadata if available
        if self.scan_output_dir:
            self._load_scan_metadata()
        
        if self.error_csv_path and Path(self.error_csv_path).exists():
            self.df = pd.read_csv(self.error_csv_path)
            print(f"✅ Loaded {len(self.df)} error records from {self.error_csv_path.name}")
            return True
        else:
            print("❌ No error CSV file found")
            return False
    
    def _load_scan_metadata(self):
        """Load scan metadata from the scan directory"""
        if not self.scan_output_dir:
            return
            
        # Look for scan session reference
        session_files = list(self.scan_output_dir.glob("scan_session_reference_*.json"))
        if session_files:
            session_file = max(session_files, key=lambda x: x.stat().st_mtime)
            try:
                with open(session_file, 'r') as f:
                    self.scan_metadata = json.load(f)
                print(f"📋 Loaded scan metadata from {session_file.name}")
            except Exception as e:
                print(f"⚠️  Could not load scan metadata: {e}")
    
    def analyze_error_patterns(self):
        """Comprehensive error pattern analysis"""
        if self.df is None:
            print("❌ No data loaded. Call load_error_data() first.")
            return
        
        analysis = {
            'total_errors': len(self.df),
            'unique_accounts': self.df['Account'].nunique(),
            'unique_regions': self.df['Region'].nunique(),
            'unique_services': self.df['Service'].nunique(),
            'error_categories': self.df['ErrorType'].value_counts().to_dict(),
            'top_failing_services': self.df['Service'].value_counts().head(10).to_dict(),
            'top_failing_regions': self.df['Region'].value_counts().head(10).to_dict(),
            'parameter_validation_issues': self._analyze_parameter_validation(),
            'function_not_found_issues': self._analyze_function_not_found(),
            'scan_performance_analysis': self._analyze_scan_performance(),
            'recommendations': self._generate_recommendations()
        }
        
        self.analysis_results = analysis
        return analysis
    
    def _analyze_scan_performance(self):
        """Analyze scan performance based on scan metadata and errors"""
        if not self.scan_metadata:
            return {'available': False}
        
        performance_analysis = {
            'available': True,
            'scan_duration_minutes': self.scan_metadata.get('scan_duration_minutes', 0),
            'total_api_calls': self.scan_metadata.get('total_api_calls', 0),
            'success_rate': self.scan_metadata.get('success_rate', 0),
            'calls_per_minute': 0,
            'error_rate': 0,
            'efficiency_metrics': {}
        }
        
        # Calculate performance metrics
        if performance_analysis['scan_duration_minutes'] > 0:
            performance_analysis['calls_per_minute'] = performance_analysis['total_api_calls'] / performance_analysis['scan_duration_minutes']
        
        if performance_analysis['total_api_calls'] > 0:
            performance_analysis['error_rate'] = (len(self.df) / performance_analysis['total_api_calls']) * 100
        
        # Efficiency categorization
        if performance_analysis['success_rate'] >= 85:
            efficiency = "EXCELLENT"
        elif performance_analysis['success_rate'] >= 70:
            efficiency = "GOOD"
        elif performance_analysis['success_rate'] >= 50:
            efficiency = "FAIR"
        else:
            efficiency = "POOR"
        
        performance_analysis['efficiency_metrics'] = {
            'overall_efficiency': efficiency,
            'scan_speed': 'FAST' if performance_analysis['calls_per_minute'] > 100 else 'MODERATE' if performance_analysis['calls_per_minute'] > 50 else 'SLOW',
            'error_impact': 'LOW' if performance_analysis['error_rate'] < 10 else 'MEDIUM' if performance_analysis['error_rate'] < 25 else 'HIGH'
        }
        
        return performance_analysis
    
    def _analyze_parameter_validation(self):
        """Analyze parameter validation errors in detail"""
        param_errors = self.df[self.df['ErrorType'] == 'parameter_validation']
        
        if param_errors.empty:
            return {'count': 0, 'services': {}}
        
        # Extract missing parameters from error messages
        missing_params = defaultdict(list)
        
        for _, row in param_errors.iterrows():
            service = row['Service']
            function = row['Function']
            message = row['ErrorMessage']
            
            # Parse missing parameters from error message
            if 'Missing required parameter' in message:
                # Extract parameter names between quotes
                import re
                params = re.findall(r'"([^"]*)"', message)
                missing_params[f"{service}.{function}"].extend(params)
        
        # Consolidate missing parameters
        consolidated = {}
        for func, params in missing_params.items():
            consolidated[func] = {
                'missing_params': list(set(params)),
                'occurrence_count': len(params),
                'sample_functions': list(set([p for p in params if not p.startswith('Missing')]))
            }
        
        return {
            'count': len(param_errors),
            'affected_services': param_errors['Service'].nunique(),
            'missing_parameters_by_function': consolidated,
            'most_common_missing_params': Counter([p for params in missing_params.values() for p in params]).most_common(10)
        }
    
    def _analyze_function_not_found(self):
        """Analyze function not found errors"""
        func_errors = self.df[self.df['ErrorType'] == 'function_not_found']
        
        if func_errors.empty:
            return {'count': 0, 'functions': {}}
        
        # Group by service and function
        func_analysis = defaultdict(list)
        for _, row in func_errors.iterrows():
            service = row['Service']
            function = row['Function']
            func_analysis[service].append(function)
        
        # Find functions that don't exist in boto3
        invalid_functions = {}
        for service, functions in func_analysis.items():
            invalid_functions[service] = {
                'functions': list(set(functions)),
                'count': len(functions),
                'regions_affected': func_errors[func_errors['Service'] == service]['Region'].nunique()
            }
        
        return {
            'count': len(func_errors),
            'affected_services': len(invalid_functions),
            'invalid_functions_by_service': invalid_functions,
            'most_problematic_services': dict(Counter([row['Service'] for _, row in func_errors.iterrows()]).most_common(5))
        }
    
    def _generate_recommendations(self):
        """Generate actionable recommendations based on error analysis"""
        recommendations = []
        
        # Performance-based recommendations
        if self.scan_metadata:
            success_rate = self.scan_metadata.get('success_rate', 0)
            scan_duration = self.scan_metadata.get('scan_duration_minutes', 0)
            
            if success_rate < 70:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Scan Performance',
                    'issue': f'Low API success rate ({success_rate:.1f}%)',
                    'description': 'Many AWS API calls are failing, indicating systematic issues',
                    'solutions': [
                        'Review AWS credentials and permissions',
                        'Check service enablement across regions',
                        'Reduce concurrent workers to avoid rate limiting',
                        'Increase timeout values for slow regions'
                    ],
                    'immediate_action': 'Run with reduced workers (5-10) and increased timeout (45s)'
                })
            
            if scan_duration > 30:  # More than 30 minutes
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'Scan Efficiency',
                    'issue': f'Long scan duration ({scan_duration:.1f} minutes)',
                    'description': 'Scan is taking longer than optimal for enterprise efficiency',
                    'solutions': [
                        'Increase concurrent workers if success rate is good',
                        'Focus on specific regions or services',
                        'Use service filtering to scan only required services',
                        'Consider parallel account scanning'
                    ],
                    'immediate_action': 'Increase workers to 20-25 if success rate > 80%'
                })

        # Parameter validation recommendations
        param_errors = len(self.df[self.df['ErrorType'] == 'parameter_validation'])
        if param_errors > 50:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Parameter Validation',
                'issue': f'{param_errors} parameter validation errors detected',
                'description': 'Many AWS API functions require specific parameters that are not being provided',
                'solutions': [
                    'Update service_enablement_mapping.json to include required parameters',
                    'Implement parameter builders for complex functions',
                    'Use conditional parameter passing based on service requirements',
                    'Consider skipping parameterized functions in initial scans'
                ],
                'affected_functions': self.df[self.df['ErrorType'] == 'parameter_validation']['Function'].nunique(),
                'immediate_action': 'Clean service mapping to remove functions requiring parameters'
            })
        
        # Function not found recommendations
        func_errors = len(self.df[self.df['ErrorType'] == 'function_not_found'])
        if func_errors > 20:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Function Availability',
                'issue': f'{func_errors} function not found errors',
                'description': 'Service mapping references functions that do not exist in current boto3 version',
                'solutions': [
                    'Validate all functions in service_enablement_mapping.json against current boto3',
                    'Remove non-existent functions from mapping',
                    'Update boto3 to latest version',
                    'Use dynamic function discovery instead of static mapping'
                ],
                'affected_services': self.df[self.df['ErrorType'] == 'function_not_found']['Service'].nunique(),
                'immediate_action': 'Run: pip install --upgrade boto3 botocore'
            })
        
        # Service-specific recommendations
        service_errors = self.df['Service'].value_counts()
        top_problematic = service_errors.head(3)
        
        for service, count in top_problematic.items():
            if count > 30:  # Threshold for problematic services
                service_error_types = self.df[self.df['Service'] == service]['ErrorType'].value_counts()
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': f'Service-Specific ({service})',
                    'issue': f'{service} has {count} errors across regions',
                    'description': f'Service {service} shows consistent failure patterns',
                    'solutions': [
                        f'Review {service} service configuration in mapping',
                        f'Check if {service} requires special permissions or setup',
                        f'Consider service-specific parameter handling for {service}',
                        f'Investigate regional availability of {service}'
                    ],
                    'error_breakdown': service_error_types.to_dict(),
                    'immediate_action': f'Remove {service} from mapping temporarily if not critical'
                })
        
        return recommendations
    
    def create_service_mapping_fixes(self):
        """Generate fixes for service_enablement_mapping.json"""
        if self.df is None:
            return None
        
        # Find functions that consistently fail
        function_failures = defaultdict(int)
        for _, row in self.df.iterrows():
            if row['ErrorType'] in ['function_not_found', 'parameter_validation']:
                function_failures[f"{row['Service']}.{row['Function']}"] += 1
        
        # Generate mapping fixes
        fixes = {
            'functions_to_remove': [],
            'functions_needing_parameters': {},
            'recommended_alternatives': {}
        }
        
        # Functions to remove (consistent function_not_found)
        for func_key, count in function_failures.items():
            if count > 5:  # Threshold for removal
                service, function = func_key.split('.', 1)
                error_types = self.df[
                    (self.df['Service'] == service) & 
                    (self.df['Function'] == function)
                ]['ErrorType'].unique()
                
                if 'function_not_found' in error_types:
                    fixes['functions_to_remove'].append(func_key)
        
        # Functions needing parameters
        param_errors = self.df[self.df['ErrorType'] == 'parameter_validation']
        for _, row in param_errors.iterrows():
            func_key = f"{row['Service']}.{row['Function']}"
            if func_key not in fixes['functions_needing_parameters']:
                fixes['functions_needing_parameters'][func_key] = {
                    'error_count': 0,
                    'sample_error': row['ErrorMessage']
                }
            fixes['functions_needing_parameters'][func_key]['error_count'] += 1
        
        return fixes
    
    def generate_report(self, output_file=None):
        """Generate comprehensive error analysis report"""
        if not self.analysis_results:
            self.analyze_error_patterns()
        
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'scan_metadata': self.scan_metadata,
            'summary': {
                'total_errors': self.analysis_results['total_errors'],
                'unique_accounts': self.analysis_results['unique_accounts'],
                'unique_regions': self.analysis_results['unique_regions'],
                'unique_services': self.analysis_results['unique_services']
            },
            'error_breakdown': self.analysis_results['error_categories'],
            'top_failing_services': self.analysis_results['top_failing_services'],
            'parameter_validation_analysis': self.analysis_results['parameter_validation_issues'],
            'function_availability_analysis': self.analysis_results['function_not_found_issues'],
            'scan_performance_analysis': self.analysis_results.get('scan_performance_analysis', {}),
            'actionable_recommendations': self.analysis_results['recommendations'],
            'service_mapping_fixes': self.create_service_mapping_fixes()
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"📊 Report saved to: {output_file}")
        
        return report
    
    def print_summary(self):
        """Print a concise summary of the error analysis"""
        if not self.analysis_results:
            self.analyze_error_patterns()
        
        print(f"\n{'='*80}")
        print(f"🔍 AWS INVENTORY ERROR ANALYSIS SUMMARY")
        print(f"{'='*80}")
        
        # Overview
        print(f"📊 OVERVIEW:")
        print(f"   Total Errors: {self.analysis_results['total_errors']:,}")
        print(f"   Unique Services: {self.analysis_results['unique_services']}")
        print(f"   Unique Regions: {self.analysis_results['unique_regions']}")
        
        # Error categories
        print(f"\n🏷️  ERROR CATEGORIES:")
        for error_type, count in list(self.analysis_results['error_categories'].items())[:5]:
            percentage = (count / self.analysis_results['total_errors'] * 100)
            print(f"   {error_type}: {count:,} ({percentage:.1f}%)")
        
        # Top recommendations
        print(f"\n💡 TOP RECOMMENDATIONS:")
        for i, rec in enumerate(self.analysis_results['recommendations'][:3], 1):
            print(f"   {i}. [{rec['priority']}] {rec['issue']}")
            print(f"      Solution: {rec['solutions'][0]}")
        
        print(f"{'='*80}")

    def explain_scan_parameters(self):
        """Explain what 'Customize scan parameters' means"""
        print(f"\n{'='*80}")
        print(f"🔧 UNDERSTANDING 'CUSTOMIZE SCAN PARAMETERS'")
        print(f"{'='*80}")
        
        print(f"\n📋 When the Enterprise Scanner asks 'Customize scan parameters? (y/n)', it's offering to adjust:")
        
        print(f"\n1. 🧵 MAX CONCURRENT WORKERS (Default: 15)")
        print(f"   • Controls how many AWS API calls run simultaneously")
        print(f"   • Higher = Faster scanning but more resource intensive")
        print(f"   • Lower = Slower scanning but more stable")
        print(f"   • Range: 1-50 workers")
        print(f"   • Recommended: 10-20 for most environments")
        
        print(f"\n2. ⏱️  TIMEOUT PER API CALL (Default: 30 seconds)")
        print(f"   • How long to wait for each AWS API response")
        print(f"   • Too low = More timeout errors")
        print(f"   • Too high = Slower failure detection")
        print(f"   • Recommended: 15-45 seconds")
        
        print(f"\n3. 🔄 MAX RETRIES (Default: 3)")
        print(f"   • How many times to retry failed API calls")
        print(f"   • Higher = More resilient to temporary failures")
        print(f"   • Lower = Faster completion but less error recovery")
        print(f"   • Recommended: 2-5 retries")
        
        print(f"\n💡 WHEN TO CUSTOMIZE:")
        print(f"   ✅ Large environments (1000+ resources): Increase workers to 20-30")
        print(f"   ✅ Slow network connections: Increase timeout to 45-60 seconds")
        print(f"   ✅ High error rates: Increase retries to 5")
        print(f"   ✅ Rate limiting issues: Decrease workers to 5-10")
        print(f"   ❌ First-time scanning: Use defaults (just press 'n')")
        
        print(f"\n🎯 FOR YOUR CURRENT SITUATION:")
        param_errors = self.analysis_results.get('error_categories', {}).get('parameter_validation', 0)
        func_errors = self.analysis_results.get('error_categories', {}).get('function_not_found', 0)
        
        if param_errors > 100:
            print(f"   🚨 High parameter validation errors ({param_errors})")
            print(f"   📝 Recommendation: Use default settings but fix service mapping first")
        elif func_errors > 50:
            print(f"   🚨 Many function not found errors ({func_errors})")
            print(f"   📝 Recommendation: Clean up service mapping before optimization")
        else:
            print(f"   ✅ Error levels are manageable")
            print(f"   📝 Recommendation: You can safely increase workers to 20 for faster scanning")
        
        print(f"{'='*80}")

    def explain_next_steps(self):
        """Provide clear next steps based on the analysis"""
        if not self.analysis_results:
            self.analyze_error_patterns()
        
        print(f"\n{'='*80}")
        print(f"🎯 RECOMMENDED NEXT STEPS BASED ON ANALYSIS")
        print(f"{'='*80}")
        
        recommendations = self.analysis_results.get('recommendations', [])
        
        if not recommendations:
            print(f"✅ No critical issues found! Your scan performed well.")
            return
        
        # Sort by priority
        high_priority = [r for r in recommendations if r['priority'] == 'HIGH']
        medium_priority = [r for r in recommendations if r['priority'] == 'MEDIUM']
        
        if high_priority:
            print(f"\n🚨 HIGH PRIORITY ACTIONS (Do These First):")
            for i, rec in enumerate(high_priority, 1):
                print(f"\n   {i}. {rec['issue']}")
                print(f"      💡 Quick Fix: {rec.get('immediate_action', 'See solutions below')}")
                print(f"      📋 Category: {rec['category']}")
                if len(rec['solutions']) > 0:
                    print(f"      🔧 Primary Solution: {rec['solutions'][0]}")
        
        if medium_priority:
            print(f"\n⚠️  MEDIUM PRIORITY ACTIONS (Do These After High Priority):")
            for i, rec in enumerate(medium_priority, 1):
                print(f"\n   {i}. {rec['issue']}")
                print(f"      💡 Quick Fix: {rec.get('immediate_action', 'See solutions below')}")
                print(f"      📋 Category: {rec['category']}")
        
        # Performance insights
        perf = self.analysis_results.get('scan_performance_analysis', {})
        if perf.get('available'):
            print(f"\n📊 SCAN PERFORMANCE INSIGHTS:")
            efficiency = perf.get('efficiency_metrics', {})
            print(f"   Overall Efficiency: {efficiency.get('overall_efficiency', 'Unknown')}")
            print(f"   Scan Speed: {efficiency.get('scan_speed', 'Unknown')}")
            print(f"   Error Impact: {efficiency.get('error_impact', 'Unknown')}")
            
            if efficiency.get('overall_efficiency') == 'EXCELLENT':
                print(f"   🎉 Great job! Consider increasing workers for even faster scans.")
            elif efficiency.get('overall_efficiency') in ['GOOD', 'FAIR']:
                print(f"   📈 Room for improvement. Focus on high priority items above.")
            else:
                print(f"   🚨 Significant issues detected. Address high priority items immediately.")
        
        print(f"\n💡 GENERAL OPTIMIZATION TIPS:")
        print(f"   • For your next scan, consider these parameter adjustments:")
        
        if self.scan_metadata:
            success_rate = self.scan_metadata.get('success_rate', 0)
            if success_rate > 80:
                print(f"     - Increase workers to 20-25 (current success rate is good)")
            elif success_rate > 60:
                print(f"     - Keep current workers, increase timeout to 45 seconds")
            else:
                print(f"     - Reduce workers to 5-10, increase timeout to 60 seconds")
                print(f"     - Fix mapping issues first before optimizing")
        
        print(f"   • Clean up service_enablement_mapping.json based on function_not_found errors")
        print(f"   • Monitor AWS service health during scans")
        print(f"   • Consider regional scanning during off-peak hours")
        
        print(f"{'='*80}")

# Integration function for the service enablement checker
def run_post_scan_analysis(scan_output_dir, scan_metadata=None):
    """
    Run error analysis after a service enablement scan completes
    This function is called by the simplified_service_enablement_checker
    """
    print(f"\n🔍 Starting Post-Scan Error Analysis...")
    
    # Initialize analyzer with scan directory
    analyzer = InventoryErrorAnalyzer(scan_output_dir=scan_output_dir)
    
    # Load error data
    if analyzer.load_error_data():
        # Run comprehensive analysis
        analyzer.analyze_error_patterns()
        
        # Print summary and next steps
        analyzer.print_summary()
        analyzer.explain_scan_parameters()
        analyzer.explain_next_steps()
        
        # Generate detailed report in the scan directory
        if scan_output_dir:
            report_file = scan_output_dir / f"error_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            analyzer.generate_report(str(report_file))
            
            # Generate service mapping fixes
            fixes = analyzer.create_service_mapping_fixes()
            if fixes:
                fixes_file = scan_output_dir / f"service_mapping_fixes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(fixes_file, 'w') as f:
                    json.dump(fixes, f, indent=2)
                print(f"🔧 Service mapping fixes saved to: {fixes_file}")
        
        return analyzer.analysis_results
    else:
        print("❌ No errors to analyze (this might be good news!)")
        return None

def main():
    """Main execution function"""
    print("🔍 AWS Inventory Error Analyzer & Scan Parameter Guide")
    
    # Try to auto-discover latest scan first
    analyzer = InventoryErrorAnalyzer()
    
    # Load and analyze data
    if analyzer.load_error_data():
        analyzer.analyze_error_patterns()
        analyzer.explain_scan_parameters()
        analyzer.print_summary()
        analyzer.explain_next_steps()
        
        # Generate detailed report
        if analyzer.scan_output_dir:
            report_file = analyzer.scan_output_dir / f"error_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        else:
            report_file = Path(__file__).parent / f"error_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        analyzer.generate_report(str(report_file))
        
        # Generate service mapping fixes
        fixes = analyzer.create_service_mapping_fixes()
        if fixes and analyzer.scan_output_dir:
            fixes_file = analyzer.scan_output_dir / f"service_mapping_fixes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(fixes_file, 'w') as f:
                json.dump(fixes, f, indent=2)
            print(f"🔧 Service mapping fixes saved to: {fixes_file}")
    else:
        print("❌ Could not load error data")
        print("💡 Make sure you have run the service enablement checker first")

if __name__ == "__main__":
    main()
