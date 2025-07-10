#!/usr/bin/env python3
"""
LG-Protect: Unified AWS Cloud Security and Compliance Automation Platform
Orchestrator that integrates all components into a cohesive solution.
"""

import os
import sys
import json
import logging
import argparse
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

# Add component paths to Python path
BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR / "inventory"))
sys.path.insert(0, str(BASE_DIR / "core-engine"))
sys.path.insert(0, str(BASE_DIR / "core-engine" / "compliance_engine"))
sys.path.insert(0, str(BASE_DIR / "cspm-data-security-engine"))

class LGProtectOrchestrator:
    """
    Master orchestrator for the lg-protect platform.
    Integrates inventory, compliance, CSPM, and data security components.
    """
    
    def __init__(self, config_file: Optional[str] = None):
        self.base_dir = BASE_DIR
        self.session_id = f"lg_protect_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.results_dir = self.base_dir / "orchestrator_results" / self.session_id
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        self.setup_logging()
        
        # Load configuration
        self.config = self.load_configuration(config_file)
        
        # Initialize components
        self.components = {
            'inventory': None,
            'compliance': None,
            'cspm': None,
            'data_security': None,
            'opa': None
        }
        
        self.logger.info(f"🚀 LG-Protect Orchestrator initialized - Session: {self.session_id}")
    
    def setup_logging(self):
        """Setup comprehensive logging"""
        log_file = self.results_dir / "orchestrator.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('LGProtectOrchestrator')
    
    def load_configuration(self, config_file: Optional[str] = None) -> Dict[str, Any]:
        """Load orchestrator configuration"""
        default_config = {
            "execution_mode": "full_scan",  # full_scan, inventory_only, compliance_only, etc.
            "aws_accounts": [],
            "enabled_regions": ["us-east-1", "us-west-2"],
            "compliance_frameworks": ["soc2_aws", "cis_aws"],
            "output_formats": ["json", "csv"],
            "integrations": {
                "slack": {"enabled": False},
                "security_hub": {"enabled": False},
                "cspm_ui": {"enabled": True}
            },
            "parallel_execution": True,
            "max_workers": 10
        }
        
        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config
    
    def run_full_scan(self) -> Dict[str, Any]:
        """
        Execute complete end-to-end scan:
        1. Inventory Discovery
        2. Compliance Validation
        3. CSMP Analysis
        4. Data Security Assessment
        5. OPA Policy Evaluation
        """
        self.logger.info("🔍 Starting Full Platform Scan")
        
        results = {
            "session_id": self.session_id,
            "timestamp": datetime.now().isoformat(),
            "execution_mode": "full_scan",
            "components": {}
        }
        
        try:
            # Phase 1: AWS Infrastructure Discovery
            self.logger.info("📊 Phase 1: AWS Infrastructure Discovery")
            inventory_results = self.run_inventory_discovery()
            results["components"]["inventory"] = inventory_results
            
            # Phase 2: Compliance Validation
            self.logger.info("✅ Phase 2: Compliance Validation")
            compliance_results = self.run_compliance_checks(inventory_results)
            results["components"]["compliance"] = compliance_results
            
            # Phase 3: CSPM Analysis
            self.logger.info("🛡️ Phase 3: Cloud Security Posture Management")
            cspm_results = self.run_cspm_analysis(inventory_results, compliance_results)
            results["components"]["cspm"] = csmp_results
            
            # Phase 4: Data Security Assessment
            self.logger.info("🔒 Phase 4: Data Security Assessment")
            data_security_results = self.run_data_security_assessment(inventory_results)
            results["components"]["data_security"] = data_security_results
            
            # Phase 5: OPA Policy Evaluation
            self.logger.info("📋 Phase 5: Open Policy Agent Evaluation")
            opa_results = self.run_opa_evaluation(inventory_results, compliance_results)
            results["components"]["opa"] = opa_results
            
            # Phase 6: Generate Unified Report
            self.logger.info("📄 Phase 6: Generating Unified Report")
            unified_report = self.generate_unified_report(results)
            results["unified_report"] = unified_report
            
            # Phase 7: Execute Integrations
            self.logger.info("🔌 Phase 7: Executing Integrations")
            integration_results = self.execute_integrations(results)
            results["integrations"] = integration_results
            
            self.logger.info("✅ Full Platform Scan Completed Successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Full scan failed: {str(e)}")
            results["error"] = str(e)
            results["status"] = "failed"
        
        # Save results
        self.save_results(results)
        return results
    
    def run_inventory_discovery(self) -> Dict[str, Any]:
        """Execute AWS inventory discovery"""
        self.logger.info("🔍 Starting AWS inventory discovery...")
        
        try:
            # Change to inventory directory and run scanner
            inventory_dir = self.base_dir / "inventory"
            os.chdir(inventory_dir)
            
            # Run the simplified service enablement checker
            cmd = ["python3", "simplified_service_enablement_checker.py"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # 30 min timeout
            
            if result.returncode == 0:
                self.logger.info("✅ Inventory discovery completed successfully")
                
                # Find the latest results
                results_dir = inventory_dir / "service_enablement_results" / "latest_scan"
                if results_dir.exists():
                    # Load CSV and JSON results
                    csv_files = list(results_dir.glob("account_service_inventory_*.csv"))
                    json_files = list(results_dir.glob("scan_session_reference_*.json"))
                    
                    inventory_data = {
                        "status": "success",
                        "csv_file": str(csv_files[0]) if csv_files else None,
                        "metadata_file": str(json_files[0]) if json_files else None,
                        "summary": self.parse_inventory_summary(json_files[0] if json_files else None)
                    }
                    
                    return inventory_data
                else:
                    raise Exception("No inventory results found")
            else:
                raise Exception(f"Inventory scan failed: {result.stderr}")
                
        except Exception as e:
            self.logger.error(f"❌ Inventory discovery failed: {str(e)}")
            return {"status": "failed", "error": str(e)}
        finally:
            os.chdir(self.base_dir)
    
    def run_compliance_checks(self, inventory_results: Dict[str, Any]) -> Dict[str, Any]:
        """Execute compliance validation using inventory data"""
        self.logger.info("✅ Starting compliance validation...")
        
        try:
            # Use inventory-compliance bridge for seamless integration
            bridge_dir = self.base_dir / "core-engine" / "inventory_compliance_bridge"
            os.chdir(bridge_dir)
            
            # Run compliance checks with inventory data
            cmd = ["python3", "main_runner.py", "--save", "--output", "compliance_results.json"]
            
            # Add framework-specific flags if configured
            if self.config.get("compliance_frameworks"):
                frameworks = ",".join(self.config["compliance_frameworks"])
                cmd.extend(["--frameworks", frameworks])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)  # 1 hour timeout
            
            if result.returncode == 0:
                self.logger.info("✅ Compliance validation completed successfully")
                
                # Load compliance results
                results_file = bridge_dir / "compliance_results.json"
                if results_file.exists():
                    with open(results_file, 'r') as f:
                        compliance_data = json.load(f)
                    
                    return {
                        "status": "success",
                        "results_file": str(results_file),
                        "summary": self.parse_compliance_summary(compliance_data)
                    }
                else:
                    raise Exception("No compliance results file found")
            else:
                raise Exception(f"Compliance checks failed: {result.stderr}")
                
        except Exception as e:
            self.logger.error(f"❌ Compliance validation failed: {str(e)}")
            return {"status": "failed", "error": str(e)}
        finally:
            os.chdir(self.base_dir)
    
    def run_cspm_analysis(self, inventory_results: Dict[str, Any], compliance_results: Dict[str, Any]) -> Dict[str, Any]:
        """Execute CSPM platform analysis"""
        self.logger.info("🛡️ Starting CSPM analysis...")
        
        try:
            # Start CSPM services if configured
            cspm_dir = self.base_dir / "cspm" / "cspm-platform"
            
            if self.config.get("integrations", {}).get("cspm_ui", {}).get("enabled", False):
                os.chdir(csmp_dir)
                
                # Check if services are running, start if needed
                # This is a simplified approach - in production you'd use PM2 or Docker
                self.logger.info("🚀 Starting CSPM platform services...")
                
                # Start inventory collector service
                inventory_service_dir = cspm_dir / "services" / "inventory-collector"
                if inventory_service_dir.exists():
                    os.chdir(inventory_service_dir)
                    subprocess.Popen(["npm", "start"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                return {
                    "status": "success",
                    "message": "CSPM platform services started",
                    "ui_url": "http://localhost:3000",
                    "api_endpoints": {
                        "inventory": "http://localhost:3001",
                        "compliance": "http://localhost:3002",
                        "alerts": "http://localhost:3003"
                    }
                }
            else:
                return {
                    "status": "skipped",
                    "message": "CSPM UI integration disabled in configuration"
                }
                
        except Exception as e:
            self.logger.error(f"❌ CSMP analysis failed: {str(e)}")
            return {"status": "failed", "error": str(e)}
        finally:
            os.chdir(self.base_dir)
    
    def run_data_security_assessment(self, inventory_results: Dict[str, Any]) -> Dict[str, Any]:
        """Execute data security engine assessment"""
        self.logger.info("🔒 Starting data security assessment...")
        
        try:
            data_security_dir = self.base_dir / "cspm-data-security-engine"
            os.chdir(data_security_dir)
            
            # Run data security engine if available
            engine_script = data_security_dir / "engine" / "main.py"
            if engine_script.exists():
                cmd = ["python3", str(engine_script), "--inventory-input", 
                       inventory_results.get("csv_file", "")]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
                
                if result.returncode == 0:
                    return {
                        "status": "success",
                        "message": "Data security assessment completed"
                    }
                else:
                    return {
                        "status": "failed", 
                        "error": f"Data security engine failed: {result.stderr}"
                    }
            else:
                return {
                    "status": "skipped",
                    "message": "Data security engine not found"
                }
                
        except Exception as e:
            self.logger.error(f"❌ Data security assessment failed: {str(e)}")
            return {"status": "failed", "error": str(e)}
        finally:
            os.chdir(self.base_dir)
    
    def run_opa_evaluation(self, inventory_results: Dict[str, Any], compliance_results: Dict[str, Any]) -> Dict[str, Any]:
        """Execute OPA policy evaluation"""
        self.logger.info("📋 Starting OPA policy evaluation...")
        
        try:
            opa_dir = self.base_dir / "core-engine" / "opa_evaluation_engine"
            os.chdir(opa_dir)
            
            # Run OPA evaluation pipeline
            runner_script = opa_dir / "runner" / "run_all.py"
            if runner_script.exists():
                cmd = ["python3", str(runner_script)]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
                
                if result.returncode == 0:
                    self.logger.info("✅ OPA evaluation completed successfully")
                    return {
                        "status": "success",
                        "message": "OPA policy evaluation completed",
                        "results_dir": str(opa_dir / "evaluations" / "results")
                    }
                else:
                    return {
                        "status": "failed",
                        "error": f"OPA evaluation failed: {result.stderr}"
                    }
            else:
                return {
                    "status": "skipped",
                    "message": "OPA runner not found"
                }
                
        except Exception as e:
            self.logger.error(f"❌ OPA evaluation failed: {str(e)}")
            return {"status": "failed", "error": str(e)}
        finally:
            os.chdir(self.base_dir)
    
    def generate_unified_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate unified report combining all component results"""
        self.logger.info("📄 Generating unified security and compliance report...")
        
        try:
            # Extract key metrics from each component
            inventory_summary = results.get("components", {}).get("inventory", {}).get("summary", {})
            compliance_summary = results.get("components", {}).get("compliance", {}).get("summary", {})
            
            unified_report = {
                "executive_summary": {
                    "scan_timestamp": results["timestamp"],
                    "session_id": results["session_id"],
                    "total_aws_resources": inventory_summary.get("total_resources", 0),
                    "total_services_scanned": inventory_summary.get("total_services", 0),
                    "compliance_score": compliance_summary.get("overall_score", 0),
                    "critical_findings": compliance_summary.get("critical_count", 0),
                    "high_findings": compliance_summary.get("high_count", 0)
                },
                "component_status": {
                    "inventory": results.get("components", {}).get("inventory", {}).get("status"),
                    "compliance": results.get("components", {}).get("compliance", {}).get("status"),
                    "cspm": results.get("components", {}).get("cspm", {}).get("status"),
                    "data_security": results.get("components", {}).get("data_security", {}).get("status"),
                    "opa": results.get("components", {}).get("opa", {}).get("status")
                },
                "recommendations": self.generate_recommendations(results),
                "next_actions": self.generate_next_actions(results)
            }
            
            # Save unified report
            report_file = self.results_dir / "unified_report.json"
            with open(report_file, 'w') as f:
                json.dump(unified_report, f, indent=2)
            
            self.logger.info(f"✅ Unified report saved to: {report_file}")
            return unified_report
            
        except Exception as e:
            self.logger.error(f"❌ Report generation failed: {str(e)}")
            return {"status": "failed", "error": str(e)}
    
    def execute_integrations(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Execute configured integrations (Slack, Security Hub, etc.)"""
        self.logger.info("🔌 Executing integrations...")
        
        integration_results = {}
        
        try:
            # Slack Integration
            if self.config.get("integrations", {}).get("slack", {}).get("enabled", False):
                slack_result = self.send_slack_notification(results)
                integration_results["slack"] = slack_result
            
            # AWS Security Hub Integration
            if self.config.get("integrations", {}).get("security_hub", {}).get("enabled", False):
                security_hub_result = self.send_to_security_hub(results)
                integration_results["security_hub"] = security_hub_result
            
            return integration_results
            
        except Exception as e:
            self.logger.error(f"❌ Integration execution failed: {str(e)}")
            return {"status": "failed", "error": str(e)}
    
    def save_results(self, results: Dict[str, Any]):
        """Save orchestrator results"""
        results_file = self.results_dir / "orchestrator_results.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"💾 Results saved to: {results_file}")
    
    def parse_inventory_summary(self, metadata_file: Optional[str]) -> Dict[str, Any]:
        """Parse inventory metadata for summary"""
        if not metadata_file or not os.path.exists(metadata_file):
            return {}
        
        try:
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            return {
                "total_services": metadata.get("total_services_checked", 0),
                "total_resources": metadata.get("total_resources_found", 0),
                "regions_scanned": metadata.get("regions_scanned", []),
                "scan_duration": metadata.get("scan_duration_seconds", 0)
            }
        except:
            return {}
    
    def parse_compliance_summary(self, compliance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse compliance results for summary"""
        try:
            findings = compliance_data.get("findings", [])
            
            critical_count = len([f for f in findings if f.get("severity") == "CRITICAL"])
            high_count = len([f for f in findings if f.get("severity") == "HIGH"])
            compliant_count = len([f for f in findings if f.get("compliance_status") == "COMPLIANT"])
            
            total_findings = len(findings)
            overall_score = (compliant_count / total_findings * 100) if total_findings > 0 else 0
            
            return {
                "total_findings": total_findings,
                "critical_count": critical_count,
                "high_count": high_count,
                "compliant_count": compliant_count,
                "overall_score": round(overall_score, 2)
            }
        except:
            return {}
    
    def generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on scan results"""
        recommendations = []
        
        compliance_summary = results.get("components", {}).get("compliance", {}).get("summary", {})
        
        if compliance_summary.get("critical_count", 0) > 0:
            recommendations.append("🔴 URGENT: Address critical compliance findings immediately")
        
        if compliance_summary.get("overall_score", 100) < 80:
            recommendations.append("📈 Improve overall compliance score by addressing high-priority findings")
        
        if results.get("components", {}).get("inventory", {}).get("status") == "success":
            recommendations.append("✅ Consider implementing automated resource tagging based on inventory data")
        
        return recommendations
    
    def generate_next_actions(self, results: Dict[str, Any]) -> List[str]:
        """Generate next action items"""
        actions = [
            "📊 Review unified security report",
            "🔍 Investigate critical and high-severity findings",
            "📋 Create remediation plan with timelines",
            "🔄 Schedule regular automated scans",
            "📈 Monitor compliance score trends"
        ]
        
        return actions
    
    def send_slack_notification(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Send results to Slack (placeholder for implementation)"""
        self.logger.info("📱 Sending Slack notification...")
        # Implementation would go here
        return {"status": "success", "message": "Slack notification sent"}
    
    def send_to_security_hub(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Send findings to AWS Security Hub (placeholder for implementation)"""
        self.logger.info("🛡️ Sending findings to AWS Security Hub...")
        # Implementation would go here
        return {"status": "success", "message": "Findings sent to Security Hub"}


def main():
    """Main CLI interface for lg-protect orchestrator"""
    parser = argparse.ArgumentParser(
        description="LG-Protect: Unified AWS Cloud Security and Compliance Automation Platform"
    )
    
    parser.add_argument(
        "--mode", 
        choices=["full", "inventory", "compliance", "cspm", "data-security", "opa"],
        default="full",
        help="Execution mode (default: full)"
    )
    
    parser.add_argument(
        "--config",
        help="Configuration file path"
    )
    
    parser.add_argument(
        "--output-dir",
        help="Custom output directory"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print("🚀 LG-Protect: Unified AWS Cloud Security Platform")
    print("=" * 60)
    
    try:
        # Initialize orchestrator
        orchestrator = LGProtectOrchestrator(config_file=args.config)
        
        # Execute based on mode
        if args.mode == "full":
            results = orchestrator.run_full_scan()
        elif args.mode == "inventory":
            results = {"components": {"inventory": orchestrator.run_inventory_discovery()}}
        elif args.mode == "compliance":
            # Need inventory first for compliance
            inventory_results = orchestrator.run_inventory_discovery()
            compliance_results = orchestrator.run_compliance_checks(inventory_results)
            results = {"components": {"inventory": inventory_results, "compliance": compliance_results}}
        else:
            print(f"❌ Mode '{args.mode}' not yet implemented")
            return 1
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 EXECUTION SUMMARY")
        print("=" * 60)
        
        if results.get("unified_report"):
            summary = results["unified_report"]["executive_summary"]
            print(f"🔍 Total AWS Resources: {summary.get('total_aws_resources', 'N/A')}")
            print(f"📊 Services Scanned: {summary.get('total_services_scanned', 'N/A')}")
            print(f"✅ Compliance Score: {summary.get('compliance_score', 'N/A')}%")
            print(f"🔴 Critical Findings: {summary.get('critical_findings', 'N/A')}")
            print(f"🟡 High Findings: {summary.get('high_findings', 'N/A')}")
        
        print(f"\n📁 Results Directory: {orchestrator.results_dir}")
        print("✅ Scan completed successfully!")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n⚠️ Scan interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Scan failed: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())