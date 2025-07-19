#!/usr/bin/env python3
"""
Comprehensive conversion script for all apiserver checks
Converts checks from prowler format to dynamic loading format
"""

import os
import json
import shutil
import re
from pathlib import Path

def extract_check_logic(original_code, check_name):
    """Extract the core check logic from the original prowler check."""
    lines = original_code.split('\n')
    logic_lines = []
    in_execute = False
    in_logic = False
    
    for line in lines:
        stripped = line.strip()
        
        # Start of execute method
        if 'def execute(self)' in line:
            in_execute = True
            continue
            
        # Skip class definition and imports
        if line.startswith('class ') or line.startswith('from ') or line.startswith('import '):
            continue
            
        # Skip empty lines and comments at the top
        if not in_execute and (not stripped or stripped.startswith('#')):
            continue
            
        if in_execute:
            # Check for end of method (return statement)
            if stripped.startswith('return '):
                break
                
            # Skip the initial setup lines (findings = [], for pod in...)
            if 'findings = []' in line or 'for pod in apiserver_client.apiserver_pods:' in line:
                continue
                
            # Skip the report creation lines
            if 'report = Check_Report_Kubernetes' in line or 'report.status = "PASS"' in line:
                continue
                
            # Extract the actual check logic
            if stripped and not stripped.startswith('#'):
                # Convert prowler logic to our format
                converted_line = convert_prowler_logic_to_our_format(line, check_name)
                if converted_line:
                    logic_lines.append(converted_line)
    
    return '\n'.join(logic_lines)

def convert_prowler_logic_to_our_format(line, check_name):
    """Convert prowler-specific logic to our format."""
    line = line.strip()
    
    # Skip lines that are not part of the core logic
    if any(skip in line for skip in ['report.status', 'report.status_extended', 'findings.append(report)', 'return findings']):
        return None
    
    # Convert pod.containers.values() to pod.spec.containers
    line = line.replace('pod.containers.values()', 'pod.spec.containers')
    
    # Convert container.command to container.args
    line = line.replace('container.command', 'container.args or []')
    
    # Convert pod.name to pod.metadata.name
    line = line.replace('pod.name', 'pod.metadata.name')
    
    # Convert apiserver_client.audit_config.get() to hardcoded values
    if 'apiserver_client.audit_config.get(' in line:
        if 'audit_log_maxsize' in line:
            line = line.replace('apiserver_client.audit_config.get("audit_log_maxsize", 100)', '100')
        elif 'audit_log_maxage' in line:
            line = line.replace('apiserver_client.audit_config.get("audit_log_maxage", 30)', '30')
        elif 'audit_log_maxbackup' in line:
            line = line.replace('apiserver_client.audit_config.get("audit_log_maxbackup", 10)', '10')
    
    # Convert boolean variable initialization
    if '= False' in line and any(flag in line for flag in ['audit_log_', 'tls_', 'auth_', 'plugin_']):
        var_name = line.split('=')[0].strip()
        line = f'                {var_name} = False'
    
    # Convert the main check logic
    if 'if command.startswith(' in line:
        line = '                ' + line
    
    # Convert the value check logic
    if 'if int(' in line and 'command.split("=")[1]' in line:
        # Extract the comparison value and convert to our format
        if '== 100' in line:
            line = '                            if int(command.split("=")[1]) < 100:'
        elif '== 30' in line:
            line = '                            if int(command.split("=")[1]) < 30:'
        elif '== 10' in line:
            line = '                            if int(command.split("=")[1]) < 10:'
        else:
            line = '                            # TODO: Add specific value check'
        line = '                ' + line
    
    # Convert the boolean setting logic
    if '= True' in line and any(flag in line for flag in ['audit_log_', 'tls_', 'auth_', 'plugin_']):
        line = '                                check_passed = True'
        line = '                ' + line
    
    # Convert the break statements
    if line.strip() == 'break':
        line = '                                break'
        line = '                ' + line
    
    # Convert the final check logic
    if 'if not ' in line and any(flag in line for flag in ['audit_log_', 'tls_', 'auth_', 'plugin_']) and ':' in line:
        line = '                if not check_passed:'
        line = '                ' + line
    
    return line

def analyze_check_pattern(original_code, check_name):
    """Analyze the check pattern to determine the type of check logic needed."""
    code_lower = original_code.lower()
    
    # Common patterns in apiserver checks
    patterns = {
        'flag_check': [
            '--token-auth-file',
            '--anonymous-auth',
            '--audit-log-maxage',
            '--audit-log-maxbackup', 
            '--audit-log-maxsize',
            '--audit-log-path',
            '--client-ca-file',
            '--encryption-provider-config',
            '--etcd-cafile',
            '--service-account-key-file',
            '--request-timeout',
            '--event-ttl',
            '--enable-admission-plugins',
            '--disable-admission-plugins',
            '--tls-cipher-suites',
            '--tls-cert-file',
            '--tls-private-key-file',
            '--kubelet-certificate-authority',
            '--kubelet-client-certificate',
            '--kubelet-client-key',
            '--profiling',
            '--bind-address',
            '--root-ca-file',
            '--rotate-kubelet-server-cert',
            '--service-account-private-key-file'
        ],
        'plugin_check': [
            'alwayspullimages',
            'securitycontextdeny',
            'noderestriction',
            'namespaceautoprovision',
            'serviceaccount'
        ],
        'auth_mode_check': [
            'auth-mode',
            'alwaysallow'
        ]
    }
    
    # Determine check type
    for pattern_type, flags in patterns.items():
        for flag in flags:
            if flag in code_lower:
                return pattern_type, flag
    
    return 'generic', None

def generate_check_logic(check_name, pattern_type, flag=None, extracted_logic=None):
    """Generate the appropriate check logic based on the pattern type."""
    
    if extracted_logic:
        # Use the extracted logic from the original file
        return f'''
{extracted_logic}
                # TODO: Add final check logic to set check_passed = False if needed
'''
    
    elif pattern_type == 'flag_check' and flag:
        return f'''
                # Check for {flag} flag
                for container in pod.spec.containers:
                    for command in container.args or []:
                        if command.startswith("{flag}"):
                            # TODO: Add specific logic here
                            # Example: check_passed = False if flag value is incorrect
                            # Example: check_passed = False if flag should not be present
                            pass
'''
    
    elif pattern_type == 'plugin_check':
        return f'''
                # Check for admission plugins
                for container in pod.spec.containers:
                    for command in container.args or []:
                        if command.startswith("--enable-admission-plugins"):
                            # TODO: Add specific plugin check logic
                            # Example: check_passed = False if required plugin is missing
                            # Example: check_passed = False if unwanted plugin is present
                            pass
'''
    
    else:
        return f'''
                # TODO: Implement specific check logic for {check_name}
                # Example: check_passed = False if configuration is incorrect
                for container in pod.spec.containers:
                    for command in container.args or []:
                        # Add your specific check logic here
                        # Set check_passed = False when check fails
                        pass
'''

def convert_check(source_dir, target_dir, check_name):
    """Convert a single check from prowler format to dynamic loading format."""
    
    print(f"Converting {check_name}...")
    
    # Read metadata
    metadata_file = os.path.join(source_dir, f"{check_name}.metadata.json")
    if not os.path.exists(metadata_file):
        print(f"⚠️  No metadata file found for {check_name}")
        return False
    
    with open(metadata_file, 'r') as f:
        metadata = json.load(f)
    
    # Read original check
    check_file = os.path.join(source_dir, f"{check_name}.py")
    if not os.path.exists(check_file):
        print(f"⚠️  No check file found for {check_name}")
        return False
    
    with open(check_file, 'r') as f:
        original_code = f.read()
    
    # Extract check logic from original code
    extracted_logic = extract_check_logic(original_code, check_name)
    
    # Analyze check pattern
    pattern_type, flag = analyze_check_pattern(original_code, check_name)
    
    # Generate converted check
    converted_code = generate_converted_check(metadata, check_name, pattern_type, flag, extracted_logic)
    
    # Create target directory
    target_check_dir = os.path.join(target_dir, check_name)
    os.makedirs(target_check_dir, exist_ok=True)
    
    # Write converted check
    with open(os.path.join(target_check_dir, f"{check_name}.py"), 'w') as f:
        f.write(converted_code)
    
    # Copy metadata
    shutil.copy2(metadata_file, os.path.join(target_check_dir, f"{check_name}.metadata.json"))
    
    # Create __init__.py
    with open(os.path.join(target_check_dir, "__init__.py"), 'w') as f:
        f.write("")
    
    print(f"✅ Converted {check_name}")
    return True

def generate_converted_check(metadata, check_name, pattern_type, flag=None, extracted_logic=None):
    """Generate the converted check code using the template."""
    
    # Map severity
    severity_map = {
        "low": "LOW",
        "medium": "MEDIUM", 
        "high": "HIGH",
        "critical": "CRITICAL"
    }
    
    severity = severity_map.get(metadata.get("Severity", "medium").lower(), "MEDIUM")
    
    # Generate friendly name
    friendly_name = check_name.replace('apiserver_', '').replace('_', ' ').title()
    
    # Get check logic
    check_logic = generate_check_logic(check_name, pattern_type, flag, extracted_logic)
    
    # Get recommendations
    recommendations = []
    if "Remediation" in metadata and "Recommendation" in metadata["Remediation"]:
        recommendations.append(metadata["Remediation"]["Recommendation"].get("Text", ""))
    
    recommendations_text = '",\n                        "'.join(recommendations) if recommendations else "Review configuration"
    
    template = f'''"""
{metadata.get("CheckTitle", friendly_name)}

{metadata.get("Description", "")}
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity


class {check_name}(KubernetesCheckBase):
    """{metadata.get("CheckTitle", friendly_name)}"""
    
    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            # Get API server pods from kube-system namespace
            v1_api = client.CoreV1Api(self.provider)
            api_server_pods = v1_api.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-apiserver"
            )
            
            for pod in api_server_pods.items:
                result = CheckResult(
                    check_id="{check_name}",
                    check_name="{metadata.get("CheckTitle", friendly_name)}",
                    status=CheckStatus.PASS,
                    status_extended=f"Configuration is properly set in pod {{pod.metadata.name}}.",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.{severity}
                )
                
                # Check logic
                check_passed = True{check_logic}
                
                if not check_passed:
                    result.status = CheckStatus.FAIL
                    result.status_extended = f"Configuration is not properly set in pod {{pod.metadata.name}}."
                    result.recommendations = [
                        "{recommendations_text}"
                    ]
                
                findings.append(result)
                
        except Exception as e:
            findings.append(CheckResult(
                check_id="{check_name}",
                check_name="{metadata.get("CheckTitle", friendly_name)}",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking {check_name}: {{str(e)}}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.{severity}
            ))
        
        return findings
'''
    
    return template

def main():
    """Convert all apiserver checks."""
    
    source_dir = "services/apiserver"
    target_dir = "kubernetes_checks/apiserver"
    
    # Ensure source directory exists
    if not os.path.exists(source_dir):
        print(f"❌ Source directory {source_dir} not found!")
        return
    
    # Create target directory
    os.makedirs(target_dir, exist_ok=True)
    
    # Get all check directories
    check_dirs = [d for d in os.listdir(source_dir) 
                  if os.path.isdir(os.path.join(source_dir, d)) 
                  and d.startswith('apiserver_')]
    
    print(f"Found {len(check_dirs)} checks to convert:")
    for check_dir in check_dirs:
        print(f"  - {check_dir}")
    
    print(f"\nStarting conversion...")
    
    # Convert each check
    successful_conversions = 0
    for check_dir in check_dirs:
        source_check_dir = os.path.join(source_dir, check_dir)
        if convert_check(source_check_dir, target_dir, check_dir):
            successful_conversions += 1
    
    print(f"\n🎉 Successfully converted {successful_conversions}/{len(check_dirs)} checks!")
    print(f"Checks are now available in: {target_dir}")
    print(f"\nNext steps:")
    print(f"1. Review the converted checks in {target_dir}")
    print(f"2. Implement the specific check logic (marked with TODO comments)")
    print(f"3. Test the dynamic loading with: python3 -c \"from kubernetes_checks.apiserver.apiserver_service import KubernetesChecksAPIServer; service = KubernetesChecksAPIServer(None); print('Available checks:', service.get_available_checks())\"")

if __name__ == "__main__":
    main() 