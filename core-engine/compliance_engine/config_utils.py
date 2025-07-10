#!/usr/bin/env python3
"""
Configuration and Common Utilities Module

Handles configuration loading, logging setup, and common utility functions.
Separated from compliance_utils for better maintainability.
"""

import json
import logging
import os
from typing import Dict, List, Any, Optional
from datetime import datetime


def setup_logging(function_name: str, log_level: str = 'INFO') -> logging.Logger:
    """
    Setup logging configuration for compliance functions.
    
    Args:
        function_name (str): Name of the compliance function for log file naming
        log_level (str): Logging level (DEBUG, INFO, WARNING, ERROR)
        
    Returns:
        logging.Logger: Configured logger instance
    """
    logger = logging.getLogger(function_name)
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # File handler
    file_handler = logging.FileHandler(f'{function_name}_compliance.log')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger


def load_service_regions() -> Dict[str, List[str]]:
    """
    Load service regions from configuration file.
    
    Returns:
        Dict[str, List[str]]: Dictionary mapping service names to their supported regions
    """
    try:
        service_regions_path = '/Users/apple/Desktop/lg-protect/core-engine/functions_list/service-regions.json'
        if os.path.exists(service_regions_path):
            with open(service_regions_path, 'r') as f:
                return json.load(f)
        else:
            # Default regions if file not found
            return {
                'ec2': ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'],
                'ssm': ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'],
                'rds': ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'],
                'redshift': ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'],
                'apigateway': ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'],
                'iam': ['us-east-1'],
                's3': ['us-east-1'],
                'cloudtrail': ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'],
                'cloudwatch': ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'],
                'logs': ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'],
                'guardduty': ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']
            }
    except Exception as e:
        logging.error(f"Error loading service regions: {e}")
        return {'ec2': ['us-east-1']}


def initialize_compliance_results(compliance_data: Dict[str, str]) -> Dict[str, Any]:
    """
    Initialize the standard compliance results structure.
    
    Args:
        compliance_data (Dict[str, str]): Compliance metadata
        
    Returns:
        Dict[str, Any]: Initialized results structure
    """
    return {
        'compliance_name': compliance_data.get('compliance_name', ''),
        'function_name': compliance_data.get('function_name', ''),
        'id': compliance_data.get('id', ''),
        'name': compliance_data.get('name', ''),
        'description': compliance_data.get('description', ''),
        'api_function': compliance_data.get('api_function', ''),
        'user_function': compliance_data.get('user_function', ''),
        'timestamp': datetime.now().isoformat(),
        'status': 'UNKNOWN',
        'findings': [],
        'errors': [],
        'regions_checked': [],
        'profiles_used': []
    }


def determine_overall_status(results: Dict[str, Any]) -> str:
    """
    Determine overall compliance status based on findings and errors.
    
    Args:
        results (Dict[str, Any]): Compliance results
        
    Returns:
        str: Overall status (SUCCESS, ERROR, PARTIAL, NO_DATA, CRITICAL_ERROR)
    """
    if results['errors'] and not results['findings']:
        return 'ERROR'
    elif results['errors'] and results['findings']:
        return 'PARTIAL'
    elif results['findings']:
        return 'SUCCESS'
    else:
        return 'NO_DATA'


def setup_command_line_interface(function_name: str):
    """
    Setup standard command line interface for compliance functions.
    
    Args:
        function_name (str): Name of the compliance function
        
    Returns:
        argparse.Namespace: Parsed command line arguments
    """
    import argparse
    
    parser = argparse.ArgumentParser(description=f'Run {function_name} compliance check')
    parser.add_argument('--profile', help='AWS profile name from ~/.aws/config')
    parser.add_argument('--region', help='Specific AWS region to check')
    parser.add_argument('--output', help='Output file path for results (JSON)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    return parser.parse_args()


def save_results(results: Dict[str, Any], output_path: Optional[str] = None) -> None:
    """
    Save compliance results to file or print to console.
    
    Args:
        results (Dict[str, Any]): Compliance results
        output_path (Optional[str]): File path to save results
    """
    if output_path:
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"Results saved to {output_path}")
    else:
        print(json.dumps(results, indent=2, default=str))


def exit_with_status(results: Dict[str, Any]) -> None:
    """
    Exit with appropriate status code based on results.
    
    Args:
        results (Dict[str, Any]): Compliance results
    """
    import sys
    
    if results['status'] in ['ERROR', 'CRITICAL_ERROR']:
        sys.exit(1)
    elif results['status'] == 'PARTIAL':
        sys.exit(2)
    else:
        sys.exit(0)