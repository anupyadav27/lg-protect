import boto3
from botocore.exceptions import ClientError
import json

def config_recorder_all_regions_enabled():
    """
    Check if AWS Config is enabled and recording in all regions.
    
    Returns:
        dict: Compliance status with details
    """
    try:
        # Get all AWS regions
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        regions_response = ec2_client.describe_regions()
        all_regions = [region['RegionName'] for region in regions_response['Regions']]
        
        compliant_regions = []
        non_compliant_regions = []
        
        for region in all_regions:
            try:
                config_client = boto3.client('config', region_name=region)
                
                # Check configuration recorders
                recorders = config_client.describe_configuration_recorders()
                recorder_status = config_client.describe_configuration_recorder_status()
                
                # Check if there's at least one recorder that's recording
                region_compliant = False
                for recorder in recorders.get('ConfigurationRecorders', []):
                    # Find corresponding status
                    for status in recorder_status.get('ConfigurationRecordersStatus', []):
                        if status['name'] == recorder['name'] and status['recording']:
                            region_compliant = True
                            break
                    if region_compliant:
                        break
                
                if region_compliant:
                    compliant_regions.append(region)
                else:
                    non_compliant_regions.append(region)
                    
            except ClientError as e:
                if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
                    non_compliant_regions.append(f"{region} (Access Denied)")
                else:
                    non_compliant_regions.append(f"{region} (Error: {str(e)})")
        
        # Determine overall compliance
        is_compliant = len(non_compliant_regions) == 0
        
        return {
            'compliance_status': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
            'resource_type': 'AWS::Config::ConfigurationRecorder',
            'total_regions': len(all_regions),
            'compliant_regions_count': len(compliant_regions),
            'non_compliant_regions_count': len(non_compliant_regions),
            'compliant_regions': compliant_regions,
            'non_compliant_regions': non_compliant_regions,
            'details': {
                'message': f'Config recording enabled in {len(compliant_regions)}/{len(all_regions)} regions',
                'recommendation': 'Enable AWS Config recording in all regions to ensure comprehensive compliance monitoring'
            }
        }
        
    except Exception as e:
        return {
            'compliance_status': 'ERROR',
            'error': f"Error checking Config recorder status: {str(e)}",
            'resource_type': 'AWS::Config::ConfigurationRecorder'
        }

if __name__ == "__main__":
    result = config_recorder_all_regions_enabled()
    print(json.dumps(result, indent=2, default=str))