import boto3
from botocore.exceptions import ClientError
import json

def guardduty_is_enabled():
    """
    Check if Amazon GuardDuty is enabled in all regions.
    
    Returns:
        dict: Compliance status with details
    """
    try:
        # Get all AWS regions
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        regions_response = ec2_client.describe_regions()
        all_regions = [region['RegionName'] for region in regions_response['Regions']]
        
        enabled_regions = []
        disabled_regions = []
        
        for region in all_regions:
            try:
                guardduty_client = boto3.client('guardduty', region_name=region)
                
                # List detectors in the region
                detectors_response = guardduty_client.list_detectors()
                detectors = detectors_response.get('DetectorIds', [])
                
                if detectors:
                    # Check if any detector is enabled
                    region_enabled = False
                    for detector_id in detectors:
                        detector_details = guardduty_client.get_detector(DetectorId=detector_id)
                        if detector_details.get('Status') == 'ENABLED':
                            region_enabled = True
                            break
                    
                    if region_enabled:
                        enabled_regions.append(region)
                    else:
                        disabled_regions.append(region)
                else:
                    disabled_regions.append(region)
                    
            except ClientError as e:
                if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
                    disabled_regions.append(f"{region} (Access Denied)")
                else:
                    disabled_regions.append(f"{region} (Error: {str(e)})")
        
        # Determine overall compliance
        is_compliant = len(disabled_regions) == 0
        
        return {
            'compliance_status': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
            'resource_type': 'AWS::GuardDuty::Detector',
            'total_regions': len(all_regions),
            'enabled_regions_count': len(enabled_regions),
            'disabled_regions_count': len(disabled_regions),
            'enabled_regions': enabled_regions,
            'disabled_regions': disabled_regions,
            'details': {
                'message': f'GuardDuty enabled in {len(enabled_regions)}/{len(all_regions)} regions',
                'recommendation': 'Enable Amazon GuardDuty in all regions to detect malicious activity and unauthorized behavior'
            }
        }
        
    except Exception as e:
        return {
            'compliance_status': 'ERROR',
            'error': f"Error checking GuardDuty status: {str(e)}",
            'resource_type': 'AWS::GuardDuty::Detector'
        }

if __name__ == "__main__":
    result = guardduty_is_enabled()
    print(json.dumps(result, indent=2, default=str))