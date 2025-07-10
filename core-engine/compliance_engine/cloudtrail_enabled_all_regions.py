import boto3
from botocore.exceptions import ClientError
import json

def cloudtrail_enabled_all_regions():
    """
    Check if CloudTrail is enabled and logging in all regions.
    
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
        trail_details = []
        
        for region in all_regions:
            try:
                cloudtrail_client = boto3.client('cloudtrail', region_name=region)
                
                # Get all trails in this region
                trails_response = cloudtrail_client.describe_trails()
                trails = trails_response.get('trailList', [])
                
                # Check trail status
                region_has_active_trail = False
                for trail in trails:
                    trail_name = trail['Name']
                    trail_arn = trail['TrailARN']
                    
                    # Check if trail is logging
                    status_response = cloudtrail_client.get_trail_status(Name=trail_arn)
                    is_logging = status_response.get('IsLogging', False)
                    
                    # Check if trail is multi-region or covers this region
                    is_multi_region = trail.get('IsMultiRegionTrail', False)
                    home_region = trail.get('HomeRegion', region)
                    
                    trail_info = {
                        'trail_name': trail_name,
                        'trail_arn': trail_arn,
                        'region': region,
                        'home_region': home_region,
                        'is_logging': is_logging,
                        'is_multi_region': is_multi_region,
                        'include_global_service_events': trail.get('IncludeGlobalServiceEvents', False)
                    }
                    trail_details.append(trail_info)
                    
                    if is_logging and (is_multi_region or home_region == region):
                        region_has_active_trail = True
                
                if region_has_active_trail:
                    compliant_regions.append(region)
                else:
                    non_compliant_regions.append(region)
                    
            except ClientError as e:
                if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
                    non_compliant_regions.append(f"{region} (Access Denied)")
                else:
                    non_compliant_regions.append(f"{region} (Error: {str(e)})")
        
        # Check for multi-region trails
        multi_region_trails = [trail for trail in trail_details if trail['is_multi_region'] and trail['is_logging']]
        
        # Determine overall compliance
        is_compliant = len(non_compliant_regions) == 0 or len(multi_region_trails) > 0
        
        return {
            'compliance_status': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
            'resource_type': 'AWS::CloudTrail::Trail',
            'total_regions': len(all_regions),
            'compliant_regions_count': len(compliant_regions),
            'non_compliant_regions_count': len(non_compliant_regions),
            'compliant_regions': compliant_regions,
            'non_compliant_regions': non_compliant_regions,
            'multi_region_trails': multi_region_trails,
            'all_trails': trail_details,
            'details': {
                'message': f'CloudTrail active in {len(compliant_regions)}/{len(all_regions)} regions',
                'recommendation': 'Enable CloudTrail in all regions or use a multi-region trail to ensure comprehensive logging'
            }
        }
        
    except Exception as e:
        return {
            'compliance_status': 'ERROR',
            'error': f"Error checking CloudTrail status: {str(e)}",
            'resource_type': 'AWS::CloudTrail::Trail'
        }

if __name__ == "__main__":
    result = cloudtrail_enabled_all_regions()
    print(json.dumps(result, indent=2, default=str))