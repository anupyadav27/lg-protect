import boto3
from botocore.exceptions import ClientError

def cloudtrail_multi_region_enabled():
    """
    Check if CloudTrail is enabled in all regions (multi-region trail exists).
    
    Returns:
        dict: Compliance check result with status and details
    """
    try:
        # Create CloudTrail client
        cloudtrail_client = boto3.client('cloudtrail')
        
        # Get all trails
        response = cloudtrail_client.describe_trails()
        trails = response.get('trailList', [])
        
        if not trails:
            return {
                'status': 'FAIL',
                'message': 'No CloudTrail trails found',
                'resource_id': 'N/A',
                'details': 'At least one multi-region trail should be configured'
            }
        
        # Check if any trail is multi-region
        multi_region_trails = []
        for trail in trails:
            if trail.get('IsMultiRegionTrail', False):
                multi_region_trails.append(trail.get('Name', 'Unknown'))
        
        if multi_region_trails:
            return {
                'status': 'PASS',
                'message': f'Multi-region CloudTrail enabled: {", ".join(multi_region_trails)}',
                'resource_id': multi_region_trails[0],
                'details': f'Found {len(multi_region_trails)} multi-region trail(s)'
            }
        else:
            return {
                'status': 'FAIL',
                'message': 'No multi-region CloudTrail trails found',
                'resource_id': trails[0].get('Name', 'Unknown') if trails else 'N/A',
                'details': 'At least one multi-region trail should be configured'
            }
    
    except ClientError as e:
        return {
            'status': 'ERROR',
            'message': f'Error checking CloudTrail multi-region status: {str(e)}',
            'resource_id': 'N/A',
            'details': str(e)
        }
    except Exception as e:
        return {
            'status': 'ERROR',
            'message': f'Unexpected error: {str(e)}',
            'resource_id': 'N/A',
            'details': str(e)
        }

if __name__ == "__main__":
    result = cloudtrail_multi_region_enabled()
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Resource ID: {result['resource_id']}")
    print(f"Details: {result['details']}")