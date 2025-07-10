import boto3
from botocore.exceptions import ClientError

def cloudtrail_s3_dataevents_write_enabled():
    """
    Check if CloudTrail has S3 data events logging enabled for write events.
    
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
                'details': 'CloudTrail should be configured with S3 data events logging'
            }
        
        trails_with_s3_write_events = []
        trails_without_s3_write_events = []
        
        for trail in trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', trail_name)
            
            try:
                # Get event selectors for the trail
                event_selectors_response = cloudtrail_client.get_event_selectors(TrailName=trail_arn)
                event_selectors = event_selectors_response.get('EventSelectors', [])
                
                has_s3_write_events = False
                
                for selector in event_selectors:
                    read_write_type = selector.get('ReadWriteType', 'All')
                    data_resources = selector.get('DataResources', [])
                    
                    # Check if write events are included
                    if read_write_type in ['All', 'WriteOnly']:
                        # Check if S3 data resources are included
                        for resource in data_resources:
                            resource_type = resource.get('Type', '')
                            if resource_type == 'AWS::S3::Object':
                                has_s3_write_events = True
                                break
                    
                    if has_s3_write_events:
                        break
                
                if has_s3_write_events:
                    trails_with_s3_write_events.append(trail_name)
                else:
                    trails_without_s3_write_events.append(trail_name)
                    
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code == 'TrailNotFoundException':
                    trails_without_s3_write_events.append(f"{trail_name} (not found)")
                else:
                    trails_without_s3_write_events.append(f"{trail_name} (error: {error_code})")
        
        if trails_without_s3_write_events:
            return {
                'status': 'FAIL',
                'message': f'CloudTrail trails without S3 write data events: {", ".join(trails_without_s3_write_events)}',
                'resource_id': trails_without_s3_write_events[0].split(' ')[0],
                'details': f'{len(trails_without_s3_write_events)} trail(s) missing S3 write data events logging'
            }
        else:
            return {
                'status': 'PASS',
                'message': f'All CloudTrail trails have S3 write data events enabled: {", ".join(trails_with_s3_write_events)}',
                'resource_id': trails_with_s3_write_events[0] if trails_with_s3_write_events else 'N/A',
                'details': f'Found {len(trails_with_s3_write_events)} trail(s) with S3 write data events'
            }
    
    except ClientError as e:
        return {
            'status': 'ERROR',
            'message': f'Error checking CloudTrail S3 write data events: {str(e)}',
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
    result = cloudtrail_s3_dataevents_write_enabled()
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Resource ID: {result['resource_id']}")
    print(f"Details: {result['details']}")