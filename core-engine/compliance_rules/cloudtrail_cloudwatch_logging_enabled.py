import boto3
from botocore.exceptions import ClientError

def cloudtrail_cloudwatch_logging_enabled():
    """
    Check if CloudTrail trails are integrated with CloudWatch Logs.
    
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
                'details': 'CloudTrail should be configured with CloudWatch Logs integration'
            }
        
        cloudwatch_enabled_trails = []
        cloudwatch_disabled_trails = []
        
        for trail in trails:
            trail_name = trail.get('Name', 'Unknown')
            cloudwatch_logs_log_group_arn = trail.get('CloudWatchLogsLogGroupArn')
            
            if cloudwatch_logs_log_group_arn:
                cloudwatch_enabled_trails.append(trail_name)
            else:
                cloudwatch_disabled_trails.append(trail_name)
        
        if cloudwatch_disabled_trails:
            return {
                'status': 'FAIL',
                'message': f'CloudTrail trails without CloudWatch Logs integration: {", ".join(cloudwatch_disabled_trails)}',
                'resource_id': cloudwatch_disabled_trails[0],
                'details': f'{len(cloudwatch_disabled_trails)} trail(s) not integrated with CloudWatch Logs'
            }
        else:
            return {
                'status': 'PASS',
                'message': f'All CloudTrail trails are integrated with CloudWatch Logs: {", ".join(cloudwatch_enabled_trails)}',
                'resource_id': cloudwatch_enabled_trails[0] if cloudwatch_enabled_trails else 'N/A',
                'details': f'Found {len(cloudwatch_enabled_trails)} trail(s) with CloudWatch Logs integration'
            }
    
    except ClientError as e:
        return {
            'status': 'ERROR',
            'message': f'Error checking CloudTrail CloudWatch Logs integration: {str(e)}',
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
    result = cloudtrail_cloudwatch_logging_enabled()
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Resource ID: {result['resource_id']}")
    print(f"Details: {result['details']}")