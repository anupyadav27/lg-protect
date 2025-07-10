import boto3
from botocore.exceptions import ClientError

def cloudtrail_log_file_validation_enabled():
    """
    Check if CloudTrail log file validation is enabled.
    
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
                'details': 'CloudTrail should be configured with log file validation'
            }
        
        validated_trails = []
        non_validated_trails = []
        
        for trail in trails:
            trail_name = trail.get('Name', 'Unknown')
            log_file_validation = trail.get('LogFileValidationEnabled', False)
            
            if log_file_validation:
                validated_trails.append(trail_name)
            else:
                non_validated_trails.append(trail_name)
        
        if non_validated_trails:
            return {
                'status': 'FAIL',
                'message': f'CloudTrail trails without log file validation: {", ".join(non_validated_trails)}',
                'resource_id': non_validated_trails[0],
                'details': f'{len(non_validated_trails)} trail(s) without log file validation enabled'
            }
        else:
            return {
                'status': 'PASS',
                'message': f'All CloudTrail trails have log file validation enabled: {", ".join(validated_trails)}',
                'resource_id': validated_trails[0] if validated_trails else 'N/A',
                'details': f'Found {len(validated_trails)} trail(s) with log file validation enabled'
            }
    
    except ClientError as e:
        return {
            'status': 'ERROR',
            'message': f'Error checking CloudTrail log file validation: {str(e)}',
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
    result = cloudtrail_log_file_validation_enabled()
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Resource ID: {result['resource_id']}")
    print(f"Details: {result['details']}")