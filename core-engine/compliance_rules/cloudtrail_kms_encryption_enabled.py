import boto3
from botocore.exceptions import ClientError

def cloudtrail_kms_encryption_enabled():
    """
    Check if CloudTrail logs are encrypted at rest using KMS CMKs.
    
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
                'details': 'CloudTrail should be configured with KMS encryption'
            }
        
        encrypted_trails = []
        unencrypted_trails = []
        
        for trail in trails:
            trail_name = trail.get('Name', 'Unknown')
            kms_key_id = trail.get('KMSKeyId')
            
            if kms_key_id:
                encrypted_trails.append(trail_name)
            else:
                unencrypted_trails.append(trail_name)
        
        if unencrypted_trails:
            return {
                'status': 'FAIL',
                'message': f'CloudTrail trails without KMS encryption: {", ".join(unencrypted_trails)}',
                'resource_id': unencrypted_trails[0],
                'details': f'{len(unencrypted_trails)} trail(s) not encrypted with KMS'
            }
        else:
            return {
                'status': 'PASS',
                'message': f'All CloudTrail trails are KMS encrypted: {", ".join(encrypted_trails)}',
                'resource_id': encrypted_trails[0] if encrypted_trails else 'N/A',
                'details': f'Found {len(encrypted_trails)} KMS encrypted trail(s)'
            }
    
    except ClientError as e:
        return {
            'status': 'ERROR',
            'message': f'Error checking CloudTrail KMS encryption: {str(e)}',
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
    result = cloudtrail_kms_encryption_enabled()
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Resource ID: {result['resource_id']}")
    print(f"Details: {result['details']}")