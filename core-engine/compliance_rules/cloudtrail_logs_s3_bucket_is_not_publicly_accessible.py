import boto3
from botocore.exceptions import ClientError

def cloudtrail_logs_s3_bucket_is_not_publicly_accessible():
    """
    Check if the S3 bucket used to store CloudTrail logs is not publicly accessible.
    
    Returns:
        dict: Compliance check result with status and details
    """
    try:
        # Create CloudTrail and S3 clients
        cloudtrail_client = boto3.client('cloudtrail')
        s3_client = boto3.client('s3')
        
        # Get all trails
        response = cloudtrail_client.describe_trails()
        trails = response.get('trailList', [])
        
        if not trails:
            return {
                'status': 'FAIL',
                'message': 'No CloudTrail trails found',
                'resource_id': 'N/A',
                'details': 'CloudTrail should be configured with secure S3 bucket'
            }
        
        public_buckets = []
        secure_buckets = []
        
        for trail in trails:
            trail_name = trail.get('Name', 'Unknown')
            s3_bucket_name = trail.get('S3BucketName')
            
            if not s3_bucket_name:
                continue
            
            try:
                # Check bucket policy status
                bucket_policy_status = s3_client.get_bucket_policy_status(Bucket=s3_bucket_name)
                is_public = bucket_policy_status.get('PolicyStatus', {}).get('IsPublic', False)
                
                if is_public:
                    public_buckets.append(f"{trail_name} (bucket: {s3_bucket_name})")
                else:
                    secure_buckets.append(f"{trail_name} (bucket: {s3_bucket_name})")
                    
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code == 'NoSuchBucketPolicy':
                    # No bucket policy means it's likely secure (default deny)
                    secure_buckets.append(f"{trail_name} (bucket: {s3_bucket_name})")
                else:
                    # Other errors might indicate access issues
                    public_buckets.append(f"{trail_name} (bucket: {s3_bucket_name}) - Error checking: {error_code}")
        
        if public_buckets:
            return {
                'status': 'FAIL',
                'message': f'CloudTrail S3 buckets with public access: {", ".join(public_buckets)}',
                'resource_id': public_buckets[0].split(' ')[0],
                'details': f'{len(public_buckets)} bucket(s) may be publicly accessible'
            }
        elif secure_buckets:
            return {
                'status': 'PASS',
                'message': f'All CloudTrail S3 buckets are not publicly accessible: {", ".join(secure_buckets)}',
                'resource_id': secure_buckets[0].split(' ')[0],
                'details': f'Found {len(secure_buckets)} secure bucket(s)'
            }
        else:
            return {
                'status': 'FAIL',
                'message': 'No S3 buckets found for CloudTrail trails',
                'resource_id': 'N/A',
                'details': 'CloudTrail trails should have S3 bucket configuration'
            }
    
    except ClientError as e:
        return {
            'status': 'ERROR',
            'message': f'Error checking CloudTrail S3 bucket public access: {str(e)}',
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
    result = cloudtrail_logs_s3_bucket_is_not_publicly_accessible()
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Resource ID: {result['resource_id']}")
    print(f"Details: {result['details']}")