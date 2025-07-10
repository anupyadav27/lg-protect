import boto3
from botocore.exceptions import ClientError

def cloudtrail_logs_s3_bucket_access_logging_enabled():
    """
    Check if S3 bucket access logging is enabled on the CloudTrail S3 bucket.
    
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
                'details': 'CloudTrail should be configured with S3 bucket access logging'
            }
        
        buckets_with_logging = []
        buckets_without_logging = []
        
        for trail in trails:
            trail_name = trail.get('Name', 'Unknown')
            s3_bucket_name = trail.get('S3BucketName')
            
            if not s3_bucket_name:
                continue
            
            try:
                # Check bucket logging configuration
                logging_response = s3_client.get_bucket_logging(Bucket=s3_bucket_name)
                logging_enabled = logging_response.get('LoggingEnabled')
                
                if logging_enabled and logging_enabled.get('TargetBucket'):
                    target_bucket = logging_enabled.get('TargetBucket')
                    buckets_with_logging.append(f"{trail_name} (bucket: {s3_bucket_name}, logs to: {target_bucket})")
                else:
                    buckets_without_logging.append(f"{trail_name} (bucket: {s3_bucket_name})")
                    
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code == 'NoSuchBucket':
                    buckets_without_logging.append(f"{trail_name} (bucket: {s3_bucket_name}) - Bucket not found")
                else:
                    buckets_without_logging.append(f"{trail_name} (bucket: {s3_bucket_name}) - Error: {error_code}")
        
        if buckets_without_logging:
            return {
                'status': 'FAIL',
                'message': f'CloudTrail S3 buckets without access logging: {", ".join(buckets_without_logging)}',
                'resource_id': buckets_without_logging[0].split(' ')[0],
                'details': f'{len(buckets_without_logging)} bucket(s) missing access logging'
            }
        elif buckets_with_logging:
            return {
                'status': 'PASS',
                'message': f'All CloudTrail S3 buckets have access logging enabled: {", ".join(buckets_with_logging)}',
                'resource_id': buckets_with_logging[0].split(' ')[0],
                'details': f'Found {len(buckets_with_logging)} bucket(s) with access logging'
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
            'message': f'Error checking CloudTrail S3 bucket access logging: {str(e)}',
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
    result = cloudtrail_logs_s3_bucket_access_logging_enabled()
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Resource ID: {result['resource_id']}")
    print(f"Details: {result['details']}")