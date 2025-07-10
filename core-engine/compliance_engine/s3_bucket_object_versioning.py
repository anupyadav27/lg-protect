import boto3
from botocore.exceptions import ClientError
import json

def s3_bucket_object_versioning():
    """
    Check if S3 buckets have versioning enabled.
    
    Returns:
        dict: Compliance status with details
    """
    try:
        s3_client = boto3.client('s3')
        
        compliant_buckets = []
        non_compliant_buckets = []
        
        # Get all S3 buckets
        buckets_response = s3_client.list_buckets()
        buckets = buckets_response.get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            try:
                # Check versioning configuration
                versioning_response = s3_client.get_bucket_versioning(Bucket=bucket_name)
                versioning_status = versioning_response.get('Status', '')
                
                if versioning_status == 'Enabled':
                    compliant_buckets.append(bucket_name)
                else:
                    non_compliant_buckets.append(bucket_name)
                    
            except ClientError as e:
                if e.response['Error']['Code'] not in ['AccessDenied', 'UnauthorizedOperation']:
                    non_compliant_buckets.append(f"{bucket_name} (Error: {str(e)})")
                else:
                    non_compliant_buckets.append(f"{bucket_name} (Access Denied)")
        
        # Determine overall compliance
        total_buckets = len(compliant_buckets) + len(non_compliant_buckets)
        is_compliant = len(non_compliant_buckets) == 0 and total_buckets > 0
        
        return {
            'compliance_status': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
            'resource_type': 'AWS::S3::Bucket',
            'total_buckets': total_buckets,
            'compliant_buckets_count': len(compliant_buckets),
            'non_compliant_buckets_count': len(non_compliant_buckets),
            'compliant_buckets': compliant_buckets,
            'non_compliant_buckets': non_compliant_buckets,
            'details': {
                'message': f'{len(compliant_buckets)}/{total_buckets} buckets have versioning enabled',
                'recommendation': 'Enable versioning on S3 buckets to protect against accidental deletion and modification'
            }
        }
        
    except Exception as e:
        return {
            'compliance_status': 'ERROR',
            'error': f"Error checking S3 bucket versioning: {str(e)}",
            'resource_type': 'AWS::S3::Bucket'
        }

if __name__ == "__main__":
    result = s3_bucket_object_versioning()
    print(json.dumps(result, indent=2, default=str))