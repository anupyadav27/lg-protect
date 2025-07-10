import boto3
from botocore.exceptions import ClientError
import json

def s3_bucket_default_encryption_enabled():
    """
    Check if S3 buckets have default encryption enabled.
    
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
                # Check encryption configuration
                try:
                    encryption_response = s3_client.get_bucket_encryption(Bucket=bucket_name)
                    rules = encryption_response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                    
                    has_encryption = len(rules) > 0
                    if has_encryption:
                        # Verify that encryption is properly configured
                        for rule in rules:
                            default_encryption = rule.get('ApplyServerSideEncryptionByDefault', {})
                            if default_encryption.get('SSEAlgorithm') in ['AES256', 'aws:kms']:
                                compliant_buckets.append(bucket_name)
                                break
                        else:
                            non_compliant_buckets.append(bucket_name)
                    else:
                        non_compliant_buckets.append(bucket_name)
                        
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        non_compliant_buckets.append(bucket_name)
                    else:
                        raise
                    
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
                'message': f'{len(compliant_buckets)}/{total_buckets} buckets have default encryption enabled',
                'recommendation': 'Enable default encryption on S3 buckets to protect data at rest'
            }
        }
        
    except Exception as e:
        return {
            'compliance_status': 'ERROR',
            'error': f"Error checking S3 bucket encryption: {str(e)}",
            'resource_type': 'AWS::S3::Bucket'
        }

if __name__ == "__main__":
    result = s3_bucket_default_encryption_enabled()
    print(json.dumps(result, indent=2, default=str))