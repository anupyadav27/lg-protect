import boto3
from botocore.exceptions import ClientError
import json

def s3_bucket_public_access():
    """
    Check if S3 buckets have public access blocked.
    
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
                # Check public access block configuration
                try:
                    public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
                    config = public_access_block['PublicAccessBlockConfiguration']
                    
                    # Check if all public access is blocked
                    is_compliant = (
                        config.get('BlockPublicAcls', False) and
                        config.get('IgnorePublicAcls', False) and
                        config.get('BlockPublicPolicy', False) and
                        config.get('RestrictPublicBuckets', False)
                    )
                    
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        is_compliant = False
                    else:
                        raise
                
                # Additional check: bucket ACL
                if is_compliant:
                    try:
                        bucket_acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                        grants = bucket_acl.get('Grants', [])
                        
                        # Check for public grants
                        for grant in grants:
                            grantee = grant.get('Grantee', {})
                            if grantee.get('Type') == 'Group':
                                uri = grantee.get('URI', '')
                                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                                    is_compliant = False
                                    break
                    except ClientError:
                        pass  # If we can't read ACL, assume it's private
                
                # Additional check: bucket policy
                if is_compliant:
                    try:
                        policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
                        if policy_status.get('PolicyStatus', {}).get('IsPublic', False):
                            is_compliant = False
                    except ClientError as e:
                        if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                            pass  # Ignore other errors for policy status
                
                if is_compliant:
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
                'message': f'{len(compliant_buckets)}/{total_buckets} buckets have public access blocked',
                'recommendation': 'Configure S3 bucket public access block settings to prevent unintended public access'
            }
        }
        
    except Exception as e:
        return {
            'compliance_status': 'ERROR',
            'error': f"Error checking S3 bucket public access: {str(e)}",
            'resource_type': 'AWS::S3::Bucket'
        }

if __name__ == "__main__":
    result = s3_bucket_public_access()
    print(json.dumps(result, indent=2, default=str))