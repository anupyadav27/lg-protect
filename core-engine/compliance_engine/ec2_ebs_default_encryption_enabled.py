import boto3
from botocore.exceptions import ClientError
import json

def ec2_ebs_default_encryption_enabled():
    """
    Check if EBS default encryption is enabled in all regions.
    
    Returns:
        dict: Compliance status with details
    """
    try:
        # Get all AWS regions
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        regions_response = ec2_client.describe_regions()
        all_regions = [region['RegionName'] for region in regions_response['Regions']]
        
        compliant_regions = []
        non_compliant_regions = []
        
        for region in all_regions:
            try:
                ec2_regional_client = boto3.client('ec2', region_name=region)
                
                # Check EBS default encryption status
                encryption_response = ec2_regional_client.get_ebs_default_kms_key_id()
                encryption_enabled = ec2_regional_client.get_ebs_encryption_by_default()
                
                if encryption_enabled.get('EbsEncryptionByDefault', False):
                    compliant_regions.append(region)
                else:
                    non_compliant_regions.append(region)
                    
            except ClientError as e:
                if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
                    non_compliant_regions.append(f"{region} (Access Denied)")
                else:
                    non_compliant_regions.append(f"{region} (Error: {str(e)})")
        
        # Determine overall compliance
        is_compliant = len(non_compliant_regions) == 0
        
        return {
            'compliance_status': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
            'resource_type': 'AWS::EC2::EBSEncryptionByDefault',
            'total_regions': len(all_regions),
            'compliant_regions_count': len(compliant_regions),
            'non_compliant_regions_count': len(non_compliant_regions),
            'compliant_regions': compliant_regions,
            'non_compliant_regions': non_compliant_regions,
            'details': {
                'message': f'EBS default encryption enabled in {len(compliant_regions)}/{len(all_regions)} regions',
                'recommendation': 'Enable EBS default encryption in all regions to ensure data at rest is encrypted'
            }
        }
        
    except Exception as e:
        return {
            'compliance_status': 'ERROR',
            'error': f"Error checking EBS default encryption: {str(e)}",
            'resource_type': 'AWS::EC2::EBSEncryptionByDefault'
        }

if __name__ == "__main__":
    result = ec2_ebs_default_encryption_enabled()
    print(json.dumps(result, indent=2, default=str))