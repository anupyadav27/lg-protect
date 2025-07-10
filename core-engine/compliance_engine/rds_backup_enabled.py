import boto3
from botocore.exceptions import ClientError
import json

def rds_backup_enabled():
    """
    Check if RDS instances have automated backups enabled.
    
    Returns:
        dict: Compliance status with details
    """
    try:
        # Get all AWS regions
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        regions_response = ec2_client.describe_regions()
        all_regions = [region['RegionName'] for region in regions_response['Regions']]
        
        compliant_instances = []
        non_compliant_instances = []
        
        for region in all_regions:
            try:
                rds_client = boto3.client('rds', region_name=region)
                
                # Get all RDS instances
                response = rds_client.describe_db_instances()
                db_instances = response.get('DBInstances', [])
                
                for instance in db_instances:
                    instance_id = instance['DBInstanceIdentifier']
                    backup_retention_period = instance.get('BackupRetentionPeriod', 0)
                    
                    instance_info = {
                        'db_instance_identifier': instance_id,
                        'region': region,
                        'engine': instance.get('Engine'),
                        'engine_version': instance.get('EngineVersion'),
                        'backup_retention_period': backup_retention_period,
                        'preferred_backup_window': instance.get('PreferredBackupWindow'),
                        'backup_window': instance.get('PreferredBackupWindow'),
                        'db_instance_status': instance.get('DBInstanceStatus')
                    }
                    
                    # Check if automated backups are enabled (retention period > 0)
                    if backup_retention_period > 0:
                        compliant_instances.append(instance_info)
                    else:
                        non_compliant_instances.append(instance_info)
                        
            except ClientError as e:
                if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
                    non_compliant_instances.append({
                        'region': region,
                        'error': 'Access Denied'
                    })
                else:
                    non_compliant_instances.append({
                        'region': region,
                        'error': str(e)
                    })
        
        # Determine overall compliance
        total_instances = len(compliant_instances) + len(non_compliant_instances)
        is_compliant = len(non_compliant_instances) == 0 and total_instances > 0
        
        return {
            'compliance_status': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
            'resource_type': 'AWS::RDS::DBInstance',
            'total_instances': total_instances,
            'compliant_instances_count': len(compliant_instances),
            'non_compliant_instances_count': len(non_compliant_instances),
            'compliant_instances': compliant_instances,
            'non_compliant_instances': non_compliant_instances,
            'details': {
                'message': f'{len(compliant_instances)}/{total_instances} RDS instances have automated backups enabled',
                'recommendation': 'Enable automated backups for all RDS instances with appropriate retention period (minimum 7 days recommended)'
            }
        }
        
    except Exception as e:
        return {
            'compliance_status': 'ERROR',
            'error': f"Error checking RDS backup configuration: {str(e)}",
            'resource_type': 'AWS::RDS::DBInstance'
        }

if __name__ == "__main__":
    result = rds_backup_enabled()
    print(json.dumps(result, indent=2, default=str))