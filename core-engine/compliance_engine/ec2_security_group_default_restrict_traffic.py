import boto3
from botocore.exceptions import ClientError
import json

def ec2_security_group_default_restrict_traffic():
    """
    Check if default security groups restrict all traffic.
    
    Returns:
        dict: Compliance status with details
    """
    try:
        # Get all AWS regions
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        regions_response = ec2_client.describe_regions()
        all_regions = [region['RegionName'] for region in regions_response['Regions']]
        
        compliant_sgs = []
        non_compliant_sgs = []
        
        for region in all_regions:
            try:
                ec2_regional_client = boto3.client('ec2', region_name=region)
                
                # Get all VPCs to find default security groups
                vpcs_response = ec2_regional_client.describe_vpcs()
                vpcs = vpcs_response.get('Vpcs', [])
                
                for vpc in vpcs:
                    vpc_id = vpc['VpcId']
                    
                    # Find default security group for this VPC
                    sgs_response = ec2_regional_client.describe_security_groups(
                        Filters=[
                            {'Name': 'vpc-id', 'Values': [vpc_id]},
                            {'Name': 'group-name', 'Values': ['default']}
                        ]
                    )
                    
                    for sg in sgs_response.get('SecurityGroups', []):
                        sg_id = sg['GroupId']
                        
                        # Check if security group has any inbound or outbound rules
                        inbound_rules = sg.get('IpPermissions', [])
                        outbound_rules = sg.get('IpPermissionsEgress', [])
                        
                        # Filter out the default self-referencing rule for outbound
                        filtered_outbound = []
                        for rule in outbound_rules:
                            # Skip the default rule that allows all outbound traffic
                            if not (rule.get('IpProtocol') == '-1' and 
                                   any(group.get('GroupId') == sg_id for group in rule.get('UserIdGroupPairs', []))):
                                filtered_outbound.append(rule)
                        
                        # A compliant default security group should have no inbound rules
                        # and minimal outbound rules
                        is_compliant = len(inbound_rules) == 0 and len(filtered_outbound) == 0
                        
                        sg_info = {
                            'security_group_id': sg_id,
                            'vpc_id': vpc_id,
                            'region': region,
                            'inbound_rules_count': len(inbound_rules),
                            'outbound_rules_count': len(filtered_outbound)
                        }
                        
                        if is_compliant:
                            compliant_sgs.append(sg_info)
                        else:
                            non_compliant_sgs.append(sg_info)
                    
            except ClientError as e:
                if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
                    non_compliant_sgs.append({
                        'region': region,
                        'error': 'Access Denied'
                    })
                else:
                    non_compliant_sgs.append({
                        'region': region,
                        'error': str(e)
                    })
        
        # Determine overall compliance
        total_sgs = len(compliant_sgs) + len(non_compliant_sgs)
        is_compliant = len(non_compliant_sgs) == 0 and total_sgs > 0
        
        return {
            'compliance_status': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
            'resource_type': 'AWS::EC2::SecurityGroup',
            'total_default_security_groups': total_sgs,
            'compliant_sgs_count': len(compliant_sgs),
            'non_compliant_sgs_count': len(non_compliant_sgs),
            'compliant_security_groups': compliant_sgs,
            'non_compliant_security_groups': non_compliant_sgs,
            'details': {
                'message': f'{len(compliant_sgs)}/{total_sgs} default security groups restrict all traffic',
                'recommendation': 'Remove all rules from default security groups to ensure they deny all traffic by default'
            }
        }
        
    except Exception as e:
        return {
            'compliance_status': 'ERROR',
            'error': f"Error checking default security groups: {str(e)}",
            'resource_type': 'AWS::EC2::SecurityGroup'
        }

if __name__ == "__main__":
    result = ec2_security_group_default_restrict_traffic()
    print(json.dumps(result, indent=2, default=str))