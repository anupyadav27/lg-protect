import boto3
from botocore.exceptions import ClientError
import json

def vpc_flow_logs_enabled():
    """
    Check if VPC Flow Logs are enabled for all VPCs.
    
    Returns:
        dict: Compliance status with details
    """
    try:
        # Get all AWS regions
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        regions_response = ec2_client.describe_regions()
        all_regions = [region['RegionName'] for region in regions_response['Regions']]
        
        compliant_vpcs = []
        non_compliant_vpcs = []
        
        for region in all_regions:
            try:
                ec2_regional_client = boto3.client('ec2', region_name=region)
                
                # Get all VPCs in this region
                vpcs_response = ec2_regional_client.describe_vpcs()
                vpcs = vpcs_response.get('Vpcs', [])
                
                # Get all flow logs in this region
                flow_logs_response = ec2_regional_client.describe_flow_logs()
                flow_logs = flow_logs_response.get('FlowLogs', [])
                
                # Create a mapping of VPC IDs to their flow logs
                vpc_flow_logs = {}
                for flow_log in flow_logs:
                    resource_id = flow_log.get('ResourceId')
                    if resource_id and flow_log.get('ResourceType') == 'VPC':
                        if resource_id not in vpc_flow_logs:
                            vpc_flow_logs[resource_id] = []
                        vpc_flow_logs[resource_id].append(flow_log)
                
                for vpc in vpcs:
                    vpc_id = vpc['VpcId']
                    is_default = vpc.get('IsDefault', False)
                    
                    # Check if this VPC has active flow logs
                    vpc_logs = vpc_flow_logs.get(vpc_id, [])
                    active_logs = [log for log in vpc_logs if log.get('FlowLogStatus') == 'ACTIVE']
                    
                    vpc_info = {
                        'vpc_id': vpc_id,
                        'region': region,
                        'is_default': is_default,
                        'cidr_block': vpc.get('CidrBlock'),
                        'flow_logs_count': len(active_logs),
                        'flow_logs': active_logs
                    }
                    
                    if len(active_logs) > 0:
                        compliant_vpcs.append(vpc_info)
                    else:
                        non_compliant_vpcs.append(vpc_info)
                        
            except ClientError as e:
                if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
                    non_compliant_vpcs.append({
                        'region': region,
                        'error': 'Access Denied'
                    })
                else:
                    non_compliant_vpcs.append({
                        'region': region,
                        'error': str(e)
                    })
        
        # Determine overall compliance
        total_vpcs = len(compliant_vpcs) + len(non_compliant_vpcs)
        is_compliant = len(non_compliant_vpcs) == 0 and total_vpcs > 0
        
        return {
            'compliance_status': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
            'resource_type': 'AWS::EC2::VPC',
            'total_vpcs': total_vpcs,
            'compliant_vpcs_count': len(compliant_vpcs),
            'non_compliant_vpcs_count': len(non_compliant_vpcs),
            'compliant_vpcs': compliant_vpcs,
            'non_compliant_vpcs': non_compliant_vpcs,
            'details': {
                'message': f'{len(compliant_vpcs)}/{total_vpcs} VPCs have flow logs enabled',
                'recommendation': 'Enable VPC Flow Logs for all VPCs to monitor network traffic and detect security issues'
            }
        }
        
    except Exception as e:
        return {
            'compliance_status': 'ERROR',
            'error': f"Error checking VPC Flow Logs: {str(e)}",
            'resource_type': 'AWS::EC2::VPC'
        }

if __name__ == "__main__":
    result = vpc_flow_logs_enabled()
    print(json.dumps(result, indent=2, default=str))