import boto3
from botocore.exceptions import ClientError
import json

def iam_user_mfa_enabled_console_access():
    """
    Check if IAM users with console access have MFA enabled.
    
    Returns:
        dict: Compliance status with details
    """
    try:
        iam_client = boto3.client('iam')
        
        compliant_users = []
        non_compliant_users = []
        
        # Get all IAM users
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']
                
                try:
                    # Check if user has console access (login profile)
                    has_console_access = False
                    try:
                        iam_client.get_login_profile(UserName=username)
                        has_console_access = True
                    except ClientError as e:
                        if e.response['Error']['Code'] != 'NoSuchEntity':
                            raise
                    
                    if has_console_access:
                        # Check if MFA is enabled for this user
                        mfa_devices = iam_client.list_mfa_devices(UserName=username)
                        virtual_mfa_devices = iam_client.list_virtual_mfa_devices()
                        
                        # Check hardware MFA devices
                        has_mfa = len(mfa_devices['MFADevices']) > 0
                        
                        # Check virtual MFA devices
                        if not has_mfa:
                            for virtual_device in virtual_mfa_devices['VirtualMFADevices']:
                                if virtual_device.get('User', {}).get('UserName') == username:
                                    has_mfa = True
                                    break
                        
                        if has_mfa:
                            compliant_users.append(username)
                        else:
                            non_compliant_users.append(username)
                
                except ClientError as e:
                    if e.response['Error']['Code'] not in ['AccessDenied', 'UnauthorizedOperation']:
                        non_compliant_users.append(f"{username} (Error: {str(e)})")
        
        # Determine overall compliance
        total_console_users = len(compliant_users) + len(non_compliant_users)
        is_compliant = len(non_compliant_users) == 0 and total_console_users > 0
        
        return {
            'compliance_status': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
            'resource_type': 'AWS::IAM::User',
            'total_console_users': total_console_users,
            'compliant_users_count': len(compliant_users),
            'non_compliant_users_count': len(non_compliant_users),
            'compliant_users': compliant_users,
            'non_compliant_users': non_compliant_users,
            'details': {
                'message': f'{len(compliant_users)}/{total_console_users} console users have MFA enabled',
                'recommendation': 'Enable MFA for all IAM users with console access to enhance security'
            }
        }
        
    except Exception as e:
        return {
            'compliance_status': 'ERROR',
            'error': f"Error checking IAM user MFA status: {str(e)}",
            'resource_type': 'AWS::IAM::User'
        }

if __name__ == "__main__":
    result = iam_user_mfa_enabled_console_access()
    print(json.dumps(result, indent=2, default=str))