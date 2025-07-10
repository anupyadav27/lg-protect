import boto3
from botocore.exceptions import ClientError
import json

def iam_root_access_key_check():
    """
    Check if root user has access keys configured.
    
    Returns:
        dict: Compliance status with details
    """
    try:
        iam_client = boto3.client('iam')
        
        # Get account summary to check root access keys
        account_summary = iam_client.get_account_summary()
        summary_map = account_summary.get('SummaryMap', {})
        
        # Check for root access keys
        root_access_keys_count = summary_map.get('AccountAccessKeysPresent', 0)
        
        # Get additional details about the account
        account_details = {
            'account_mfa_enabled': summary_map.get('AccountMFAEnabled', 0),
            'users_count': summary_map.get('Users', 0),
            'groups_count': summary_map.get('Groups', 0),
            'roles_count': summary_map.get('Roles', 0),
            'policies_count': summary_map.get('Policies', 0)
        }
        
        # Determine compliance - root should not have access keys
        is_compliant = root_access_keys_count == 0
        
        return {
            'compliance_status': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
            'resource_type': 'AWS::IAM::Root',
            'root_access_keys_present': root_access_keys_count,
            'account_details': account_details,
            'details': {
                'message': f'Root user has {root_access_keys_count} access keys configured',
                'recommendation': 'Remove all access keys from the root user and use IAM users or roles instead'
            }
        }
        
    except Exception as e:
        return {
            'compliance_status': 'ERROR',
            'error': f"Error checking root access keys: {str(e)}",
            'resource_type': 'AWS::IAM::Root'
        }

if __name__ == "__main__":
    result = iam_root_access_key_check()
    print(json.dumps(result, indent=2, default=str))