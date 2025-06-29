import boto3
import json

def get_account_contact_information():
    """Fetch and print account contact information."""
    try:
        account_client = boto3.client('account')
        contact_info = account_client.get_contact_information()
        print(json.dumps(contact_info, indent=4))
    except Exception as e:
        print(f"An error occurred while fetching contact information: {e}")

if __name__ == "__main__":
    get_account_contact_information()