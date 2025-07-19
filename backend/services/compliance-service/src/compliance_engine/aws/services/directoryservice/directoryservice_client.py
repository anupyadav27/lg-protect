from prowler.providers.aws.services.directoryservice.directoryservice_service import (
    DirectoryService,
)
from prowler.providers.common.provider import Provider

directoryservice_client = DirectoryService(Provider.get_global_provider())

def initialize_directoryservice_client(boto3_session, regions=None):
    # This function should initialize the global directoryservice_client with the given session and regions if needed
    global directoryservice_client
    directoryservice_client = DirectoryService(Provider.get_global_provider())
