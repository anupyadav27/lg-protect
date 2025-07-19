from prowler.providers.aws.services.dlm.dlm_service import DLM
from prowler.providers.common.provider import Provider

dlm_client = DLM(Provider.get_global_provider())

def initialize_dlm_client(boto3_session, regions=None):
    global dlm_client
    dlm_client = DLM(Provider.get_global_provider())
