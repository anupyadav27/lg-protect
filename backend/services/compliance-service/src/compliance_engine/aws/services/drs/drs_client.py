from prowler.providers.aws.services.drs.drs_service import DRS
from prowler.providers.common.provider import Provider

drs_client = DRS(Provider.get_global_provider())

def initialize_drs_client(boto3_session, regions=None):
    global drs_client
    drs_client = DRS(Provider.get_global_provider())
