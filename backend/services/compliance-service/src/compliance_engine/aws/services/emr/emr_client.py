from prowler.providers.aws.services.emr.emr_service import EMR
from prowler.providers.common.provider import Provider

emr_client = EMR(Provider.get_global_provider())

def initialize_emr_client(session, regions=None):
    # This function is a placeholder for any future region/session-specific initialization
    # For now, it simply ensures the client is available for the scan runner
    global emr_client
    emr_client = EMR(Provider.get_global_provider())
