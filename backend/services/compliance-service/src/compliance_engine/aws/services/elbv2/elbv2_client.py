from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2
from prowler.providers.common.provider import Provider

elbv2_client = ELBv2(Provider.get_global_provider())

def initialize_elbv2_client(session, regions=None):
    # This function is a placeholder for any future region/session-specific initialization
    # For now, it simply ensures the client is available for the scan runner
    global elbv2_client
    elbv2_client = ELBv2(Provider.get_global_provider())
