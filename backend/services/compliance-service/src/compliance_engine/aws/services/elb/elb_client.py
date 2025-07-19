from prowler.providers.aws.services.elb.elb_service import ELB
from prowler.providers.common.provider import Provider

elb_client = ELB(Provider.get_global_provider())

def initialize_elb_client(session, regions=None):
    # This function is a placeholder for any future region/session-specific initialization
    # For now, it simply ensures the client is available for the scan runner
    global elb_client
    elb_client = ELB(Provider.get_global_provider())
