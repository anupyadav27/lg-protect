from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_service import (
    ElasticBeanstalk,
)
from prowler.providers.common.provider import Provider

elasticbeanstalk_client = ElasticBeanstalk(Provider.get_global_provider())

def initialize_elasticbeanstalk_client(session, regions=None):
    # This function is a placeholder for any future region/session-specific initialization
    # For now, it simply ensures the client is available for the scan runner
    global elasticbeanstalk_client
    elasticbeanstalk_client = ElasticBeanstalk(Provider.get_global_provider())
