from prowler.providers.aws.services.elasticache.elasticache_service import ElastiCache
from prowler.providers.common.provider import Provider

elasticache_client = ElastiCache(Provider.get_global_provider())

def initialize_elasticache_client(boto3_session, regions=None):
    global elasticache_client
    elasticache_client = ElastiCache(Provider.get_global_provider())
