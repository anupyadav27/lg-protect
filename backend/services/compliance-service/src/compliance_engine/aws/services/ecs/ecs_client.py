from prowler.providers.aws.services.ecs.ecs_service import ECS
from prowler.providers.common.provider import Provider

ecs_client = ECS(Provider.get_global_provider())

def initialize_ecs_client(boto3_session, regions=None):
    global ecs_client
    ecs_client = ECS(Provider.get_global_provider())
