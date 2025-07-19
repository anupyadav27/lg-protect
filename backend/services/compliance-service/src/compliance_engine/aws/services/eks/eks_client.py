from prowler.providers.aws.services.eks.eks_service import EKS
from prowler.providers.common.provider import Provider

eks_client = EKS(Provider.get_global_provider())

def initialize_eks_client(boto3_session, regions=None):
    global eks_client
    eks_client = EKS(Provider.get_global_provider())
