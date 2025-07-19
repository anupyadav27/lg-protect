from prowler.providers.aws.services.documentdb.documentdb_service import DocumentDB
from prowler.providers.common.provider import Provider

documentdb_client = DocumentDB(Provider.get_global_provider())

def initialize_documentdb_client(boto3_session, regions=None):
    global documentdb_client
    documentdb_client = DocumentDB(Provider.get_global_provider())
