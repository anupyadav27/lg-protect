class CoreClient:
    """
    Client for interacting with core Kubernetes resources for security scanning.
    """
    def __init__(self, api_client):
        self.api_client = api_client

    def scan(self):
        """Placeholder for core resource scan logic."""
        pass
