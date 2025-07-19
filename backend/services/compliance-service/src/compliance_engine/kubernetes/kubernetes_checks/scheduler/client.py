class SchedulerClient:
    """
    Client for interacting with the Kubernetes Scheduler for security scanning.
    """
    def __init__(self, api_client):
        self.api_client = api_client

    def scan(self):
        """Placeholder for Scheduler scan logic."""
        pass
