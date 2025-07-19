"""
AWS Directconnect Service Module

Centralized imports for AWS Directconnect compliance checks.
"""

# Import the service class
from .directconnect_service import DirectConnectService

# Import individual checks
from .directconnect_connection_redundancy.directconnect_connection_redundancy import directconnect_connection_redundancy
from .directconnect_virtual_interface_redundancy.directconnect_virtual_interface_redundancy import directconnect_virtual_interface_redundancy

__all__ = [
    'DirectConnectService',
    'directconnect_connection_redundancy',
    'directconnect_virtual_interface_redundancy',
]
