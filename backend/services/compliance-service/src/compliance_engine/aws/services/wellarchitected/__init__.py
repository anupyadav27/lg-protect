"""
AWS Wellarchitected Service Module

Centralized imports for AWS Wellarchitected compliance checks.
"""

# Import the service class
from .wellarchitected_service import WellArchitectedService

# Import individual checks
from .wellarchitected_workload_no_high_or_medium_risks.wellarchitected_workload_no_high_or_medium_risks import wellarchitected_workload_no_high_or_medium_risks

__all__ = [
    'WellArchitectedService',
    'wellarchitected_workload_no_high_or_medium_risks',
]
