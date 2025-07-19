# Kubernetes Checks Module

A modular and extensible security checks framework for Kubernetes clusters, built on top of the Prowler library.

## Overview

This module provides a clean, organized way to run security checks on Kubernetes clusters. It follows a modular architecture where each Kubernetes component (API Server, Core, Kubelet, etc.) has its own set of security checks.

## Architecture

```
kubernetes_checks/
├── __init__.py              # Main module exports
├── base.py                  # Base classes and common functionality
├── orchestrator.py          # Main orchestrator for running all checks
├── apiserver.py            # API Server security checks
├── core.py                 # Core Kubernetes resource checks
├── kubelet.py              # Kubelet security checks
├── etcd.py                 # Etcd security checks
├── rbac.py                 # RBAC security checks
├── scheduler.py            # Scheduler security checks
└── controllermanager.py    # Controller Manager security checks
```

## Key Components

### Base Classes

- `KubernetesCheckBase`: Abstract base class for individual security checks
- `KubernetesServiceBase`: Base class for service-level check collections
- `CheckResult`: Data class for representing check results

### Service Modules

Each service module contains:
- Individual check classes that inherit from `KubernetesCheckBase`
- A main service class that inherits from `KubernetesServiceBase`
- Component-specific security checks

### Orchestrator

The `KubernetesChecksOrchestrator` class provides:
- Unified interface for running all checks
- Component-specific check execution
- Result summarization and filtering
- Statistics generation

## Usage

### Basic Usage

```python
from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider
from kubernetes_checks.orchestrator import KubernetesChecksOrchestrator

# Initialize provider
provider = KubernetesProvider(
    kubeconfig_file="~/.kube/config",
    context="my-context"
)

# Create orchestrator
orchestrator = KubernetesChecksOrchestrator(provider)

# Run all checks
results = orchestrator.run_all_checks()

# Get summary
summary = orchestrator.get_summary(results)
print(f"Total checks: {summary['total_checks']}")
print(f"Passed: {summary['passed']}")
print(f"Failed: {summary['failed']}")
```

### Component-Specific Checks

```python
# Run only API Server checks
apiserver_results = orchestrator.run_component_checks("apiserver")

# Run only Core checks
core_results = orchestrator.run_component_checks("core")
```

### Result Filtering

```python
# Get only failed checks
failed_checks = orchestrator.get_failed_checks(results)

# Get high severity checks
high_severity = orchestrator.get_high_severity_checks(results)
```

## Available Components

- **apiserver**: API Server configuration and security settings
- **core**: Core Kubernetes resources (Pods, Services, etc.)
- **kubelet**: Kubelet configuration and security
- **etcd**: Etcd configuration and encryption
- **rbac**: Role-based access control checks
- **scheduler**: Scheduler configuration
- **controllermanager**: Controller Manager configuration

## Adding New Checks

### 1. Create a New Check Class

```python
from kubernetes_checks.base import KubernetesCheckBase, CheckResult

class MyNewCheck(KubernetesCheckBase):
    def execute(self) -> List[CheckResult]:
        results = []
        # Your check logic here
        return results
```

### 2. Add to Service Module

```python
class KubernetesChecksMyService(KubernetesServiceBase):
    def __init__(self, provider):
        super().__init__(provider)
        self.my_check = MyNewCheck(provider)
    
    def execute_all_checks(self) -> List[CheckResult]:
        results = []
        results.extend(self.my_check.execute())
        return results
```

### 3. Update Orchestrator

Add your new service to the orchestrator:

```python
class KubernetesChecksOrchestrator:
    def __init__(self, provider):
        # ... existing services ...
        self.my_service_checks = KubernetesChecksMyService(provider)
    
    def run_all_checks(self):
        # ... existing checks ...
        all_results.extend(self.my_service_checks.execute_all_checks())
        return all_results
```

## Check Result Structure

Each check returns a `CheckResult` object with:

- `check_id`: Unique identifier for the check
- `check_name`: Human-readable name
- `status`: PASS, FAIL, ERROR, or MANUAL
- `status_extended`: Detailed description
- `resource_id`: ID of the checked resource
- `resource_name`: Name of the checked resource
- `resource_type`: Type of resource (Pod, Service, etc.)
- `findings`: List of specific findings
- `recommendations`: List of remediation steps
- `severity`: LOW, MEDIUM, HIGH, or CRITICAL

## Example

See `example_usage.py` for a complete example of how to use this module.

## Dependencies

- prowler library
- kubernetes client library
- Python 3.7+

## Contributing

When adding new checks:

1. Follow the existing naming conventions
2. Implement proper error handling
3. Add comprehensive documentation
4. Include recommendations for failed checks
5. Set appropriate severity levels 