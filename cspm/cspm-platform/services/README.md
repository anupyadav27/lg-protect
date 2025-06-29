# Services Overview

The `services` directory contains the core microservices of the CSPM platform. Each service is designed to handle a specific functionality, ensuring modularity and scalability. Below is a high-level approach to building and managing these services.

## High-Level Approach

1. **Microservice Architecture**:
   - Each service is self-contained and communicates with others via REST or GraphQL APIs.
   - Services are containerized using Docker and orchestrated with Kubernetes.

2. **Development Principles**:
   - Follow the Single Responsibility Principle (SRP) for each service.
   - Use shared utilities from the `shared/` directory to avoid code duplication.
   - Ensure services are stateless wherever possible.

3. **Security**:
   - Implement OAuth2/OIDC for authentication.
   - Use RBAC for authorization.
   - Encrypt sensitive data at rest and in transit.

4. **Testing**:
   - Write unit tests for core logic.
   - Use integration tests to validate inter-service communication.
   - Employ end-to-end tests for critical workflows.

5. **Deployment**:
   - Use CI/CD pipelines for automated testing and deployment.
   - Support blue/green and canary deployments for updates.

6. **Observability**:
   - Integrate logging, monitoring, and alerting for each service.
   - Use tools like Prometheus and Grafana for metrics.

## Folder Structure for Each Service
Each service follows a consistent folder structure to ensure modularity and maintainability:
```
/<service-name>/
    README.md                # Documentation for the service
    rules/                   # Contains rulesets for the service
        ruleset.yaml         # YAML file defining the rules for the service
        custom-rules/        # Folder for tenant-specific or custom rules
    rule-engine/             # Contains the logic for evaluating rules
        engine.py            # Core rule engine implementation
        utils.py             # Helper functions for the rule engine
    api/                     # API endpoints for the service
        endpoints.py         # REST/GraphQL API definitions
    models/                  # Database models or schemas
        schema.py            # Schema definitions for the service
    tests/                   # Unit and integration tests
        test_engine.py       # Tests for the rule engine
        test_api.py          # Tests for the API endpoints
```

## List of Services

- **User Management**: Handles user registration, login, RBAC, and organization management.
- **Cloud Connector**: Integrates with AWS, GCP, and Azure to fetch cloud resource data.
- **Inventory Collector**: Collects cloud resource inventory periodically and on events.
- **Compliance Engine**: Maps cloud resources to compliance frameworks like CIS, HIPAA, and PCI-DSS.
- **Misconfiguration Checker**: Detects misconfigurations in cloud resources using rule-based and AI-driven approaches.
- **Threat Intelligence**: Integrates with CVE, MITRE ATT&CK, and MISP to provide threat intelligence.
- **Data Security**: Ensures sensitive data detection, encryption, and access validation.
- **Alert Engine**: Handles alert routing and real-time triggers for cloud events.
- **Drift Detection**: Compares cloud resource snapshots over time to detect changes.
- **AI Recommendation**: Provides AI-driven fix suggestions and context-aware remediation.
- **Billing Subscription**: Tracks usage and manages billing plans.

# Backend Overview

The backend of the CSPM platform is a microservices-based architecture built with Node.js. Each service is responsible for a specific domain and communicates via REST APIs.

## Key Services
- **User Management**: Handles user authentication, roles, and permissions.
- **Tenant Manager**: Manages tenant isolation and resource scoping.
- **Cloud Connector**: Integrates with AWS, Azure, and GCP for asset discovery.
- **Inventory Collector**: Collects and stores cloud asset data.
- **Compliance Engine**: Maps assets to compliance frameworks like CIS, HIPAA, and PCI-DSS.
- **Misconfiguration Checker**: Detects policy violations and misconfigurations.
- **Drift Detection**: Identifies changes in cloud resources over time.
- **Threat Intelligence**: Maps CVEs and threat indicators to cloud assets.
- **Data Security**: Detects sensitive data and enforces encryption policies.
- **Notification Service**: Sends alerts via email, webhook, and SIEM integrations.

## Folder Structure
```
/services
  /<service-name>
    /api                  # API endpoints
    /models               # Data models
    /output               # Generated outputs
    /rule-engine          # Rule evaluation logic
    /rules                # YAML rules
    /tests                # Unit and integration tests
```

## Getting Started
1. Install dependencies: `npm install`
2. Start a service: `npm start`
3. Run tests: `npm test`

## Contribution Guidelines
- Follow the coding standards defined in `.eslintrc`.
- Write unit tests for all new features.
- Document APIs using OpenAPI specifications.