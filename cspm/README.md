# CSPM Workspace

## Overview
This workspace contains the CSPM (Cloud Security Posture Management) platform, which is designed to provide comprehensive security and compliance solutions for cloud environments. The platform includes various services, deployment configurations, and a user interface.

## Folder Structure

### Root Level
- **package.json**: Contains metadata and dependencies for the workspace.
- **test.py**: A Python test script.
- **Untitled-1.ini**: Configuration file.

### cspm-platform/
- **ecosystem.config.js**: Configuration for managing processes.
- **README.md**: Documentation for the CSPM platform.
- **devops/**: Contains deployment configurations for various services.
- **docs/**: Architectural documentation.
- **services/**: Microservices for different functionalities, such as AI recommendation, alert engine, billing subscription, etc.
- **shared/**: Shared utilities, configurations, and database-related files.
- **ui/**: Frontend user interface built with modern web technologies.

### devops/
Contains deployment configurations for services:
- ai-recommendation-deployment.yaml
- alert-engine-deployment.yaml
- billing-subscription-deployment.yaml
- ...

### services/
Contains microservices for various functionalities:
- **ai-recommendation/**: AI-based recommendations.
- **alert-engine/**: Alert management.
- **billing-subscription/**: Billing and subscription management.
- **cloud-connector/**: Cloud connectivity.
- **compliance-engine/**: Compliance checks.
- **data-security/**: Data security management.
- **drift-detection/**: Drift detection.
- **inventory-collector/**: Inventory collection.
- **misconfiguration-checker/**: Misconfiguration checks.
- **threat-intelligence/**: Threat intelligence.
- **user-management/**: User management.

### shared/
- **config/**: Configuration files.
- **db/**: Database-related files.
- **utils/**: Utility scripts.

### ui/
Frontend user interface:
- **eslint.config.mjs**: ESLint configuration.
- **index.html**: Entry point for the UI.
- **LICENSE**: License information.
- **package.json**: Metadata and dependencies for the UI.
- **README.md**: Documentation for the UI.
- **tsconfig.json**: TypeScript configuration.
- **vite.config.mjs**: Vite configuration.
- **public/**: Public assets.
- **src/**: Source code for the UI.

## How to Use
1. Navigate to the desired folder to explore its contents.
2. Refer to the README files in each folder for specific instructions.
3. Use the deployment configurations in `devops/` to deploy services.
4. Run the UI using Vite for frontend development.

## License
This workspace is licensed under the terms specified in the LICENSE file.