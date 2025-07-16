# 📁 rules/

This folder contains YAML-based rulesets for evaluating cloud resource configurations against data security best practices.

### Structure
- `classification/`: Rules for detecting PII, PHI, secrets, etc.
- `access-governance/`: Rules for evaluating IAM, policies, exposure.
- `protection/`: Rules validating encryption, KMS, backups.
- `lineage/`: Rules to trace data flow across cloud services.
- `activity-monitoring/`: Rules to detect anomalies using logs.
- `residency/`: Region validation rules for compliance like GDPR.

All rules follow a shared schema defined in `/rules/templates/rule_schema_template.yaml`.