# 📁 api/routes/

Contains FastAPI or Flask route handlers for each capability:

- `classify.py`: Endpoint for data classification.
- `access.py`: IAM and resource exposure checks.
- `protect.py`: Encryption and KMS validation.
- `lineage.py`: ETL and transformation path analysis.
- `activity.py`: API and access behavior checks.
- `residency.py`: Compliance with region-specific regulations.

Each route reads data, runs evaluation, and returns findings.