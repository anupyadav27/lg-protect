# 📁 engine/scanner/aws/

This directory contains resource scanners for AWS services such as S3, RDS, IAM, etc.

Each scanner script (e.g., `s3_scanner.py`) is responsible for:
- Making boto3 API calls
- Normalizing output JSON
- Passing it to the evaluation engine