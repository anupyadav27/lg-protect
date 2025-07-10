import os

FOLDERS = [
    "rules/classification",
    "rules/access-governance/aws",
    "rules/access-governance/azure",
    "rules/access-governance/gcp",
    "rules/protection/aws",
    "rules/protection/azure",
    "rules/protection/gcp",
    "rules/lineage/aws",
    "rules/lineage/azure",
    "rules/lineage/gcp",
    "rules/activity-monitoring/aws",
    "rules/activity-monitoring/azure",
    "rules/activity-monitoring/gcp",
    "rules/residency/aws",
    "rules/residency/azure",
    "rules/residency/gcp",
    "rules/templates",
    "engine/scanner/aws",
    "engine/scanner/azure",
    "engine/scanner/gcp",
    "engine/findings",
    "engine/utils",
    "api/routes",
    "api/schemas",
    "config",
    "data",
    "logs",
    "tests",
    "docs"
]

FILES = [
    # Rules
    "rules/classification/pii.yaml",
    "rules/classification/phi.yaml",
    "rules/classification/financial.yaml",
    "rules/classification/custom.yaml",
    "rules/classification/secrets.yaml",
    "rules/templates/rule_schema_template.yaml",

    # Access Governance
    *[f"rules/access-governance/aws/{name}.yaml" for name in [
        "s3", "rds", "dynamodb", "ebs", "efs", "redshift",
        "ec2", "lambda", "secrets", "iam", "networking", "logging", "backup", "replication"
    ]],

    # Protection
    *[f"rules/protection/aws/{name}.yaml" for name in ["encryption", "kms", "backup"]],

    # Lineage
    *[f"rules/lineage/aws/{name}.yaml" for name in ["glue", "athena", "redshift", "stepfunctions", "streaming"]],

    # Activity Monitoring
    *[f"rules/activity-monitoring/aws/{name}.yaml" for name in ["cloudtrail", "vpcflow", "iam_activity"]],

    # Residency
    *[f"rules/residency/aws/{name}.yaml" for name in ["s3", "rds", "ebs", "replication"]],

    # Engine core
    "engine/rule_loader.py",
    "engine/evaluator.py",
    "engine/findings/result_formatter.py",
    "engine/findings/enrich.py",
    "engine/findings/storage.py",
    "engine/findings/logger.py",
    "engine/utils/region_mapper.py",
    "engine/utils/error_analyzer.py",

    # API
    "api/app.py",
    *[f"api/routes/{name}.py" for name in ["classify", "access", "protect", "lineage", "activity", "residency"]],
    "api/schemas/request_response.py",

    # Config
    "config/settings.yaml",
    "config/region_policies.yaml",
    "config/logging.yaml",

    # Sample Data
    *[f"data/{name}" for name in [
        "aws_s3_sample.json", "aws_rds_sample.json", "aws_iam_sample.json",
        "azure_blob_sample.json", "gcp_gcs_sample.json"
    ]],

    # Logs
    *[f"logs/{name}" for name in ["scan_findings.log", "error.log", "audit.log"]],

    # Tests
    *[f"tests/{name}" for name in [
        "test_rule_loader.py", "test_classification.py", "test_access.py",
        "test_protection.py", "test_lineage.py", "test_activity.py", "test_residency.py"
    ]],

    # Docs
    *[f"docs/{name}" for name in ["RULE_FORMAT.md", "API.md", "QUICKSTART.md"]],

    # Root files
    "requirements.txt",
    "README.md",
    ".env"
]


def create_structure(base_path="."):
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_path = script_dir if base_path == "." else base_path
    
    for folder in FOLDERS:
        folder_path = os.path.join(base_path, folder)
        os.makedirs(folder_path, exist_ok=True)
        print(f"Created folder: {folder_path}")

    for file_path in FILES:
        full_path = os.path.join(base_path, file_path)
        if not os.path.exists(full_path):
            # Create parent directories if they don't exist
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, "w") as f:
                f.write("")
            print(f"Created file: {full_path}")
        else:
            print(f"File already exists: {full_path}")

    print(f"✅ Folder structure created successfully in '{base_path}'")


if __name__ == "__main__":
    create_structure()
