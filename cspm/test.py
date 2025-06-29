import os
import json

def create_cspm_platform_structure(base_path):
    structure = {
        "services": [
            "user-management",
            "cloud-connector",
            "inventory-collector",
            "compliance-engine",
            "misconfiguration-checker",
            "threat-intelligence",
            "data-security",
            "alert-engine",
            "drift-detection",
            "ai-recommendation",
            "billing-subscription"
        ],
        "shared": ["utils", "config", "db"],
        "frontend": [],
        "devops": [],
        "docs": []
    }

    for folder, subfolders in structure.items():
        folder_path = os.path.join(base_path, folder)
        os.makedirs(folder_path, exist_ok=True)
        for subfolder in subfolders:
            os.makedirs(os.path.join(folder_path, subfolder), exist_ok=True)

    # Create README.md at the root level
    readme_path = os.path.join(base_path, "README.md")
    with open(readme_path, "w") as readme_file:
        readme_file.write("# CSPM Platform\n")

# Example usage
base_path = "/Users/apple/Desktop/cspm/cspm-platform"
create_cspm_platform_structure(base_path)

# Path to the JSON file
file_path = "/Users/apple/Desktop/cspm/cspm-platform/services/misconfiguration-checker/output/AWS_compliance_information.json"

# Load the JSON data
with open(file_path, "r") as file:
    data = json.load(file)

# Add a unique rule_number to each item
for index, item in enumerate(data, start=1):
    item["rule_number"] = index

# Save the updated JSON data back to the file
with open(file_path, "w") as file:
    json.dump(data, file, indent=4)

print("rule_number field added successfully!")