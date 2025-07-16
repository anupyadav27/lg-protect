import os
import re
import csv

# Define the base folder containing service subfolders
base_folder = "/Users/apple/Desktop/github/prowler/providers/aws/services"
output_csv = "/Users/apple/Desktop/github/prowler/providers/aws/services/service_functions.csv"

# Function to extract function names from a Python file
def extract_function_names(file_path):
    function_names = []
    try:
        with open(file_path, "r") as file:
            content = file.read()
            # Use regex to find all function definitions
            matches = re.findall(r"def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", content)
            function_names.extend(matches)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return function_names

# Traverse the folder structure and extract function names
service_functions = []
for root, dirs, files in os.walk(base_folder):
    for file in files:
        if file.endswith("_service.py"):
            service_name = file.replace("_service.py", "")
            file_path = os.path.join(root, file)
            functions = extract_function_names(file_path)
            if not functions:  # If no functions are found, log it
                print(f"No functions found in {file_path}")
            for func in functions:
                service_functions.append((service_name, func))

# Ensure no service is missed by checking for empty services
all_services = set()
for root, dirs, files in os.walk(base_folder):
    for file in files:
        if file.endswith("_service.py"):
            service_name = file.replace("_service.py", "")
            all_services.add(service_name)

# Check for services with no functions
processed_services = {service for service, _ in service_functions}
missing_services = all_services - processed_services
for service in missing_services:
    service_functions.append((service, "No functions found"))

# Save the extracted function names to a CSV file
with open(output_csv, "w", newline="") as csv_file:
    writer = csv.writer(csv_file)
    # Write the header row
    writer.writerow(["Service", "Function"])
    # Write each service-function pair
    writer.writerows(service_functions)

print(f"CSV file has been created at: {output_csv}")