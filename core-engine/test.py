import os
import json

# Load data from compliance_checks.json
input_file = "compliance_checks.json"
output_dir = "compliance_rules"
os.makedirs(output_dir, exist_ok=True)

with open(input_file) as f:
    compliance_data = json.load(f)

# Process each compliance rule
for item in compliance_data:
    function_name = item.get("Function Name", "unknown_function")

    # Create a new file for each function name
    output_path = os.path.join(output_dir, f"{function_name}.json")

    # Copy the function name section into the file
    structured_rule = {
        "Compliance Name": item["Compliance Name"],
        "ID": item["ID"],
        "Name": item["Name"],
        "Description": item["Description"],
        "Function Name": function_name,
        "API function": item["API function"],
        "user function": item["user function"]
    }

    with open(output_path, "w") as f:
        json.dump(structured_rule, f, indent=2)
        f.write("\n")
        f.write("\n")
        f.write("Promt:\n")
        f.write("{\n")
        f.write("You are given a compliance rule in above formate. Your task is to convert it into a structured JSON file that supports:\n")
        f.write("1. Multiple clients and functions\n")
        f.write("2. Field paths used from each function's response\n")
        f.write("3. Evaluation logic that compares or validates across clients\n")
        f.write("\n")
        f.write("Output format:\n")
        f.write("{\n")
        f.write("  \"Compliance Name\": \"...\",\n")
        f.write("  \"ID\": \"...\",\n")
        f.write("  \"Name\": \"...\",\n")
        f.write("  \"Description\": \"...\",\n")
        f.write("  \"Function Name\": \"...\",\n")
        f.write("  \"clients\": [\"ec2\", \"ssm\"],\n")
        f.write("  \"functions\": {\n")
        f.write("    \"ec2\": {\n")
        f.write("      \"method\": \"describe_instances\",\n")
        f.write("      \"field_path\": \"Reservations[].Instances[].InstanceId\"\n")
        f.write("    },\n")
        f.write("    \"ssm\": {\n")
        f.write("      \"method\": \"describe_instance_information\",\n")
        f.write("      \"field_path\": \"InstanceInformationList[].InstanceId\"\n")
        f.write("    }\n")
        f.write("  },\n")
        f.write("  \"evaluation\": {\n")
        f.write("    \"type\": \"subset\",  # other possible values: equal, find, not exists\n")
        f.write("    \"source_client\": \"ec2\",\n")
        f.write("    \"target_client\": \"ssm\",\n")
        f.write("    \"field\": \"InstanceId\"\n")
        f.write("  }\n")
        f.write("}\n")
        f.write("\n")
        f.write("Explanation:\n")
        f.write("This rule ensures all EC2 instances are also managed by SSM.\n")
        f.write("So, all EC2 Instance IDs must be found in the list of SSM-managed Instance IDs.\n")
        f.write("\n")
        f.write("Save the output as:\n")
        f.write("  compliance_rules/ec2_instance_managed_by_ssm.json\n")
        f.write("\"\"\"\n")

    print(f"Created: {output_path}")