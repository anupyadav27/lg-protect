promt for generating the complaince rules.. 

{
  "Compliance Name": "iso27001_2022_aws",
  "ID": "A.8.1",
  "Name": "User Endpoint Devices",
  "Description": "Information stored on, processed by or accessible via user endpoint devices should be protected.",
  "Function Name": "ec2_ami_public",
  "API function": "client=boto3.client('ec2')",
  "user function": "describe_images()"
}

Promt:
{
You are given a compliance rule in above formate. Your task is to convert it into a structured JSON file that supports:
1. Multiple clients and functions
2. Field paths used from each function's response
3. Evaluation logic that compares or validates across clients

Output format:
{
  "Compliance Name": "...",
  "ID": "...",
  "Name": "...",
  "Description": "...",
  "Function Name": "...",
  "clients": ["ec2", "ssm"],
  "functions": {
    "ec2": {
      "method": "describe_instances",
      "field_path": "Reservations[].Instances[].InstanceId"
    },
    "ssm": {
      "method": "describe_instance_information",
      "field_path": "InstanceInformationList[].InstanceId"
    }
  },
  "evaluation": {
    "type": "subset",  # other possible values: equal, find, not exists
    "source_client": "ec2",
    "target_client": "ssm",
    "field": "InstanceId"
  }
}

Explanation:
This rule ensures all EC2 instances are also managed by SSM.
So, all EC2 Instance IDs must be found in the list of SSM-managed Instance IDs.

Save the output as:
  compliance_rules/ec2_instance_managed_by_ssm.json
"""
