import json
import os
import boto3
from botocore.stub import Stubber
import requests
from bs4 import BeautifulSoup

# This script converts a CSV file into a JSON file and stores the output in the same directory.

# Steps to achieve the task:
# Step 1: Convert CSV to JSON
# - Read the `compliance_checks.csv` file.
# - Convert the data into JSON format.
# - Save the JSON data into a file named `compliance_checks.json`.



# Step 2: Create Output Folder
# - Check if the `output` folder exists in the current directory.
# - If not, create the folder using Python's `os.makedirs()` function.
#
# Step 3: Read JSON Data
# - Load the data from the `compliance_checks.json` file using Python's `json` module.
# - Ensure the file exists and contains valid JSON data.

# Define the path to the JSON file
json_file_path = os.path.join(os.path.dirname(__file__), 'compliance_checks.json')

# Check if the file exists
if os.path.exists(json_file_path):
    try:
        # Open and load the JSON data
        with open(json_file_path, 'r') as json_file:
            json_data = json.load(json_file)
            print("JSON data successfully loaded.")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
else:
    print(f"File {json_file_path} does not exist.")

# Step 4: Simulate Boto3 Function Execution

# - Iterate through the JSON data.
# - Extract relevant fields such as `Function Name`, `API function`, and `user function`.
# - Parse the `API function` to extract the AWS service name (e.g., 'ec2' from `client = boto3.client('ec2')`).
# - Use `botocore.stub.Stubber` to mock responses for each `user function`.
# - Dynamically execute each `user function` and capture its output.
# - Handle any exceptions that occur during execution and log the error.
# - Ensure the logic can handle multiple clients and multiple functions for each client.

def fetch_response_syntax(service, function):
    # Correcting the URL formatting to avoid '%20' in the URL
    url = f"https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/{service}/client/{function}.html"
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract the Response Syntax section
        response_syntax_section = soup.find('h2', string='Response Syntax')
        if response_syntax_section:
            syntax = response_syntax_section.find_next('pre').text
            return syntax
        else:
            print(f"Response Syntax not found for {service}/{function}")
            return None
    except Exception as e:
        print(f"Error fetching response syntax for {service}/{function}: {e}")
        return None

def simulate_boto3_functions(json_data):
    simulated_results = []

    for item in json_data:
        try:
            # Extract relevant fields
            function_name = item.get('Function Name')
            api_function = item.get('API function')
            user_function = item.get('user function')

            if not function_name or not api_function or not user_function:
                print(f"Skipping invalid entry: {item}")
                continue

            # Parse the API function to extract the AWS service name
            service_name = api_function.split("client = boto3.client(")[1].split(")")[0].strip("'")

            # Parse the user function to extract the function name
            function_names = [func.strip("()") for func in user_function.split(',')]

            for func in function_names:
                # Fetch the response syntax dynamically
                response_syntax = fetch_response_syntax(service_name, func)

                if response_syntax:
                    simulated_results.append({
                        "Function Name": function_name,
                        "User Function": func,
                        "Simulated Output": response_syntax
                    })

        except Exception as e:
            simulated_results.append({
                "Function Name": function_name,
                "User Function": user_function,
                "Error": str(e)
            })

    return simulated_results

# Example usage
if 'json_data' in locals():
    simulated_results = simulate_boto3_functions(json_data)
else:
    print("No JSON data available to simulate.")

# Step 5: Store Simulated Results
# - Pass the simulated output from Step 4 to Step 5.
# - Save the results in separate JSON files for each `user function` inside the `output` folder.
# - Name the files based on the `Function Name` and `user function` (e.g., `ec2_describe_instances.json`).
# - Ensure each file contains the correct simulated output.

def store_simulated_results(simulated_results):
    output_folder = os.path.join(os.path.dirname(__file__), 'output')

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    for result in simulated_results:
        try:
            function_name = result.get('Function Name')
            user_function = result.get('User Function')
            simulated_output = result.get('Simulated Output', {})

            if not function_name or not user_function:
                print(f"Skipping invalid result: {result}")
                continue

            # Define the output file name
            output_file_name = f"{function_name}_{user_function}.json"
            output_file_path = os.path.join(output_folder, output_file_name)

            # Save the simulated output to the file
            with open(output_file_path, 'w') as output_file:
                json.dump(simulated_output, output_file, indent=4)

            print(f"Simulated results saved to {output_file_path}")

        except Exception as e:
            print(f"Error storing results for {result.get('Function Name')}: {e}")

if 'json_data' in locals():
    simulated_results = simulate_boto3_functions(json_data)
    store_simulated_results(simulated_results)
else:
    print("No JSON data available to simulate.")

# Step 6: Run the Script
# - Execute the script to process the JSON data, simulate the boto3 functions, and store the results.