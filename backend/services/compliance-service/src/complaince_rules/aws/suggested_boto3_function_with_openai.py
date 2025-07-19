import csv
import openai

# Set your OpenAI API key
openai.api_key = "your_openai_api_key"

# Input CSV file path
input_csv = "/Users/apple/Desktop/github/prowler/compliance/aws/compliance_checks.csv"
# Output CSV file path
output_csv = "/Users/apple/Desktop/github/prowler/compliance/aws/compliance_checks_with_boto3.csv"

# Function to query ChatGPT for Boto3 function suggestions
def suggest_boto3_functions_with_chatgpt(function_name, description):
    try:
        # Create a prompt for ChatGPT
        prompt = f"""
        Based on the following information, suggest the primary Boto3 functions needed to implement the functionality in Python:
        
        Function Name: {function_name}
        Description: {description}
        
        Provide the Boto3 function names in a comma-separated list.
        """
        # Query ChatGPT
        response = openai.Completion.create(
            engine="text-davinci-003",
            prompt=prompt,
            max_tokens=100,
            temperature=0.7
        )
        # Extract the response text
        boto3_functions = response.choices[0].text.strip()
        return boto3_functions
    except Exception as e:
        print(f"Error querying ChatGPT for function '{function_name}': {e}")
        return "Error"

# Process the CSV file
def process_csv_with_chatgpt(input_file, output_file):
    with open(input_file, "r") as csv_in, open(output_file, "w", newline="") as csv_out:
        reader = csv.reader(csv_in)
        writer = csv.writer(csv_out)

        # Read the header and add a new column for Boto3 functions
        header = next(reader)
        header.append("Boto3 Functions")
        writer.writerow(header)

        # Process each row
        for row in reader:
            function_name = row[4]  # Assuming "Function Name" is the 5th column
            description = row[3]   # Assuming "Description" is the 4th column
            boto3_functions = suggest_boto3_functions_with_chatgpt(function_name, description)
            row.append(boto3_functions)
            writer.writerow(row)

# Main execution
process_csv_with_chatgpt(input_csv, output_csv)

print(f"Processed CSV with Boto3 suggestions saved to: {output_csv}")