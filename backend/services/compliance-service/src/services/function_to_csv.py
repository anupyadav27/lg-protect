import csv

# Filepath for the input CSV
input_csv = "/Users/apple/Desktop/github/prowler/providers/aws/services/service_functions.csv"

def extract_unique_services(csv_file):
    """Extract unique services from the CSV file."""
    unique_services = set()
    try:
        with open(csv_file, "r") as file:
            reader = csv.reader(file)
            # Skip the header row
            next(reader)
            for row in reader:
                # Assuming the service name is in the first column
                service_name = row[0].strip()
                unique_services.add(service_name)
        return unique_services
    except FileNotFoundError:
        print(f"File not found: {csv_file}")
        return None
    except Exception as e:
        print(f"Error processing file: {e}")
        return None

# Extract unique services and print them
unique_services = extract_unique_services(input_csv)
if unique_services:
    print("Unique Services:")
    for service in sorted(unique_services):
        print(service)