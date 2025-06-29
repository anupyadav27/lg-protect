import os
import json
import datetime
import glob

def load_json(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                print(f"[-] Skipping empty file: {file_path}")
                return {}
            return json.loads(content)
    except UnicodeDecodeError:
        print(f"[-] Skipping file due to encoding issue: {file_path}")
        return {}
    except json.JSONDecodeError as e:
        print(f"[-] Skipping file due to JSON decode error: {file_path} - {e}")
        return {}

def merge_inventory_data(inventory_files):
    """Merge multiple inventory files into a single data structure"""
    merged_data = {}
    
    for inv_file in inventory_files:
        inv_data = load_json(inv_file)
        if inv_data:
            # Merge the data - handle different merge strategies
            for key, value in inv_data.items():
                if key in merged_data:
                    # If key exists, handle merging based on data type
                    if isinstance(merged_data[key], list) and isinstance(value, list):
                        # Merge arrays
                        merged_data[key].extend(value)
                    elif isinstance(merged_data[key], dict) and isinstance(value, dict):
                        # Merge dictionaries
                        merged_data[key].update(value)
                    else:
                        # Override with new value (or create array if different types)
                        if not isinstance(merged_data[key], list):
                            merged_data[key] = [merged_data[key]]
                        merged_data[key].append(value)
                else:
                    merged_data[key] = value
    
    return merged_data

def find_inventory_files_by_client_method(policy_data, inventory_dir):
    """Find inventory files based on client_method combination from policy"""
    inventory_files = []
    
    # Get clients and their methods from the policy
    clients = policy_data.get("clients", [])
    functions = policy_data.get("functions", {})
    
    for client in clients:
        if client in functions:
            method = functions[client].get("method", "")
            if method:
                # Create expected inventory filename: client_method.json
                inventory_filename = f"{client}_{method}.json"
                inventory_path = os.path.join(inventory_dir, inventory_filename)
                
                if os.path.exists(inventory_path):
                    inventory_files.append(inventory_path)
                    print(f"[+] Found inventory file: {inventory_filename}")
                else:
                    print(f"[-] Expected inventory file not found: {inventory_filename}")
    
    return inventory_files

def find_matching_inventory_files(policy_name, inventory_dir):
    """Legacy function - kept for backward compatibility but simplified"""
    # Simple exact match only
    exact_match = os.path.join(inventory_dir, f"{policy_name}.json")
    if os.path.exists(exact_match):
        return [exact_match]
    return []

def get_required_clients_from_policy(policy_data):
    """Extract required client types from policy data"""
    clients = set()
    
    # Get clients from policy details
    if "clients" in policy_data:
        clients.update(policy_data["clients"])
    
    # Get clients from functions
    functions = policy_data.get("functions", {})
    clients.update(functions.keys())
    
    # Get client from evaluation
    evaluation = policy_data.get("evaluation", {})
    if "source_client" in evaluation:
        clients.add(evaluation["source_client"])
    
    return list(clients)

def find_inventory_by_clients(required_clients, inventory_dir):
    """Find inventory files based on required client types - simplified"""
    inventory_files = []
    
    for client in required_clients:
        # Simple exact match for client name
        client_file = os.path.join(inventory_dir, f"{client}.json")
        if os.path.exists(client_file):
            inventory_files.append(client_file)
    
    return inventory_files

def build_input(inventory_data, policy_data):
    # Extract only what's needed for evaluation
    evaluation = policy_data.get("evaluation", {})
    
    # Get the field path from the policy
    functions = policy_data.get("functions", {})
    source_client = evaluation.get("source_client", "account")
    field_path = functions.get(source_client, {}).get("field_path", "")
    
    # Create a copy of policy data without evaluation to avoid duplication
    policy_details = policy_data.copy()
    if "evaluation" in policy_details:
        del policy_details["evaluation"]
    
    # Enhanced to include policy details in the input
    return {
        "data": inventory_data,
        "policy": {
            "details": policy_details,
            "evaluation": {
                "type": evaluation.get("type"),
                "source_client": evaluation.get("source_client", "account"),
                "field_path": field_path,
                "expected_value": evaluation.get("expected_value"),
                "allowed_values": evaluation.get("allowed_values", []),
                "min_value": evaluation.get("min_value"),
                "threshold": evaluation.get("threshold")
            }
        }
    }

def save_input(input_data, output_path):
    with open(output_path, 'w') as f:
        json.dump(input_data, f, indent=2)

if __name__ == "__main__":
    # Update paths to match actual workspace structure
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    # Fix: Point to the correct inventory directory where the actual files are located
    inventory_dir = os.path.join(base_dir, "opa_evaluation_engine", "data", "inventory")
    policy_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policies")
    current_date = datetime.datetime.now().strftime("%d-%m-%Y")
    output_dir = os.path.join(base_dir, "opa_evaluation_engine", "evaluations", "logs", "generated_inputs", current_date)
    os.makedirs(output_dir, exist_ok=True)

    print(f"[*] Using policy directory: {policy_dir}")
    print(f"[*] Using inventory directory: {inventory_dir}")
    print(f"[*] Output directory: {output_dir}")

    # Create required directories if they don't exist
    os.makedirs(inventory_dir, exist_ok=True)
    os.makedirs(policy_dir, exist_ok=True)

    # Get list of policy files
    if not os.path.exists(policy_dir):
        print(f"[-] Policy directory not found: {policy_dir}")
        exit(1)

    policy_files = [f for f in os.listdir(policy_dir) if f.endswith('.json')]
    if not policy_files:
        print(f"[-] No policy files found in: {policy_dir}")
        print(f"[*] Please make sure your policy files are in: {policy_dir}")
        exit(1)

    print(f"[+] Found {len(policy_files)} policy files")

    # For each policy file, find all matching inventory files
    for pol_file in policy_files:
        pol_name, pol_ext = os.path.splitext(pol_file)
        pol_path = os.path.join(policy_dir, pol_file)
        
        print(f"[*] Processing policy: {pol_file}")
        
        policy_data = load_json(pol_path)
        if not policy_data:
            print(f"[-] Failed to load policy: {pol_file}")
            continue
        
        # Strategy 1: Find by policy name pattern
        matching_files = find_matching_inventory_files(pol_name, inventory_dir)
        
        # Strategy 2: If no matches, find by client_method
        if not matching_files:
            matching_files = find_inventory_files_by_client_method(policy_data, inventory_dir)
            print(f"[*] Found {len(matching_files)} inventory files for client_method combinations")
        
        # Strategy 3: If still no matches, use a generic inventory file
        if not matching_files:
            generic_inventory = os.path.join(inventory_dir, "inventory.json")
            if os.path.exists(generic_inventory):
                matching_files = [generic_inventory]
                print(f"[*] Using generic inventory file: inventory.json")
        
        if matching_files:
            print(f"[*] Found {len(matching_files)} inventory files:")
            for f in matching_files:
                print(f"    - {os.path.basename(f)}")
            
            # Merge multiple inventory files
            merged_inventory = merge_inventory_data(matching_files)
            
            # Build the input
            combined_input = build_input(merged_inventory, policy_data)
            if combined_input is not None:
                save_path = os.path.join(output_dir, f"{pol_name}_input.json")
                save_input(combined_input, save_path)
                print(f"[+] Created: {save_path}")
                print(f"[+] Merged data from {len(matching_files)} inventory files")
            else:
                print(f"[-] Failed to build input for policy: {pol_file}")
        else:
            print(f"[-] No matching inventory files found for policy: {pol_file}")
        
        print("-" * 50)
