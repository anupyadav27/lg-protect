import os
import json
import subprocess
import datetime

def run_opa(input_path, rego_path):
    """Run OPA evaluation and return pass/fail decision"""
    result = subprocess.run(
        ["opa", "eval", "-i", input_path, "-d", rego_path, "data.dynamic_field_checker.decision"],
        capture_output=True, text=True
    )
    try:
        output = json.loads(result.stdout)
        return output["result"][0]["expressions"][0]["value"]
    except Exception as e:
        return f"error: {str(e)}"

def find_latest_date_folder(generated_inputs_dir):
    """Find the latest date folder in generated_inputs directory"""
    if not os.path.exists(generated_inputs_dir):
        return None
    
    # Get all directories that match DD-MM-YYYY pattern
    date_folders = []
    for item in os.listdir(generated_inputs_dir):
        item_path = os.path.join(generated_inputs_dir, item)
        if os.path.isdir(item_path):
            # Try to parse as date (DD-MM-YYYY format)
            try:
                date_obj = datetime.datetime.strptime(item, "%d-%m-%Y")
                date_folders.append((item, date_obj))
            except ValueError:
                # Skip folders that don't match date pattern
                continue
    
    if not date_folders:
        return None
    
    # Sort by date and return the latest
    date_folders.sort(key=lambda x: x[1], reverse=True)
    return date_folders[0][0]  # Return folder name (DD-MM-YYYY)

def run_batch_evaluation():
    """Run OPA evaluation for all input files from the latest date folder"""
    # Set up paths relative to script location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)
    
    generated_inputs_base = os.path.join(base_dir, "evaluations", "logs", "generated_inputs")
    rego_file = os.path.join(base_dir, "opa", "dynamic_field_checker.rego")
    
    # Find the latest date folder
    latest_date = find_latest_date_folder(generated_inputs_base)
    if not latest_date:
        print(f"[-] No date folders found in: {generated_inputs_base}")
        print(f"[*] Expected format: DD-MM-YYYY (e.g., 28-06-2025)")
        return
    
    input_dir = os.path.join(generated_inputs_base, latest_date)
    result_dir = os.path.join(base_dir, "evaluations", "results", latest_date)
    
    # Create results directory if it doesn't exist
    os.makedirs(result_dir, exist_ok=True)
    
    print(f"[*] Latest date folder found: {latest_date}")
    print(f"[*] Processing input files from: {input_dir}")
    print(f"[*] Using Rego policy: {rego_file}")
    print(f"[*] Saving results to: {result_dir}")
    print("-" * 60)
    
    # Check if rego file exists
    if not os.path.exists(rego_file):
        print(f"[-] Rego file not found: {rego_file}")
        return
    
    # Get all input files
    input_files = [f for f in os.listdir(input_dir) if f.endswith("_input.json")]
    
    if not input_files:
        print(f"[-] No input files found in: {input_dir}")
        return
    
    print(f"[+] Found {len(input_files)} input files to evaluate")
    print("-" * 60)
    
    # Track results for summary
    results_summary = []
    
    # Process each input file
    for input_file in sorted(input_files):
        input_path = os.path.join(input_dir, input_file)
        
        # Run OPA evaluation
        decision = run_opa(input_path, rego_file)
        
        # Create result filename
        result_file = input_file.replace("_input.json", "_result.json")
        result_path = os.path.join(result_dir, result_file)
        
        # Save result
        result_data = {
            "input_file": input_file,
            "decision": decision,
            "evaluation_date": latest_date,
            "timestamp": datetime.datetime.now().isoformat()
        }
        
        with open(result_path, "w") as f:
            json.dump(result_data, f, indent=2)
        
        # Print result
        status_icon = "✅" if decision == "pass" else "❌" if decision == "fail" else "⚠️"
        print(f"{status_icon} {input_file:<50} → {decision}")
        
        # Track for summary
        results_summary.append((input_file, decision))
    
    print("-" * 60)
    
    # Print summary
    total_files = len(results_summary)
    passed = len([r for r in results_summary if r[1] == "pass"])
    failed = len([r for r in results_summary if r[1] == "fail"])
    errors = len([r for r in results_summary if r[1].startswith("error")])
    
    print(f"[📊] EVALUATION SUMMARY:")
    print(f"    Latest Date: {latest_date}")
    print(f"    Total Files: {total_files}")
    print(f"    ✅ Passed: {passed}")
    print(f"    ❌ Failed: {failed}")
    print(f"    ⚠️ Errors: {errors}")
    print(f"    📈 Pass Rate: {(passed/total_files)*100:.1f}%")
    
    # Save summary report
    summary_path = os.path.join(result_dir, "evaluation_summary.json")
    summary_data = {
        "evaluation_date": latest_date,
        "timestamp": datetime.datetime.now().isoformat(),
        "total_files": total_files,
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "pass_rate": round((passed/total_files)*100, 1),
        "results": [{"file": r[0], "decision": r[1]} for r in results_summary]
    }
    
    with open(summary_path, "w") as f:
        json.dump(summary_data, f, indent=2)
    
    print(f"[+] Summary saved to: {summary_path}")

if __name__ == "__main__":
    run_batch_evaluation()
