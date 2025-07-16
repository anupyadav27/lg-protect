#!/usr/bin/env python3
"""
Script to update compliance rules by matching CSV data with JSON rules.
This script performs two main operations:
1. Match existing rules (existing: true) with CSV data via function name
2. Add new rules (existing: false) to CSV as new rows
"""

import json
import csv
import os
import glob
from typing import Dict, List, Set, Tuple
import pandas as pd

class ComplianceRuleUpdater:
    def __init__(self, rules_dir: str, csv_file: str):
        self.rules_dir = rules_dir
        self.csv_file = csv_file
        self.rules_data = {}
        self.csv_data = None
        self.matched_functions = set()
        self.unmatched_rules = []
        
    def load_json_rules(self) -> Dict:
        """Load all JSON rule files from the rules directory."""
        print("Loading JSON rules...")
        rules_data = {}
        
        # Get all JSON files in the rules directory
        json_files = glob.glob(os.path.join(self.rules_dir, "*.json"))
        
        for json_file in json_files:
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if 'rules' in data:
                        # Add source file info to each rule
                        for rule in data['rules']:
                            rule['source_file'] = os.path.basename(json_file)
                        rules_data[os.path.basename(json_file)] = data['rules']
                        print(f"Loaded {len(data['rules'])} rules from {os.path.basename(json_file)}")
            except Exception as e:
                print(f"Error loading {json_file}: {e}")
                
        return rules_data
    
    def load_csv_data(self) -> pd.DataFrame:
        """Load CSV data into pandas DataFrame."""
        print(f"Loading CSV data from {self.csv_file}...")
        try:
            df = pd.read_csv(self.csv_file)
            print(f"Loaded {len(df)} rows from CSV")
            return df
        except Exception as e:
            print(f"Error loading CSV: {e}")
            return None
    
    def get_existing_rules(self) -> List[Dict]:
        """Get all rules with existing: true."""
        existing_rules = []
        for file_rules in self.rules_data.values():
            for rule in file_rules:
                if rule.get('existing', False):
                    existing_rules.append(rule)
        print(f"Found {len(existing_rules)} rules with existing: true")
        return existing_rules
    
    def get_non_existing_rules(self) -> List[Dict]:
        """Get all rules with existing: false."""
        non_existing_rules = []
        for file_rules in self.rules_data.values():
            for rule in file_rules:
                if not rule.get('existing', False):
                    non_existing_rules.append(rule)
        print(f"Found {len(non_existing_rules)} rules with existing: false")
        return non_existing_rules
    
    def match_rules_with_csv(self) -> Tuple[List[Dict], Set[str]]:
        """Match existing rules with CSV data via function name."""
        print("Matching rules with CSV data...")
        existing_rules = self.get_existing_rules()
        csv_function_names = set(self.csv_data['Function Name'].dropna().unique())
        
        matched_rules = []
        unmatched_rules = []
        matched_functions = set()
        
        for rule in existing_rules:
            function_names = rule.get('Checks', [])
            if not function_names:
                function_names = [rule.get('function_name', '')]
            
            # Check if any function name matches CSV
            matched = False
            for func_name in function_names:
                if func_name in csv_function_names:
                    matched = True
                    matched_functions.add(func_name)
                    break
            
            if matched:
                matched_rules.append(rule)
            else:
                # Change existing to false for unmatched rules
                rule['existing'] = False
                unmatched_rules.append(rule)
        
        print(f"Matched {len(matched_rules)} rules")
        print(f"Unmatched {len(unmatched_rules)} rules (changed to existing: false)")
        print(f"Matched {len(matched_functions)} unique function names")
        
        return matched_rules, matched_functions
    
    def update_csv_with_data_security_column(self, matched_functions: Set[str]):
        """Add data_security column to CSV with unique_id for matched functions."""
        print("Adding data_security column to CSV...")
        
        # Create a mapping of function names to unique_ids
        function_to_unique_id = {}
        for file_rules in self.rules_data.values():
            for rule in file_rules:
                function_names = rule.get('Checks', [])
                if not function_names:
                    function_names = [rule.get('function_name', '')]
                
                for func_name in function_names:
                    if func_name in matched_functions:
                        function_to_unique_id[func_name] = rule.get('unique_key', '')
        
        # Add data_security column to CSV
        self.csv_data['data_security'] = self.csv_data['Function Name'].map(function_to_unique_id)
        
        # Count how many rows got matched
        matched_rows = self.csv_data['data_security'].notna().sum()
        print(f"Updated {matched_rows} CSV rows with data_security unique_ids")
    
    def add_new_rules_to_csv(self, non_existing_rules: List[Dict]):
        """Add new rules (existing: false) as new rows to CSV."""
        print("Adding new rules to CSV...")
        
        new_rows = []
        for rule in non_existing_rules:
            # Create new row for each rule
            new_row = {
                'Compliance Name': 'data_security',  # Default compliance name
                'ID': rule.get('Id', ''),
                'Name': rule.get('title', ''),
                'Description': rule.get('description', ''),
                'Function Name': rule.get('function_name', ''),
                'data_security': rule.get('unique_key', '')
            }
            new_rows.append(new_row)
        
        # Create DataFrame for new rows
        new_df = pd.DataFrame(new_rows)
        
        # Concatenate with existing CSV data
        self.csv_data = pd.concat([self.csv_data, new_df], ignore_index=True)
        
        print(f"Added {len(new_rows)} new rows to CSV")
    
    def save_updated_csv(self, output_file: str = None):
        """Save the updated CSV data."""
        if output_file is None:
            # Create backup of original file
            backup_file = self.csv_file.replace('.csv', '_backup.csv')
            os.rename(self.csv_file, backup_file)
            output_file = self.csv_file
        
        self.csv_data.to_csv(output_file, index=False)
        print(f"Saved updated CSV to {output_file}")
    
    def save_updated_json_rules(self):
        """Save updated JSON rules with modified existing status."""
        print("Saving updated JSON rules...")
        
        for filename, rules in self.rules_data.items():
            filepath = os.path.join(self.rules_dir, filename)
            
            # Create backup
            backup_file = filepath.replace('.json', '_backup.json')
            if not os.path.exists(backup_file):
                os.rename(filepath, backup_file)
            
            # Save updated rules
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump({'rules': rules}, f, indent=2, ensure_ascii=False)
            
            print(f"Updated {filename}")
    
    def run(self):
        """Main execution method."""
        print("Starting compliance rule update process...")
        
        # Load data
        self.rules_data = self.load_json_rules()
        self.csv_data = self.load_csv_data()
        
        if self.csv_data is None:
            print("Failed to load CSV data. Exiting.")
            return
        
        # Step 1: Match existing rules with CSV
        matched_rules, matched_functions = self.match_rules_with_csv()
        
        # Update CSV with data_security column
        self.update_csv_with_data_security_column(matched_functions)
        
        # Save updated JSON rules (with existing status changes)
        self.save_updated_json_rules()
        
        # Step 2: Add new rules to CSV
        non_existing_rules = self.get_non_existing_rules()
        self.add_new_rules_to_csv(non_existing_rules)
        
        # Save final updated CSV
        self.save_updated_csv()
        
        print("\nCompliance rule update completed!")
        print(f"Total rules processed: {len(self.get_existing_rules()) + len(self.get_non_existing_rules())}")
        print(f"Matched functions: {len(matched_functions)}")
        print(f"Final CSV rows: {len(self.csv_data)}")

def main():
    # Configuration
    rules_dir = "/Users/apple/Desktop/lg-protect/backend/services/data-security-service/src/rules"
    csv_file = "/Users/apple/Desktop/lg-protect/backend/services/compliance-service/src/functions_list/complaince/compliance_checks.csv"
    
    # Create updater and run
    updater = ComplianceRuleUpdater(rules_dir, csv_file)
    updater.run()

if __name__ == "__main__":
    main() 