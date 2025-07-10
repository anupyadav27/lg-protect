#!/usr/bin/env python3
"""
Clean Function Files Script

This script removes prompt sections from all generated function files in data_function_list
to create clean, production-ready code.
"""

import os
import re
from pathlib import Path

def clean_function_file(file_path):
    """
    Remove the prompt section from a function file while preserving the essential code.
    
    Args:
        file_path (str): Path to the function file to clean
        
    Returns:
        bool: True if file was cleaned successfully, False otherwise
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if file already appears to be cleaned (no prompt section)
        if '📌 Prompt to Generate Python-Based Data Security Engine Function' not in content:
            print(f"  ✓ {os.path.basename(file_path)} - Already clean")
            return True
        
        # Find the start and end of the prompt section
        prompt_start = content.find('"""\\n📌 Prompt to Generate Python-Based Data Security Engine Function')
        if prompt_start == -1:
            prompt_start = content.find('"""\\n📌 Prompt to Generate Python-Based Data Security Engine Function')
        if prompt_start == -1:
            # Try finding without newline
            prompt_start = content.find('"""📌 Prompt to Generate Python-Based Data Security Engine Function')
        
        if prompt_start == -1:
            print(f"  ⚠ {os.path.basename(file_path)} - No prompt section found")
            return False
        
        # Find the end of the prompt section (look for closing triple quotes + newline + newline)
        prompt_section = content[prompt_start:]
        prompt_end_marker = '"""\\n\\n# Import required modules'
        prompt_end = prompt_section.find(prompt_end_marker)
        
        if prompt_end == -1:
            # Try alternative end marker
            prompt_end_marker = '"""\\n\\n# Import'
            prompt_end = prompt_section.find(prompt_end_marker)
        
        if prompt_end == -1:
            # Try another alternative
            prompt_end_marker = '"""\\n\\nimport'
            prompt_end = prompt_section.find(prompt_end_marker)
            
        if prompt_end == -1:
            print(f"  ⚠ {os.path.basename(file_path)} - Could not find prompt end marker")
            return False
        
        # Calculate absolute position
        absolute_prompt_end = prompt_start + prompt_end + 3  # +3 for the """
        
        # Create cleaned content
        before_prompt = content[:prompt_start].rstrip()
        after_prompt = content[absolute_prompt_end:].lstrip()
        
        # Make sure we end the metadata section properly
        if not before_prompt.endswith('\\n'):
            before_prompt += '\\n'
        
        cleaned_content = before_prompt + '\\n' + after_prompt
        
        # Write the cleaned content back to the file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(cleaned_content)
        
        print(f"  ✓ {os.path.basename(file_path)} - Cleaned successfully")
        return True
        
    except Exception as e:
        print(f"  ✗ {os.path.basename(file_path)} - Error: {e}")
        return False

def main():
    """Main function to clean all files in data_function_list directory."""
    
    # Set up paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_function_dir = os.path.join(script_dir, "data_function_list")
    
    if not os.path.exists(data_function_dir):
        print(f"Error: Directory not found: {data_function_dir}")
        return
    
    print("🧹 Starting cleanup of function files...")
    print(f"Target directory: {data_function_dir}")
    print("-" * 60)
    
    # Get all Python files
    python_files = [f for f in os.listdir(data_function_dir) if f.endswith('.py')]
    
    # Skip our reference file that's already cleaned
    if 'awslambda_function_code_signing_enabled.py' in python_files:
        python_files.remove('awslambda_function_code_signing_enabled.py')
        print(f"  ✓ awslambda_function_code_signing_enabled.py - Already cleaned (reference)")
    
    print(f"Found {len(python_files)} files to process...")
    print()
    
    # Process each file
    cleaned_count = 0
    error_count = 0
    
    for py_file in sorted(python_files):
        file_path = os.path.join(data_function_dir, py_file)
        if clean_function_file(file_path):
            cleaned_count += 1
        else:
            error_count += 1
    
    print()
    print("📊 Cleanup Summary:")
    print(f"Total files processed: {len(python_files)}")
    print(f"Successfully cleaned: {cleaned_count}")
    print(f"Errors encountered: {error_count}")
    print(f"Already clean: {len(python_files) - cleaned_count - error_count}")
    
    if error_count == 0:
        print("\\n✅ All files cleaned successfully!")
    else:
        print(f"\\n⚠️ {error_count} files had issues and may need manual review")

if __name__ == "__main__":
    main()