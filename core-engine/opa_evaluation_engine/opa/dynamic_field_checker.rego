# =====================================
# AWS COMPLIANCE CHECKER - OPA REGO POLICY
# =====================================
# This file contains Open Policy Agent (OPA) rules written in Rego language
# to evaluate AWS resource compliance against various security standards
# (ISO 27001, CIS Benchmarks, SOC 2, etc.)
#
# PURPOSE: Automatically check if AWS resources meet compliance requirements
# INPUT: JSON data containing AWS resource information + policy rules
# OUTPUT: "pass" or "fail" decision for each compliance check
#
# HOW IT WORKS:
# 1. Receives input with AWS data (EC2 instances, S3 buckets, etc.)
# 2. Extracts specific fields from complex AWS JSON structures
# 3. Applies compliance rules (exists, equals, date checks, etc.)
# 4. Returns pass/fail decision based on evaluation
# =====================================

package dynamic_field_checker

# =====================================
# SECTION 1: FIELD EXTRACTION FUNCTIONS
# =====================================
# These functions navigate complex AWS JSON structures to extract specific values
# They handle various AWS data patterns: simple fields, nested objects, arrays, etc.

# SIMPLE FIELD ACCESS
# Example: "instanceType" from {"instanceType": "t3.micro"}
get_field_value(obj, path) = val if {
    # Handle simple field access (e.g., "field_name")
    not contains(path, ".")    # No dots = simple field
    not contains(path, "[")    # No brackets = not an array
    val := obj[path]           # Direct field access
}

# 2-LEVEL NESTED FIELD ACCESS  
# Example: "contact.email" from {"contact": {"email": "admin@company.com"}}
get_field_value(obj, path) = val if {
    # Handle 2-level nested field access (e.g., "contact.email")
    contains(path, ".")        # Has dot = nested field
    not contains(path, "[")    # No brackets = not an array
    parts := split(path, ".")  # Split by dots
    count(parts) == 2          # Exactly 2 parts
    val := obj[parts[0]][parts[1]]  # Navigate: obj.contact.email
}

# 3-LEVEL NESTED FIELD ACCESS
# Example: "user.contact.email" from {"user": {"contact": {"email": "admin@company.com"}}}
get_field_value(obj, path) = val if {
    # Handle 3-level nested field access (e.g., "user.contact.email")
    contains(path, ".")
    not contains(path, "[")
    parts := split(path, ".")
    count(parts) == 3          # Exactly 3 parts
    val := obj[parts[0]][parts[1]][parts[2]]  # Navigate 3 levels deep
}

# 4-LEVEL NESTED FIELD ACCESS
# Example: "config.user.contact.email"
get_field_value(obj, path) = val if {
    # Handle 4-level nested field access (e.g., "config.user.contact.email")
    contains(path, ".")
    not contains(path, "[")
    parts := split(path, ".")
    count(parts) == 4          # Exactly 4 parts
    val := obj[parts[0]][parts[1]][parts[2]][parts[3]]  # Navigate 4 levels deep
}

# 5-LEVEL NESTED FIELD ACCESS
# Example: "root.config.user.contact.email"
get_field_value(obj, path) = val if {
    # Handle 5-level nested field access (e.g., "root.config.user.contact.email")
    contains(path, ".")
    not contains(path, "[")
    parts := split(path, ".")
    count(parts) == 5          # Exactly 5 parts
    val := obj[parts[0]][parts[1]][parts[2]][parts[3]][parts[4]]  # Navigate 5 levels deep
}

# 6-LEVEL NESTED FIELD ACCESS
# Example: "system.root.config.user.contact.email"
get_field_value(obj, path) = val if {
    # Handle 6-level nested field access
    contains(path, ".")
    not contains(path, "[")
    parts := split(path, ".")
    count(parts) == 6          # Exactly 6 parts
    val := obj[parts[0]][parts[1]][parts[2]][parts[3]][parts[4]][parts[5]]  # Navigate 6 levels deep
}

# NESTED ARRAY ACCESS (AWS EC2 Pattern)
# Example: "Reservations[].Instances[].LaunchTime"
# This handles AWS EC2's complex structure where instances are nested in reservations
get_field_value(obj, path) = val if {
    # Handle nested array access (e.g., "Reservations[].Instances[].LaunchTime")
    contains(path, "[]")       # Has array indicators
    parts := split(path, "[]") # Split by array indicators
    count(parts) == 3          # Three parts: before first [], between [], after second []
    
    first_array_path := parts[0]                    # "Reservations"
    second_array_path := trim_left(parts[1], ".")   # "Instances" 
    field_after_arrays := trim_left(parts[2], ".")  # "LaunchTime"
    
    # Get the first level array (e.g., Reservations)
    first_array := obj[first_array_path]
    
    # Navigate through nested arrays and collect field values
    # This collects LaunchTime from all instances in all reservations
    val := [reservation[second_array_path][j][field_after_arrays] | 
            reservation := first_array[_];      # For each reservation
            reservation[second_array_path];     # That has instances
            j := _;                             # For each instance index
            reservation[second_array_path][j][field_after_arrays]]  # Get the field value
}

# SIMPLE ARRAY ACCESS WITH FIELD
# Example: "analyzers[].name" from {"analyzers": [{"name": "analyzer1"}, {"name": "analyzer2"}]}
get_field_value(obj, path) = val if {
    # Handle simple array access with field (e.g., "analyzers[].name")
    contains(path, "[]")       # Has array indicator
    parts := split(path, "[]") # Split by array indicator
    count(parts) == 2          # Only two parts for single array
    array_path := parts[0]     # "analyzers"
    field_after_array := trim_left(parts[1], ".")  # "name"
    
    # Get the array directly
    array_obj := obj[array_path]
    
    # If field specified after [], collect all field values from array elements
    field_after_array != ""    # Field is specified
    not contains(field_after_array, ".")  # Simple field (no nested access)
    val := [item[field_after_array] | item := array_obj[_]; item[field_after_array]]  # Collect all names
}

# ARRAY ACCESS WITH 2-LEVEL NESTED FIELD
# Example: "analyzers[].status.code" from {"analyzers": [{"status": {"code": 200}}]}
get_field_value(obj, path) = val if {
    # Handle array access with 2-level nested field (e.g., "analyzers[].status.code")
    contains(path, "[]")
    parts := split(path, "[]")
    count(parts) == 2          # Only two parts for single array
    array_path := parts[0]     # "analyzers"
    field_after_array := trim_left(parts[1], ".")  # "status.code"
    
    # Get the array directly
    array_obj := obj[array_path]
    
    # Handle 2-level nested field after array
    field_after_array != ""
    contains(field_after_array, ".")  # Has nested field
    field_parts := split(field_after_array, ".")
    count(field_parts) == 2    # Exactly 2 parts: "status" and "code"
    val := [item[field_parts[0]][field_parts[1]] |  # Get status.code from each item
            item := array_obj[_]; 
            item[field_parts[0]]; 
            item[field_parts[0]][field_parts[1]]]
}

# ARRAY ACCESS WITH 3-LEVEL NESTED FIELD
# Example: "analyzers[].config.unused.age"
get_field_value(obj, path) = val if {
    # Handle array access with 3-level nested field (e.g., "analyzers[].config.unused.age")
    contains(path, "[]")
    parts := split(path, "[]")
    count(parts) == 2
    array_path := parts[0]
    field_after_array := trim_left(parts[1], ".")
    
    array_obj := obj[array_path]
    
    # Handle 3-level nested field after array
    field_after_array != ""
    contains(field_after_array, ".")
    field_parts := split(field_after_array, ".")
    count(field_parts) == 3    # Exactly 3 parts
    val := [item[field_parts[0]][field_parts[1]][field_parts[2]] | 
            item := array_obj[_]; 
            item[field_parts[0]]; 
            item[field_parts[0]][field_parts[1]];
            item[field_parts[0]][field_parts[1]][field_parts[2]]]
}

# ARRAY ACCESS WITH 4-LEVEL NESTED FIELD
# Example: "analyzers[].configuration.unusedAccess.unusedAccessAge"
get_field_value(obj, path) = val if {
    # Handle array access with 4-level nested field (e.g., "analyzers[].configuration.unusedAccess.unusedAccessAge")
    contains(path, "[]")
    parts := split(path, "[]")
    count(parts) == 2
    array_path := parts[0]
    field_after_array := trim_left(parts[1], ".")
    
    array_obj := obj[array_path]
    
    # Handle 4-level nested field after array
    field_after_array != ""
    contains(field_after_array, ".")
    field_parts := split(field_after_array, ".")
    count(field_parts) == 4    # Exactly 4 parts
    val := [item[field_parts[0]][field_parts[1]][field_parts[2]][field_parts[3]] | 
            item := array_obj[_]; 
            item[field_parts[0]]; 
            item[field_parts[0]][field_parts[1]];
            item[field_parts[0]][field_parts[1]][field_parts[2]];
            item[field_parts[0]][field_parts[1]][field_parts[2]][field_parts[3]]]
}

# ARRAY ACCESS WITH 5-LEVEL NESTED FIELD
get_field_value(obj, path) = val if {
    # Handle array access with 5-level nested field
    contains(path, "[]")
    parts := split(path, "[]")
    count(parts) == 2
    array_path := parts[0]
    field_after_array := trim_left(parts[1], ".")
    
    array_obj := obj[array_path]
    
    # Handle 5-level nested field after array
    field_after_array != ""
    contains(field_after_array, ".")
    field_parts := split(field_after_array, ".")
    count(field_parts) == 5    # Exactly 5 parts
    val := [item[field_parts[0]][field_parts[1]][field_parts[2]][field_parts[3]][field_parts[4]] | 
            item := array_obj[_]; 
            item[field_parts[0]]; 
            item[field_parts[0]][field_parts[1]];
            item[field_parts[0]][field_parts[1]][field_parts[2]];
            item[field_parts[0]][field_parts[1]][field_parts[2]][field_parts[3]];
            item[field_parts[0]][field_parts[1]][field_parts[2]][field_parts[3]][field_parts[4]]]
}

# ARRAY ACCESS WITHOUT SPECIFIC FIELD
# Example: "analyzers[]" - returns the entire array
get_field_value(obj, path) = val if {
    # Handle array access without field (e.g., "analyzers[]")
    contains(path, "[]")
    parts := split(path, "[]")
    count(parts) == 2
    array_path := parts[0]
    field_after_array := trim_left(parts[1], ".")
    
    array_obj := obj[array_path]
    
    # Return the array itself if no field specified after []
    field_after_array == ""   # No field specified
    val := array_obj          # Return entire array
}

# =====================================
# SECTION 2: COMPLIANCE EVALUATION RULES
# =====================================
# These rules implement different types of compliance checks
# Each rule matches a specific evaluation type and applies the appropriate logic

# EXISTS CHECK
# Purpose: Verify that a required field or resource exists
# Use case: "Ensure encryption is enabled", "Verify logging is configured"
allow if {
    input.policy.evaluation.type == "exists"
    field_path := input.policy.details.functions[input.policy.evaluation.source_client].field_path
    val := get_field_value(input.data, field_path)
    val != null            # Field exists
    val != ""             # Field is not empty
}

# NOT EXISTS CHECK (Version 1: Null Values)
# Purpose: Verify that a field or resource does NOT exist
# Use case: "Ensure no public access", "Verify no unencrypted data"
allow if {
    input.policy.evaluation.type == "not exists"
    field_path := input.policy.details.functions[input.policy.evaluation.source_client].field_path
    val := get_field_value(input.data, field_path)
    val == null           # Field is null/missing
}

# NOT EXISTS CHECK (Version 2: Empty Arrays)
# Purpose: Handle cases where "not exists" means empty array
# Use case: "No security findings", "No public buckets"
allow if {
    input.policy.evaluation.type == "not exists"
    field_path := input.policy.details.functions[input.policy.evaluation.source_client].field_path
    val := get_field_value(input.data, field_path)
    is_array(val)         # Value is an array
    count(val) == 0       # Array is empty
}

# EQUALS CHECK (For Arrays)
# Purpose: Verify that a field equals a specific value (array format)
# Use case: "Instance type must be t3.micro", "Region must be us-east-1"
allow if {
    input.policy.evaluation.type == "equals"
    field_path := input.policy.details.functions[input.policy.evaluation.source_client].field_path
    val := get_field_value(input.data, field_path)
    is_array(val)         # Value is an array
    count(val) == 1       # Array has exactly one element
    val[0] == input.policy.evaluation.expected_value  # Element equals expected value
}

# EQUALS CHECK (For Single Values)
# Purpose: Verify that a field equals a specific value (direct comparison)
allow if {
    input.policy.evaluation.type == "equals"
    field_path := input.policy.details.functions[input.policy.evaluation.source_client].field_path
    val := get_field_value(input.data, field_path)
    not is_array(val)     # Value is not an array
    val == input.policy.evaluation.expected_value  # Direct comparison
}

# NOT EQUALS CHECK (For Arrays)
# Purpose: Verify that a field does NOT equal a specific value (array format)
# Use case: "Instance type must not be t1.micro", "Protocol must not be HTTP"
allow if {
    input.policy.evaluation.type == "not equals"
    field_path := input.policy.details.functions[input.policy.evaluation.source_client].field_path
    val := get_field_value(input.data, field_path)
    is_array(val)         # Value is an array
    count(val) == 1       # Array has exactly one element
    val[0] != input.policy.evaluation.expected_value  # Element does not equal expected value
}

# NOT EQUALS CHECK (For Single Values)
# Purpose: Verify that a field does NOT equal a specific value (direct comparison)
allow if {
    input.policy.evaluation.type == "not equals"
    field_path := input.policy.details.functions[input.policy.evaluation.source_client].field_path
    val := get_field_value(input.data, field_path)
    not is_array(val)     # Value is not an array
    val != input.policy.evaluation.expected_value  # Direct comparison
}

# GREATER THAN CHECK (For Arrays)
# Purpose: Verify that a numeric field is greater than a threshold (array format)
# Use case: "CPU utilization > 80%", "Storage size > 100GB"
allow if {
    input.policy.evaluation.type == "greater_than"
    field_path := input.policy.details.functions[input.policy.evaluation.source_client].field_path
    val := get_field_value(input.data, field_path)
    is_array(val)         # Value is an array
    count(val) == 1       # Array has exactly one element
    val[0] > input.policy.evaluation.threshold  # Element is greater than threshold
}

# GREATER THAN CHECK (For Single Values)
# Purpose: Verify that a numeric field is greater than a threshold (direct comparison)
allow if {
    input.policy.evaluation.type == "greater_than"
    field_path := input.policy.details.functions[input.policy.evaluation.source_client].field_path
    val := get_field_value(input.data, field_path)
    not is_array(val)     # Value is not an array
    val > input.policy.evaluation.threshold  # Direct comparison
}

# LESS THAN CHECK (For Arrays)
# Purpose: Verify that a numeric field is less than a threshold (array format)
# Use case: "Response time < 200ms", "Cost < $1000"
allow if {
    input.policy.evaluation.type == "less_than"
    field_path := input.policy.details.functions[input.policy.evaluation.source_client].field_path
    val := get_field_value(input.data, field_path)
    is_array(val)         # Value is an array
    count(val) == 1       # Array has exactly one element
    val[0] < input.policy.evaluation.threshold  # Element is less than threshold
}

# LESS THAN CHECK (For Single Values)
# Purpose: Verify that a numeric field is less than a threshold (direct comparison)
allow if {
    input.policy.evaluation.type == "less_than"
    field_path := input.policy.details.functions[input.policy.evaluation.source_client].field_path
    val := get_field_value(input.data, field_path)
    not is_array(val)     # Value is not an array
    val < input.policy.evaluation.threshold  # Direct comparison
}

# CUSTOM MULTI-FIELD CHECK
# Purpose: Evaluate multiple fields with different conditions (AND logic)
# Use case: Complex compliance rules with multiple requirements
# Example: "Encryption enabled AND logging enabled AND monitoring enabled"
allow if {
    input.policy.evaluation.type == "custom_multi_field"
    validations := input.policy.evaluation.validations  # Array of validation rules
    
    # Check each validation rule
    passed_validations := [v | 
        v := validations[_];                            # For each validation
        val := get_field_value(input.data, v.field_path);  # Get field value
        _validate_condition(val, v.operator, v.expected_value)  # Apply condition
    ]
    
    # All validations must pass
    count(passed_validations) == count(validations)
}

# MULTIPLE FIELDS AND CHECK
# Purpose: All specified fields must equal their expected values (AND logic)
# Use case: "All security groups must be configured correctly"
allow if {
    input.policy.evaluation.type == "multiple_fields_and"
    field_paths := input.policy.evaluation.field_paths      # Array of field paths
    expected_values := input.policy.evaluation.expected_values  # Array of expected values
    
    # Count how many fields match their expected values
    count([i | 
        field_path := field_paths[i];        # Get field path at index i
        expected := expected_values[i];      # Get expected value at index i
        val := get_field_value(input.data, field_path);  # Get actual value
        val == expected                      # Check if they match
    ]) == count(field_paths)                 # All fields must match
}

# MULTIPLE FIELDS OR CHECK
# Purpose: At least one of the specified fields must equal its expected value (OR logic)
# Use case: "At least one backup method must be enabled"
allow if {
    input.policy.evaluation.type == "multiple_fields_or"
    field_paths := input.policy.evaluation.field_paths
    expected_values := input.policy.evaluation.expected_values
    
    # Count how many fields match their expected values
    count([i | 
        field_path := field_paths[i];
        expected := expected_values[i];
        val := get_field_value(input.data, field_path);
        val == expected
    ]) > 0                                  # At least one field must match
}

# DATE/AGE CHECK (For Arrays - Multiple Dates)
# Purpose: Verify that dates are within a specified time threshold
# Use case: "EC2 instances must be newer than 365 days", "Certificates must not expire within 30 days"
allow if {
    input.policy.evaluation.type == "date_check"
    field_path := input.policy.details.functions[input.policy.evaluation.source_client].field_path
    val := get_field_value(input.data, field_path)
    threshold := input.policy.evaluation.threshold  # e.g., "365 days"
    
    # Handle array of dates (e.g., multiple instances)
    is_array(val)
    
    # Parse threshold (e.g., "365 days" -> 365)
    threshold_parts := split(threshold, " ")
    threshold_days := to_number(threshold_parts[0])
    
    # Check if all dates are within the threshold
    current_time := time.now_ns()  # Current time in nanoseconds
    all_within_threshold := [date | 
        date := val[_];                                     # For each date in array
        date_time := time.parse_rfc3339_ns(date);         # Parse ISO date
        age_ns := current_time - date_time;               # Calculate age in nanoseconds
        age_days := age_ns / (24 * 60 * 60 * 1000000000); # Convert to days
        age_days <= threshold_days                         # Check if within threshold
    ]
    count(all_within_threshold) == count(val)  # All dates must be within threshold
}

# DATE/AGE CHECK (For Single Date)
# Purpose: Verify that a single date is within a specified time threshold
allow if {
    input.policy.evaluation.type == "date_check"
    field_path := input.policy.details.functions[input.policy.evaluation.source_client].field_path
    val := get_field_value(input.data, field_path)
    threshold := input.policy.evaluation.threshold
    
    # Handle single date
    not is_array(val)
    
    # Parse threshold (e.g., "365 days" -> 365)
    threshold_parts := split(threshold, " ")
    threshold_days := to_number(threshold_parts[0])
    
    # Check if date is within the threshold
    current_time := time.now_ns()
    date_time := time.parse_rfc3339_ns(val)          # Parse single date
    age_ns := current_time - date_time               # Calculate age
    age_days := age_ns / (24 * 60 * 60 * 1000000000) # Convert to days
    age_days <= threshold_days                       # Check if within threshold
}

# =====================================
# SECTION 3: HELPER FUNCTIONS
# =====================================
# Supporting functions for complex validation conditions

# VALIDATION CONDITION HELPERS
# These functions support the custom_multi_field evaluation type
_validate_condition(val, "equals", expected) if { val == expected }
_validate_condition(val, "not_equals", expected) if { val != expected }
_validate_condition(val, "greater_than", expected) if { val > expected }
_validate_condition(val, "less_than", expected) if { val < expected }
_validate_condition(val, "exists", _) if { val != null; val != "" }
_validate_condition(val, "not_exists", _) if { val == null }
_validate_condition(val, "contains", expected) if { contains(val, expected) }

# =====================================
# SECTION 4: FINAL DECISION OUTPUT
# =====================================
# These rules determine the final compliance decision

# PASS DECISION
# If any of the above "allow" rules evaluate to true, the policy passes
decision = "pass" if { allow }

# FAIL DECISION  
# If none of the above "allow" rules evaluate to true, the policy fails
decision = "fail" if { not allow }

# =====================================
# USAGE EXAMPLES:
# =====================================
# 
# 1. EC2 Instance Age Check:
#    Input: EC2 instance data with LaunchTime fields
#    Rule: date_check with threshold "365 days"
#    Result: "pass" if all instances < 365 days old, "fail" otherwise
#
# 2. S3 Bucket Encryption Check:
#    Input: S3 bucket data with encryption configuration
#    Rule: exists check on encryption field
#    Result: "pass" if encryption exists, "fail" if missing
#
# 3. Security Group Rule Check:
#    Input: Security group data with ingress rules
#    Rule: not_exists check on public access (0.0.0.0/0)
#    Result: "pass" if no public access, "fail" if public access exists
#
# 4. Multi-Field Compliance Check:
#    Input: Resource data with multiple security settings
#    Rule: custom_multi_field with multiple validations
#    Result: "pass" if all conditions met, "fail" if any condition fails
# =====================================
